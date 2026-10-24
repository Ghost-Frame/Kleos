//! Server-side MCP endpoint (Streamable HTTP transport).
//!
//! `POST /mcp` accepts JSON-RPC 2.0 requests and dispatches tool calls
//! through a middleware-free internal Axum router via `Router::oneshot()`.
//! Auth, rate limiting, and audit run once on the outer request; inner
//! dispatch inherits the pre-validated `AuthContext` via request extensions.

use axum::body::Body;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use kleos_client::{render_path, resolve_tool_name, Method, Scope as RouteScope};
use kleos_lib::auth::{AuthContext, Scope};
use kleos_lib::spaces::InstanceAccess;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde_json::{json, Value};
use tower::ServiceExt;

use crate::extractors::Auth;
use crate::middleware::audit::{dispatch_audit_event, AuditEvent};
use crate::state::AppState;

/// MCP protocol version this endpoint speaks.
const PROTOCOL_VERSION: &str = "2025-03-26";

/// Guidance returned in the `initialize` response. Clients inject it into the
/// model's context for every conversation on the connector, so it is the one
/// channel that reaches a user who cannot run client-side hooks.
const MCP_INSTRUCTIONS: &str = "Kleos is this person's persistent memory across conversations. \
SEARCH FIRST: before answering anything that depends on a person, job, customer, vendor, \
price, past decision, or earlier conversation, call memory_search; try a second phrasing \
if the first is thin. STORE WITHOUT BEING ASKED: when a durable fact, decision, number, or \
next step appears, call memory_store in the same turn, one memory per fact, and show one \
line: Saved: <short summary>. Store immediately when they say remember this. Never store \
passwords, secrets, or throwaway chatter. Memory read results end with a reminder; act on \
it before the conversation ends.";

/// Trailing line appended to the text content of successful memory read
/// results, so every turn that consults Kleos also reminds the model to store.
/// `structuredContent` is never touched.
const STORE_NUDGE: &str = "Kleos reminder: if this turn produced a decision, a fact about a \
person or job, a number that matters, or a next step, store each one with memory_store \
before you finish.";

/// Byte cap on the search-text preview written to the audit trail.
const QUERY_PREVIEW_MAX_BYTES: usize = 80;

/// Maximum number of JSON-RPC requests allowed in a single batch.
/// Prevents rate-limit bypass via fan-out and bounds response memory.
const MAX_BATCH_SIZE: usize = 20;

/// Builds the MCP route. When `KLEOS_MCP_ENABLED=0`, returns an empty router.
/// The `dispatch` router is the middleware-free internal router used for
/// in-process tool-call dispatch via `Router::oneshot()`.
pub fn router(dispatch: Router) -> Router<AppState> {
    if std::env::var("KLEOS_MCP_ENABLED")
        .unwrap_or_else(|_| "1".into())
        .trim()
        == "0"
    {
        tracing::info!("server-side MCP endpoint disabled (KLEOS_MCP_ENABLED=0)");
        return Router::new();
    }

    tracing::info!("server-side MCP endpoint enabled at POST /mcp");
    Router::new()
        .route("/mcp", post(mcp_handler))
        .layer(Extension(dispatch))
}

/// Handles one `POST /mcp` request. Supports single JSON-RPC requests and
/// batch arrays per the MCP streamable HTTP spec.
#[tracing::instrument(skip_all, fields(endpoint = "mcp"))]
async fn mcp_handler(
    State(state): State<AppState>,
    Extension(dispatch): Extension<Router>,
    Auth(auth): Auth,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    // MCP spec MUST: validate Origin header to prevent DNS rebinding.
    // Reject requests with an Origin that looks like a browser cross-origin
    // attack. Requests without an Origin header (non-browser clients like
    // Claude Code) are allowed through.
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
        if !is_allowed_origin(origin) {
            return json_rpc_error_response(
                body.get("id").cloned(),
                -32001,
                "Forbidden: Origin not allowed",
            );
        }
    }

    // Batch support: JSON array of requests.
    if let Some(batch) = body.as_array() {
        if batch.len() > MAX_BATCH_SIZE {
            return json_rpc_error_response(
                None,
                -32600,
                &format!(
                    "Batch too large: {} requests exceeds limit of {}",
                    batch.len(),
                    MAX_BATCH_SIZE
                ),
            );
        }
        let mut responses = Vec::with_capacity(batch.len());
        for request in batch {
            if let Some(resp) = handle_single_rpc(&dispatch, &auth, &state, request).await {
                responses.push(resp);
            }
        }
        if responses.is_empty() {
            return StatusCode::NO_CONTENT.into_response();
        }
        return Json(Value::Array(responses)).into_response();
    }

    // Single request.
    match handle_single_rpc(&dispatch, &auth, &state, &body).await {
        Some(resp) => Json(resp).into_response(),
        // Notification (no id) -- spec says return 202 Accepted.
        None => StatusCode::ACCEPTED.into_response(),
    }
}

/// Dispatches one JSON-RPC request. Returns `None` for notifications (no id).
/// For `tools/call`, charges rate-limit tokens proportional to the endpoint
/// cost of the dispatched route.
async fn handle_single_rpc(
    dispatch: &Router,
    auth: &AuthContext,
    state: &AppState,
    req: &Value,
) -> Option<Value> {
    let id = req.get("id").cloned();
    let method = match req.get("method").and_then(Value::as_str) {
        Some(m) => m,
        None => return id.map(|id| rpc_error(id, -32600, "Invalid Request: missing method")),
    };

    let params = req.get("params").cloned().unwrap_or_else(|| json!({}));

    match method {
        "initialize" => {
            let id = id?;
            Some(rpc_ok(
                id,
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {
                        "tools": {},
                        "prompts": {}
                    },
                    "serverInfo": {
                        "name": "kleos",
                        "version": env!("CARGO_PKG_VERSION")
                    },
                    "instructions": MCP_INSTRUCTIONS
                }),
            ))
        }
        "notifications/initialized" => None,
        "ping" => {
            let id = id?;
            Some(rpc_ok(id, json!({})))
        }
        "tools/list" => {
            let id = id?;
            Some(rpc_ok(id, json!({ "tools": kleos_mcp::tools::registry() })))
        }
        "prompts/list" => {
            let id = id?;
            Some(rpc_ok(id, json!({ "prompts": prompt_catalog() })))
        }
        "prompts/get" => {
            let id = id?;
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            match prompt_messages(name, &arguments) {
                Some(result) => Some(rpc_ok(id, result)),
                None => Some(rpc_error(id, -32602, "Unknown prompt")),
            }
        }
        "tools/call" => {
            let id = id?;
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let query_preview = search_query_preview(&name, &arguments);

            // Charge per-tool rate-limit tokens before dispatch.
            if let Some(route) = resolve_tool_name(&name) {
                let http_method = match route.method {
                    Method::Get => axum::http::Method::GET,
                    Method::Post => axum::http::Method::POST,
                    Method::Put => axum::http::Method::PUT,
                    Method::Delete => axum::http::Method::DELETE,
                    Method::Patch => axum::http::Method::PATCH,
                };
                let cost = crate::middleware::rate_limit::endpoint_cost(route.path, &http_method);
                let key = format!("user:{}", auth.user_id);
                let limit = auth.key.rate_limit as i64;
                match kleos_lib::ratelimit::check_and_increment_by(&state.db, &key, limit, 60, cost)
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        record_tool_audit(state, auth, &name, 429, query_preview).await;
                        return Some(rpc_ok(
                            id,
                            json!({
                                "content": [{ "type": "text", "text": "Rate limit exceeded for this tool" }],
                                "isError": true
                            }),
                        ));
                    }
                    Err(e) => {
                        tracing::error!(tool = %name, error = %e, "rate-limit check failed during MCP dispatch");
                        record_tool_audit(state, auth, &name, 503, query_preview).await;
                        return Some(rpc_ok(
                            id,
                            json!({
                                "content": [{ "type": "text", "text": "Rate limit backend unavailable" }],
                                "isError": true
                            }),
                        ));
                    }
                }
            }

            let outcome = dispatch_tool(dispatch, auth, &name, arguments).await;
            let status = match &outcome {
                Ok(_) => 200,
                Err(failure) => failure.status,
            };
            record_tool_audit(state, auth, &name, status, query_preview).await;

            match outcome {
                Ok(value) => {
                    let text =
                        serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
                    Some(rpc_ok(
                        id,
                        json!({
                            "content": [{
                                "type": "text",
                                "text": with_store_nudge(&name, text)
                            }],
                            "structuredContent": value,
                            "isError": false
                        }),
                    ))
                }
                Err(failure) => Some(rpc_ok(
                    id,
                    json!({
                        "content": [{ "type": "text", "text": failure.message }],
                        "isError": true
                    }),
                )),
            }
        }
        _ => id.map(|id| rpc_error(id, -32601, "Method not found")),
    }
}

/// Why a tool call did not produce a successful result, with the HTTP-style
/// status the audit trail records for it. Pre-dispatch refusals use synthetic
/// codes (403 blocked or out of scope, 404 unknown tool, 400 bad arguments);
/// dispatched calls carry the handler's own status.
struct DispatchFailure {
    /// Status recorded in the `mcp.tool` audit row.
    status: u16,
    /// Client-safe message returned in the tool result.
    message: String,
}

/// Constructors for dispatch failures.
impl DispatchFailure {
    /// Pairs a status code with its client-facing message.
    fn new(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

/// Queues one `mcp.tool` audit row for a `tools/call`, attributed to the
/// caller the same way the outer HTTP row is. Best-effort and non-blocking,
/// exactly like HTTP audit.
async fn record_tool_audit(
    state: &AppState,
    auth: &AuthContext,
    tool: &str,
    status: u16,
    query_preview: Option<String>,
) {
    let (identity_id, tier) = auth
        .identity
        .as_ref()
        .map(|id| (id.identity_id, Some(id.tier.as_str().to_string())))
        .unwrap_or((None, None));
    dispatch_audit_event(
        &state.db,
        &state.audit_tx,
        AuditEvent {
            user_id: Some(auth.user_id),
            agent_id: auth.key.agent_id,
            identity_id,
            tier,
            method: "POST".to_string(),
            path: "/mcp".to_string(),
            status,
            ip: None,
            tool: Some(tool.to_string()),
            query_preview,
        },
    )
    .await;
}

/// Bounded, single-line preview of the search text for memory search tools,
/// written to the audit row so the trail shows what a person was looking for.
/// `None` for every other tool or when no usable query was supplied.
fn search_query_preview(tool: &str, args: &Value) -> Option<String> {
    let route = resolve_tool_name(tool)?;
    if !route.name.starts_with("memory.search") {
        return None;
    }
    let query = args.get("query").and_then(Value::as_str)?.trim();
    if query.is_empty() {
        return None;
    }
    let preview = kleos_lib::validation::truncate_on_char_boundary(query, QUERY_PREVIEW_MAX_BYTES);
    Some(preview.replace(['\n', '\r'], " "))
}

/// True when the tool is a read-only memory tool (search, list, recall, get),
/// the calls after which a store reminder is useful.
fn is_memory_read_tool(tool: &str) -> bool {
    resolve_tool_name(tool)
        .map(|route| route.name.starts_with("memory.") && route.scope == RouteScope::Read)
        .unwrap_or(false)
}

/// Appends the store reminder to the text content of a memory read result.
/// Any other tool's text is returned unchanged.
fn with_store_nudge(tool: &str, text: String) -> String {
    if !is_memory_read_tool(tool) {
        return text;
    }
    format!("{text}\n\n{STORE_NUDGE}")
}

/// Prompts advertised through `prompts/list`: a one-tap recall briefing and a
/// one-tap wrap-up, for clients that surface server prompts to the user.
fn prompt_catalog() -> Value {
    json!([
        {
            "name": "catch_up",
            "description": "Search Kleos memory for a topic and give a short briefing of what is known, what was decided, and what is still open.",
            "arguments": [
                {
                    "name": "topic",
                    "description": "The customer, job, person, or subject you are about to work on.",
                    "required": false
                }
            ]
        },
        {
            "name": "wrap_up",
            "description": "Store every durable fact, decision, number, and next step from this conversation in Kleos memory, then list what was saved.",
            "arguments": []
        }
    ])
}

/// Builds the `prompts/get` result for a named prompt, or `None` when the
/// prompt is unknown. A missing or non-string `topic` falls back to generic
/// wording rather than an error.
fn prompt_messages(name: &str, args: &Value) -> Option<Value> {
    let text = match name {
        "catch_up" => {
            let topic = args
                .get("topic")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|topic| !topic.is_empty());
            match topic {
                Some(topic) => format!(
                    "Search Kleos memory for everything known about \"{topic}\" using memory_search; \
                     try a second phrasing if the first result is thin. Then give me a short briefing: \
                     what is known, what decisions were made and why, and what is still open."
                ),
                None => "Ask me what I am about to work on, then search Kleos memory for it using \
                         memory_search and give me a short briefing: what is known, what decisions \
                         were made and why, and what is still open."
                    .to_string(),
            }
        }
        "wrap_up" => "Review this conversation and store each durable fact, decision, number that \
                      matters, and next step as its own memory with memory_store. Skip throwaway \
                      chatter, anything uncertain, and any password or secret. Then list what you \
                      saved, one line each."
            .to_string(),
        _ => return None,
    };
    Some(json!({
        "description": prompt_catalog()
            .as_array()
            .and_then(|prompts| prompts.iter().find(|p| p["name"] == name))
            .and_then(|p| p["description"].as_str())
            .unwrap_or_default(),
        "messages": [{
            "role": "user",
            "content": { "type": "text", "text": text }
        }]
    }))
}

/// Builds a client-safe error message for a failed internal dispatch.
/// Full details are logged server-side; the client sees only the tool name
/// and HTTP status unless the handler returned a narrowly recognized Forge
/// validation message that is safe and necessary for the caller to correct.
fn sanitize_dispatch_error(tool_name: &str, status_code: u16, internal_msg: &str) -> String {
    tracing::warn!(
        tool = tool_name,
        status = status_code,
        detail = internal_msg,
        "MCP tool dispatch failed"
    );
    if tool_name.starts_with("forge_") {
        if safe_forge_missing_spec(status_code, internal_msg) {
            return format!(
                "tool '{tool_name}' could not find that spec in remote Kleos; \
                 local and remote Forge spec IDs are separate"
            );
        }
        if let Some(detail) = safe_forge_validation_detail(status_code, internal_msg) {
            return format!("tool '{tool_name}' rejected input: {detail}");
        }
    }
    format!("tool '{}' failed (HTTP {})", tool_name, status_code)
}

/// Recognize a bounded Forge missing-spec error without exposing backend details.
fn safe_forge_missing_spec(status_code: u16, internal_msg: &str) -> bool {
    if status_code != 404 {
        return false;
    }
    let Some(spec_id) = internal_msg.trim().strip_prefix("Spec not found: ") else {
        return false;
    };
    spec_id.starts_with("spec_")
        && spec_id.len() <= 80
        && spec_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
}

/// Return a bounded allowlisted Forge validation detail for 400-class input errors.
fn safe_forge_validation_detail(status_code: u16, internal_msg: &str) -> Option<&str> {
    if !matches!(status_code, 400 | 422) {
        return None;
    }
    let detail = internal_msg.trim();
    if detail.is_empty()
        || detail.len() > 300
        || detail.chars().any(char::is_control)
        || detail.contains('/')
        || detail.contains('\\')
        || detail.contains("://")
    {
        return None;
    }
    const SAFE_PREFIXES: &[&str] = &[
        "Minimum 2 acceptance criteria required",
        "Minimum 3 edge cases required",
        "task_type must be one of:",
        "status must be one of:",
    ];
    SAFE_PREFIXES
        .iter()
        .any(|prefix| detail.starts_with(prefix))
        .then_some(detail)
}

/// Dispatches a single tool call through the internal router.
///
/// Looks up the route, enforces scope, builds a synthetic HTTP request
/// with the caller's `AuthContext` pre-injected, and dispatches via
/// `Router::oneshot()`.
#[tracing::instrument(
    skip(dispatch, auth, args),
    fields(
        mcp.tool = %name,
        mcp.user_id = auth.user_id,
        mcp.scope,
        mcp.status,
    )
)]
/// Dispatches one tool call through the internal router with auth applied.
async fn dispatch_tool(
    dispatch: &Router,
    auth: &AuthContext,
    name: &str,
    mut args: Value,
) -> Result<Value, DispatchFailure> {
    // Secret-bearing routes (cred resolve/proxy) are dispatchable by name even
    // though tools/list omits them. Refuse them so a raw credential never lands
    // in the MCP response's structuredContent / text and, from there, in model
    // transcripts and logs.
    if kleos_client::is_mcp_blocked(name) {
        return Err(DispatchFailure::new(
            403,
            format!("tool '{name}' is not available over MCP"),
        ));
    }

    let route = resolve_tool_name(name)
        .ok_or_else(|| DispatchFailure::new(404, format!("unknown tool: {name}")))?;

    // Record the required scope in the span.
    tracing::Span::current().record(
        "mcp.scope",
        tracing::field::display(format_args!("{:?}", route.scope)),
    );

    // Enforce scope before dispatch.
    let required = route_scope_to_auth_scope(route.scope);
    if !auth.has_scope(&required) {
        return Err(DispatchFailure::new(
            403,
            format!(
                "insufficient scope: tool '{}' requires {:?}",
                name, required
            ),
        ));
    }

    // The outer POST /mcp transport is logically read-capable, so delegated
    // access must be checked against each actual tool before internal dispatch.
    if auth.act_as.is_some() {
        let required_access = route_scope_to_instance_access(route.scope);
        let delegated = auth.act_as_access.ok_or_else(|| {
            DispatchFailure::new(403, "delegated MCP request is missing its grant context")
        })?;
        if !delegated.satisfies(required_access) {
            return Err(DispatchFailure::new(
                403,
                format!(
                    "insufficient delegated access: tool '{name}' requires {}",
                    required_access.as_str()
                ),
            ));
        }
    }

    let path = render_path(route.path, &mut args).map_err(|e| DispatchFailure::new(400, e))?;

    // Build URI: for GET/DELETE, remaining args become query parameters.
    let uri = match route.method {
        Method::Get | Method::Delete => append_query_string(&path, &args),
        _ => path.clone(),
    };

    // Build the HTTP method.
    let http_method = match route.method {
        Method::Get => axum::http::Method::GET,
        Method::Post => axum::http::Method::POST,
        Method::Put => axum::http::Method::PUT,
        Method::Delete => axum::http::Method::DELETE,
        Method::Patch => axum::http::Method::PATCH,
    };

    // Build the request body for POST/PUT/PATCH.
    let (body, content_type) = match route.method {
        Method::Post | Method::Put | Method::Patch => {
            let bytes = serde_json::to_vec(&args).unwrap_or_default();
            (Body::from(bytes), Some("application/json"))
        }
        _ => (Body::empty(), None),
    };

    let mut builder = Request::builder().method(http_method).uri(&uri);
    if let Some(ct) = content_type {
        builder = builder.header("content-type", ct);
    }

    let mut request = builder
        .body(body)
        .map_err(|e| DispatchFailure::new(500, format!("failed to build internal request: {e}")))?;

    // Inject pre-validated AuthContext so handler extractors find it.
    request.extensions_mut().insert(auth.clone());

    // Dispatch through the internal router (no middleware, just handlers).
    let response = dispatch
        .clone()
        .oneshot(request)
        .await
        .map_err(|e| DispatchFailure::new(502, format!("internal dispatch failed: {e}")))?;

    let status = response.status();
    tracing::Span::current().record("mcp.status", status.as_u16() as i64);
    let body_bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .map_err(|e| DispatchFailure::new(502, format!("failed to read internal response: {e}")))?;

    let parsed: Result<Value, _> = serde_json::from_slice(&body_bytes);
    if status.is_success() {
        if status == StatusCode::MULTI_STATUS {
            let body = parsed
                .as_ref()
                .map(Value::to_string)
                .unwrap_or_else(|_| String::from_utf8_lossy(&body_bytes).into_owned());
            return Err(DispatchFailure::new(
                status.as_u16(),
                format!(
                    "tool '{}' returned a partial result requiring caller recovery: {}",
                    name, body
                ),
            ));
        }
        if let Some(body) = parsed
            .as_ref()
            .ok()
            .filter(|body| body.get("attachments_committed") == Some(&Value::Bool(false)))
        {
            return Err(DispatchFailure::new(
                StatusCode::MULTI_STATUS.as_u16(),
                format!(
                    "tool '{}' partially persisted its memory but did not commit attachments: {}",
                    name, body
                ),
            ));
        }
        parsed.or_else(|_| {
            let text = String::from_utf8_lossy(&body_bytes).into_owned();
            Ok(json!({ "content": text }))
        })
    } else {
        let internal_msg = parsed
            .as_ref()
            .ok()
            .and_then(|b| {
                b.get("error")
                    .or_else(|| b.get("message"))
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .unwrap_or_else(|| {
                let s = String::from_utf8_lossy(&body_bytes);
                if s.len() > 512 {
                    format!(
                        "{}... ({} bytes)",
                        kleos_lib::validation::truncate_on_char_boundary(s.as_ref(), 512),
                        body_bytes.len()
                    )
                } else {
                    s.into_owned()
                }
            });
        Err(DispatchFailure::new(
            status.as_u16(),
            sanitize_dispatch_error(name, status.as_u16(), &internal_msg),
        ))
    }
}

/// Converts a route-registry scope to an auth-module scope.
fn route_scope_to_auth_scope(scope: RouteScope) -> Scope {
    match scope {
        RouteScope::Read => Scope::Read,
        RouteScope::Write => Scope::Write,
        RouteScope::Admin => Scope::Admin,
    }
}

/// Converts a route-registry scope to the whole-instance delegation level.
fn route_scope_to_instance_access(scope: RouteScope) -> InstanceAccess {
    match scope {
        RouteScope::Read => InstanceAccess::Read,
        RouteScope::Write | RouteScope::Admin => InstanceAccess::Write,
    }
}

/// Appends remaining JSON object fields as query-string parameters.
fn append_query_string(path: &str, args: &Value) -> String {
    let map = match args.as_object() {
        Some(m) if !m.is_empty() => m,
        _ => return path.to_string(),
    };
    let mut qs = String::new();
    for (k, v) in map {
        match v {
            Value::Null => continue,
            Value::Object(inner) if inner.is_empty() => continue,
            Value::Array(arr) => {
                for item in arr {
                    push_qparam(&mut qs, k, item);
                }
            }
            _ => push_qparam(&mut qs, k, v),
        }
    }
    if qs.is_empty() {
        return path.to_string();
    }
    format!("{path}?{}", qs.strip_prefix('&').unwrap_or(&qs))
}

/// Pushes one key=value pair onto the query string buffer.
fn push_qparam(qs: &mut String, key: &str, val: &Value) {
    let encoded_key = utf8_percent_encode(key, NON_ALPHANUMERIC);
    let raw = match val {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => return,
    };
    let encoded_val = utf8_percent_encode(&raw, NON_ALPHANUMERIC);
    qs.push('&');
    qs.push_str(&encoded_key.to_string());
    qs.push('=');
    qs.push_str(&encoded_val.to_string());
}

/// Checks whether the Origin header is from a trusted source.
/// Rejects obvious cross-origin browser attacks while allowing
/// non-browser MCP clients (which don't send Origin).
fn is_allowed_origin(origin: &str) -> bool {
    let lower = origin.to_ascii_lowercase();

    if is_loopback_origin(&lower) {
        return true;
    }

    // Allow origins from the configured ENGRAM_ALLOWED_ORIGINS.
    if let Ok(allowed) = kleos_lib::kleos_env("ALLOWED_ORIGINS") {
        for allowed_origin in allowed.split(',').map(str::trim) {
            if lower == allowed_origin.to_ascii_lowercase() {
                return true;
            }
        }
    }
    false
}

/// Returns true if the origin is a loopback address (localhost, 127.0.0.1, [::1]).
/// Matches the exact authority only -- "http://localhost.evil.com" is rejected.
fn is_loopback_origin(lower: &str) -> bool {
    const LOOPBACK_PREFIXES: &[&str] = &[
        "http://localhost",
        "https://localhost",
        "http://127.0.0.1",
        "https://127.0.0.1",
        "http://[::1]",
        "https://[::1]",
    ];
    for prefix in LOOPBACK_PREFIXES {
        if let Some(rest) = lower.strip_prefix(prefix) {
            if rest.is_empty() {
                return true;
            }
            // Only allow a numeric port suffix (":NNNN"), reject subdomains
            // like "localhost:3000.evil.com".
            if let Some(port_str) = rest.strip_prefix(':') {
                if !port_str.is_empty() && port_str.chars().all(|c| c.is_ascii_digit()) {
                    return true;
                }
            }
        }
    }
    false
}

// -- JSON-RPC helpers -------------------------------------------------------

/// Builds a successful JSON-RPC 2.0 response.
fn rpc_ok(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

/// Builds a JSON-RPC 2.0 error response.
fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// Builds an HTTP response wrapping a JSON-RPC error (for pre-dispatch failures).
fn json_rpc_error_response(id: Option<Value>, code: i64, message: &str) -> Response {
    let id = id.unwrap_or(Value::Null);
    Json(rpc_error(id, code, message)).into_response()
}

/// Builds a bounded UTF-8 preview for testing and logging.
#[cfg(test)]
fn preview_utf8(text: &str, limit: usize) -> String {
    kleos_lib::validation::truncate_on_char_boundary(text, limit).to_string()
}

/// Tests the MCP routing helpers and origin guardrails.
#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies query string assembly for numeric arguments.
    #[test]
    fn query_string_builds_correctly() {
        let args = json!({"limit": 10, "offset": 5});
        let result = append_query_string("/list", &args);
        assert!(result.starts_with("/list?"));
        assert!(result.contains("limit=10"));
        assert!(result.contains("offset=5"));
    }

    /// Verifies null values are skipped when building a query string.
    #[test]
    fn query_string_skips_null() {
        let args = json!({"limit": 10, "filter": null});
        let result = append_query_string("/list", &args);
        assert!(result.contains("limit=10"));
        assert!(!result.contains("filter"));
    }

    /// Verifies empty argument maps return the original path.
    #[test]
    fn query_string_empty_returns_path() {
        assert_eq!(append_query_string("/list", &json!({})), "/list");
    }

    /// Verifies localhost origins are accepted.
    #[test]
    fn origin_allows_localhost() {
        assert!(is_allowed_origin("http://localhost:3000"));
        assert!(is_allowed_origin("https://127.0.0.1:8080"));
    }

    /// Verifies unknown origins are rejected.
    #[test]
    fn origin_rejects_unknown() {
        assert!(!is_allowed_origin("https://evil.example.com"));
    }

    /// Verifies route scopes map cleanly to auth scopes.
    #[test]
    fn scope_conversion() {
        assert_eq!(route_scope_to_auth_scope(RouteScope::Read), Scope::Read);
        assert_eq!(route_scope_to_auth_scope(RouteScope::Write), Scope::Write);
        assert_eq!(route_scope_to_auth_scope(RouteScope::Admin), Scope::Admin);
    }

    /// Verifies the hard batch cap stays at the configured constant.
    #[test]
    fn batch_cap_constant_is_set() {
        assert_eq!(MAX_BATCH_SIZE, 20);
    }

    /// Verifies localhost subdomains are rejected.
    #[test]
    fn origin_rejects_localhost_subdomain() {
        assert!(!is_allowed_origin("http://localhost.evil.com"));
        assert!(!is_allowed_origin("https://localhost.evil.com"));
    }

    /// Verifies port-suffixed subdomains are rejected.
    #[test]
    fn origin_rejects_port_suffixed_subdomain() {
        assert!(!is_allowed_origin("http://localhost:3000.evil.com"));
        assert!(!is_allowed_origin("https://127.0.0.1:8080.attacker.net"));
    }

    /// Verifies non-numeric ports are rejected.
    #[test]
    fn origin_rejects_non_numeric_port() {
        assert!(!is_allowed_origin("http://localhost:abc"));
        assert!(!is_allowed_origin("http://localhost:"));
    }

    /// Verifies bare localhost origins are accepted.
    #[test]
    fn origin_allows_localhost_bare() {
        assert!(is_allowed_origin("http://localhost"));
        assert!(is_allowed_origin("https://localhost"));
    }

    /// Verifies IPv6 loopback origins are accepted.
    #[test]
    fn origin_allows_ipv6_loopback_with_port() {
        assert!(is_allowed_origin("http://[::1]:3000"));
        assert!(is_allowed_origin("http://[::1]"));
    }

    /// Verifies internal dispatch errors do not leak backend details.
    #[test]
    fn error_response_is_sanitized() {
        let sanitized = sanitize_dispatch_error(
            "test_tool",
            500,
            "SQLITE_BUSY: database is locked at /data/tenants/42/kleos.db",
        );
        assert_eq!(sanitized, "tool 'test_tool' failed (HTTP 500)");
        assert!(!sanitized.contains("SQLITE"));
        assert!(!sanitized.contains("/data"));
    }

    /// Forge input errors expose only allowlisted, actionable validation details.
    #[test]
    fn forge_validation_error_is_actionable_and_bounded() {
        let actionable = sanitize_dispatch_error(
            "forge_spec_task",
            400,
            "Minimum 2 acceptance criteria required",
        );
        assert_eq!(
            actionable,
            "tool 'forge_spec_task' rejected input: Minimum 2 acceptance criteria required"
        );

        let sensitive = sanitize_dispatch_error(
            "forge_spec_task",
            400,
            "Minimum 2 acceptance criteria required at /data/private.db",
        );
        assert_eq!(sensitive, "tool 'forge_spec_task' failed (HTTP 400)");
    }

    /// Forge missing-spec errors explain the local and remote identifier boundary.
    #[test]
    fn forge_missing_spec_error_explains_identifier_scope() {
        let actionable =
            sanitize_dispatch_error("forge_update_spec", 404, "Spec not found: spec_3a807975");
        assert_eq!(
            actionable,
            "tool 'forge_update_spec' could not find that spec in remote Kleos; \
             local and remote Forge spec IDs are separate"
        );

        let sensitive = sanitize_dispatch_error(
            "forge_update_spec",
            404,
            "Spec not found: spec_3a807975 at /data/private.db",
        );
        assert_eq!(sensitive, "tool 'forge_update_spec' failed (HTTP 404)");
    }

    /// Verifies multibyte output previews truncate without panicking.
    #[test]
    fn preview_utf8_truncates_multibyte_text() {
        let text = "💥".repeat(200);
        let preview = preview_utf8(&text, 512);
        assert!(preview.len() <= 512);
        assert!(text.starts_with(&preview));
    }

    /// The initialize guidance states the protocol and stays short enough
    /// that clients inject it without truncation.
    #[test]
    fn instructions_state_protocol_and_stay_bounded() {
        assert!(MCP_INSTRUCTIONS.contains("memory_search"));
        assert!(MCP_INSTRUCTIONS.contains("memory_store"));
        assert!(MCP_INSTRUCTIONS.contains("remember this"));
        assert!(
            MCP_INSTRUCTIONS.len() < 900,
            "len {}",
            MCP_INSTRUCTIONS.len()
        );
    }

    /// Memory read tools get the store reminder in their text; write tools
    /// and non-memory tools do not.
    #[test]
    fn store_nudge_only_follows_memory_reads() {
        let nudged = with_store_nudge("memory_search", "{}".to_string());
        assert!(nudged.starts_with("{}\n\n"));
        assert!(nudged.ends_with(STORE_NUDGE));
        assert_eq!(
            with_store_nudge("memory_recall", "r".to_string()),
            format!("r\n\n{STORE_NUDGE}")
        );
        assert_eq!(with_store_nudge("memory_store", "{}".to_string()), "{}");
        assert_eq!(with_store_nudge("tasks_list", "[]".to_string()), "[]");
        assert_eq!(with_store_nudge("no_such_tool", "x".to_string()), "x");
    }

    /// Search previews are bounded, single-line, multibyte safe, and absent
    /// for non-search tools or empty queries.
    #[test]
    fn search_query_preview_is_bounded_and_scoped() {
        let long = "é".repeat(100);
        let preview = search_query_preview("memory_search", &json!({ "query": long })).unwrap();
        assert!(preview.len() <= QUERY_PREVIEW_MAX_BYTES);
        assert!(preview.chars().all(|c| c == 'é'));

        let multiline =
            search_query_preview("memory_search", &json!({ "query": "a\nb\r\nc" })).unwrap();
        assert_eq!(multiline, "a b  c");

        assert_eq!(
            search_query_preview("memory_search", &json!({ "query": "   " })),
            None
        );
        assert_eq!(
            search_query_preview("memory_search", &json!({ "query": 5 })),
            None
        );
        assert_eq!(
            search_query_preview("memory_store", &json!({ "query": "x" })),
            None
        );
        assert_eq!(
            search_query_preview("memory_list", &json!({ "query": "x" })),
            None
        );
    }

    /// Both prompts are advertised, resolvable, and tolerant of missing
    /// arguments; unknown names resolve to nothing.
    #[test]
    fn prompts_are_listed_and_resolvable() {
        let catalog = prompt_catalog();
        let names: Vec<&str> = catalog
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["catch_up", "wrap_up"]);

        let with_topic = prompt_messages("catch_up", &json!({ "topic": " Smith job " })).unwrap();
        let text = with_topic["messages"][0]["content"]["text"]
            .as_str()
            .unwrap();
        assert!(text.contains("\"Smith job\""));
        assert!(text.contains("memory_search"));
        assert_eq!(with_topic["messages"][0]["role"], "user");
        assert!(!with_topic["description"].as_str().unwrap().is_empty());

        let without_topic = prompt_messages("catch_up", &json!({ "topic": 42 })).unwrap();
        let text = without_topic["messages"][0]["content"]["text"]
            .as_str()
            .unwrap();
        assert!(text.starts_with("Ask me what I am about to work on"));

        let wrap = prompt_messages("wrap_up", &json!({})).unwrap();
        assert!(wrap["messages"][0]["content"]["text"]
            .as_str()
            .unwrap()
            .contains("memory_store"));

        assert!(prompt_messages("nope", &json!({})).is_none());
    }

    /// Pre-dispatch failures carry the synthetic status the audit row records.
    #[test]
    fn dispatch_failure_pairs_status_with_message() {
        let failure = DispatchFailure::new(404, format!("unknown tool: {}", "x"));
        assert_eq!(failure.status, 404);
        assert_eq!(failure.message, "unknown tool: x");
    }
}
