//! Claude Code hook handlers -- thin shim that routes decisions to kleos-server.
//! All handlers read JSON from stdin, call the server, emit hookSpecificOutput on stdout.
//! Network failures are logged (eprintln) and fail open by default (exit 0);
//! set KLEOS_HOOK_GATE_FAIL_CLOSED=1 to deny tool use when the gate is
//! unreachable. A reachable gate that omits `allowed` always denies.

use clap::Subcommand;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde_json::{json, Value};
use std::io::{Read, Seek, SeekFrom};
use std::time::Duration;

use crate::Client;

// --- CLI definition ---

/// CLI subcommands for each Claude Code hook event.
#[derive(Subcommand)]
pub enum HookCommands {
    /// SessionStart hook -- registers session, fetches context
    SessionStart,
    /// UserPromptSubmit hook -- drains supervisor, injects mandatory rules
    UserPrompt,
    /// Stop hook -- records session end
    Stop,
    /// PreToolUse hook -- routes tool calls through /gate/check
    PreTool,
    /// PostToolUse hook -- reports activity, completes gate
    PostTool,
    /// Back-compat alias for older packaged settings.
    #[command(name = "post-bash", hide = true)]
    PostBash,
}

// --- Constants ---

/// Offline / fetch-failure fallback for the mandatory rules text.
///
/// Empty by design: the rules are operator-configured server-side via the
/// `KLEOS_MANDATORY_RULES` env var. If the CLI cannot reach the server, no
/// rules are injected rather than substituting hardcoded content that may
/// not match the operator's policy.
const FALLBACK_MANDATORY_RULES: &str = "";

/// Maximum age in seconds before the on-disk policy cache is considered stale.
const POLICY_CACHE_TTL_SECS: u64 = 60;

/// Timeout for /gate/check requests -- long because the gate may queue behind human review.
const GATE_TIMEOUT: Duration = Duration::from_secs(130);
/// Bounds the number of accumulated session gates closed during one stop hook.
const MAX_GATE_COMPLETIONS_PER_STOP: usize = 64;
/// Default timeout for best-effort server calls (activity, supervisor, coordination).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// Timeout for sidecar /recall requests (memory retrieval before prompt processing).
const SIDECAR_RECALL_TIMEOUT: Duration = Duration::from_secs(12);
/// Timeout for best-effort sidecar session registration.
const SIDECAR_SESSION_TIMEOUT: Duration = Duration::from_secs(5);
/// Timeout for sidecar /observe requests (tool result observation storage).
const SIDECAR_OBSERVE_TIMEOUT: Duration = Duration::from_secs(5);
/// Timeout for sidecar /end requests (session teardown notification).
const SIDECAR_END_TIMEOUT: Duration = Duration::from_secs(15);
/// Maximum transcript tail read for per-prompt dialogue context.
const RECALL_TRANSCRIPT_TAIL_BYTES: u64 = 1024 * 1024;
/// Maximum number of prior user or assistant messages added to a recall query.
const RECALL_DIALOGUE_MESSAGES: usize = 2;
/// Maximum characters contributed by any one prior dialogue message.
const RECALL_DIALOGUE_MESSAGE_CHARS: usize = 260;

// --- Policy fetch with cache ---

/// Returns the mandatory rules text.
/// Tries `{server_url}/policy/mandatory` first (2s timeout).
/// On success, caches the response to `~/.cache/kleos/policy.json` (60s TTL).
/// On any failure, falls back to `FALLBACK_MANDATORY_RULES`.
async fn fetch_mandatory_rules(client: &Client) -> String {
    // Check cache first
    if let Some(cached) = read_policy_cache() {
        return cached;
    }

    let timeout = std::time::Duration::from_secs(2);
    match client.get_with_timeout("/policy/mandatory", timeout).await {
        Ok(v) => {
            let rules = v
                .get("rules")
                .and_then(|r| r.as_str())
                .unwrap_or(FALLBACK_MANDATORY_RULES)
                .to_string();
            write_policy_cache(&rules);
            rules
        }
        Err(e) => {
            eprintln!(
                "kleos hook: /policy/mandatory fetch failed ({}), using fallback",
                e
            );
            FALLBACK_MANDATORY_RULES.to_string()
        }
    }
}

/// Returns the on-disk cache path for mandatory hook policy text.
fn policy_cache_path() -> Option<std::path::PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let dir = std::path::Path::new(&home).join(".cache").join("kleos");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir.join("policy.json"))
}

/// Reads fresh mandatory policy text from the local cache if it is still valid.
fn read_policy_cache() -> Option<String> {
    let path = policy_cache_path()?;
    let meta = std::fs::metadata(&path).ok()?;
    let modified = meta.modified().ok()?;
    let age = std::time::SystemTime::now().duration_since(modified).ok()?;
    if age.as_secs() > POLICY_CACHE_TTL_SECS {
        return None;
    }
    let bytes = std::fs::read(&path).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("rules")
        .and_then(|r| r.as_str())
        .map(|s| s.to_string())
}

/// Writes mandatory policy text to the local hook policy cache.
fn write_policy_cache(rules: &str) {
    if let Some(path) = policy_cache_path() {
        let v = serde_json::json!({ "rules": rules });
        let _ = std::fs::write(path, serde_json::to_vec(&v).unwrap_or_default());
    }
}

// --- Helpers ---

/// Reads all of stdin and parses it as JSON, returning `Value::Null` on failure.
fn read_stdin_json() -> Value {
    let mut buf = String::new();
    let _ = std::io::stdin().read_to_string(&mut buf);
    serde_json::from_str(&buf).unwrap_or(Value::Null)
}

/// Extracts Claude's session id from hook input or falls back to the parent process id.
fn extract_session_id(input: &Value) -> String {
    input
        .get("session_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| std::env::var("PPID").unwrap_or_else(|_| "unknown".to_string()))
}

/// Extracts plain text from a Claude or Codex transcript message payload.
fn transcript_message(value: &Value) -> Option<(&str, String)> {
    let message = value.get("message").or_else(|| {
        let payload = value.get("payload")?;
        (payload.get("type").and_then(Value::as_str) == Some("message")).then_some(payload)
    })?;
    let role = message.get("role").and_then(Value::as_str)?;
    if role != "user" && role != "assistant" {
        return None;
    }

    let content = message.get("content")?;
    let text = match content {
        Value::String(text) => text.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|part| {
                part.get("text")
                    .and_then(Value::as_str)
                    .or_else(|| part.as_str())
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    };
    (!text.trim().is_empty()).then_some((role, text))
}

/// Reads a bounded transcript tail and returns recent dialogue before the current prompt.
fn recent_dialogue(input: &Value, current_prompt: &str) -> Vec<(String, String)> {
    let Some(path) = input.get("transcript_path").and_then(Value::as_str) else {
        return Vec::new();
    };
    let Ok(mut file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let Ok(length) = file.metadata().map(|metadata| metadata.len()) else {
        return Vec::new();
    };
    let start = length.saturating_sub(RECALL_TRANSCRIPT_TAIL_BYTES);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }
    let mut bytes = Vec::with_capacity((length - start) as usize);
    if file.read_to_end(&mut bytes).is_err() {
        return Vec::new();
    }
    let tail = String::from_utf8_lossy(&bytes);
    let complete_tail = if start == 0 {
        tail.as_ref()
    } else {
        tail.split_once('\n').map(|(_, rest)| rest).unwrap_or("")
    };

    let mut skipped_current = false;
    let mut dialogue = Vec::new();
    for line in complete_tail.lines().rev() {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some((role, text)) = transcript_message(&value) else {
            continue;
        };
        if !skipped_current && role == "user" && text.trim() == current_prompt.trim() {
            skipped_current = true;
            continue;
        }
        dialogue.push((role.to_string(), text));
        if dialogue.len() == RECALL_DIALOGUE_MESSAGES {
            break;
        }
    }
    dialogue
}

/// Truncates recall text by Unicode scalar count without splitting UTF-8.
fn truncate_recall_text(text: &str, max_chars: usize) -> String {
    text.chars().take(max_chars).collect()
}

/// Builds a bounded recall query that preserves the current prompt and recent subject context.
fn contextual_recall_message(input: &Value, current_prompt: &str, max_chars: usize) -> String {
    if current_prompt.chars().count() >= max_chars / 2 {
        return truncate_recall_text(current_prompt, max_chars);
    }
    let dialogue = recent_dialogue(input, current_prompt);
    if dialogue.is_empty() {
        return current_prompt.to_string();
    }

    let mut query = format!(
        "Current prompt: {}\nRecent dialogue (newest first):",
        current_prompt
    );
    for (role, text) in dialogue {
        let remaining = max_chars.saturating_sub(query.chars().count());
        if remaining <= role.len() + 5 {
            break;
        }
        let prefix = format!("\n[{role}] ");
        query.push_str(&prefix);
        let remaining = max_chars.saturating_sub(query.chars().count());
        query.push_str(&truncate_recall_text(
            &text,
            remaining.min(RECALL_DIALOGUE_MESSAGE_CHARS),
        ));
    }
    query
}

/// Return the hook-provided working directory or the process working directory.
fn hook_cwd(input: &Value) -> Option<String> {
    input
        .get("cwd")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            std::env::current_dir()
                .ok()
                .map(|path| path.to_string_lossy().to_string())
        })
}

/// Legacy fixed bootstrap query, kept as the fallback when no cwd is available.
const LEGACY_BOOTSTRAP_QUERY: &str =
    "session-bootstrap agent-rules infrastructure active-tasks recent-decisions";

/// Reads the current git branch from `<cwd>/.git/HEAD` without spawning git.
fn git_branch(cwd: &str) -> Option<String> {
    let head = std::fs::read_to_string(std::path::Path::new(cwd).join(".git/HEAD")).ok()?;
    head.trim()
        .strip_prefix("ref: refs/heads/")
        .map(|b| b.to_string())
}

/// Builds the session-bootstrap brain query from the project the session
/// actually starts in (cwd basename + git branch words) so /prompt/generate
/// recalls task-relevant memories instead of the fixed keyword salad, which
/// the brain answers with "No relevant patterns activated".
fn bootstrap_task_query(input: &Value) -> String {
    let cwd = input
        .get("cwd")
        .and_then(|c| c.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            std::env::current_dir()
                .ok()
                .map(|p| p.display().to_string())
        });
    let Some(cwd) = cwd else {
        return LEGACY_BOOTSTRAP_QUERY.to_string();
    };
    let project = match std::path::Path::new(&cwd).file_name() {
        Some(n) => n.to_string_lossy().to_string(),
        None => return LEGACY_BOOTSTRAP_QUERY.to_string(),
    };
    let mut query = format!("{project} project");
    if let Some(branch) = git_branch(&cwd) {
        // Branch names like fix/ingestion-import-user-id carry strong task signal.
        query.push(' ');
        query.push_str(&branch.replace(['/', '-', '_'], " "));
    }
    query.push_str(" active-tasks recent-decisions agent-rules");
    query
}

/// Returns the project label for the session: the basename of the working
/// directory it started in. Used to scope the session.start activity record and
/// the coordination read-back so Chiasm/Axon know which checkout this session
/// is in (the record previously reported a useless "unknown").
fn cwd_project(input: &Value) -> Option<String> {
    let cwd = hook_cwd(input)?;
    std::path::Path::new(&cwd)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
}

/// Formats the coordination banner from active tasks already open in the
/// session's project. This is the read-back half of coordination: sessions
/// register via /activity but never saw who else was working the same checkout,
/// so two agents would collide on one git working tree. Injecting this banner
/// every session makes the coordination state visible mechanically, rather than
/// relying on the model to query it (which it does not). Empty when nobody else
/// is active, so quiet by default.
fn format_coordination_banner(project: &str, tasks: &[Value]) -> String {
    if tasks.is_empty() {
        return String::new();
    }
    let mut lines = vec![
        format!(
            "## Coordination -- {} active task(s) in project `{}`",
            tasks.len(),
            project
        ),
        "Another session may be working in this checkout. Coordinate, or use a \
         separate git worktree -- two agents in one working tree race on HEAD \
         and the index and will clobber each other's uncommitted work."
            .to_string(),
    ];
    for t in tasks.iter().take(6) {
        let agent = t.get("agent").and_then(|a| a.as_str()).unwrap_or("?");
        let status = t.get("status").and_then(|a| a.as_str()).unwrap_or("active");
        let title: String = t
            .get("title")
            .and_then(|a| a.as_str())
            .unwrap_or("")
            .chars()
            .take(90)
            .collect();
        lines.push(format!("- {agent} ({status}): {title}"));
    }
    lines.join("\n")
}

/// Fetches active tasks in the session's project and renders the coordination
/// banner. Best-effort: any error or absent project yields an empty banner.
async fn fetch_coordination_banner(client: &Client, project: Option<&str>) -> String {
    let Some(project) = project else {
        return String::new();
    };
    let path = format!(
        "/tasks?status=active&project={}&limit=10",
        utf8_percent_encode(project, NON_ALPHANUMERIC)
    );
    match client.get_with_timeout(&path, DEFAULT_TIMEOUT).await {
        Ok(v) => {
            let tasks = v
                .get("tasks")
                .and_then(|t| t.as_array())
                .cloned()
                .unwrap_or_default();
            format_coordination_banner(project, &tasks)
        }
        Err(_) => String::new(),
    }
}

/// Resolves the agent identity for hook reporting and living-context generation.
///
/// Prefers the `KLEOS_AGENT_LABEL` env var, which each harness sets to identify
/// itself ("codex" for Codex, "claude-code" for Claude Code). Falls back to
/// "claude-code" -- the historical default -- when the env var is unset, so
/// existing Claude Code sessions are unaffected. This is what stops the living
/// context from hardcoding "You are claude-code" inside Codex sessions.
fn resolve_agent() -> String {
    std::env::var("KLEOS_AGENT_LABEL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "claude-code".to_string())
}

/// Emits Claude hook JSON on stdout.
fn emit(v: &Value) {
    println!("{}", serde_json::to_string(v).unwrap_or_default());
}

/// Builds a hook response that injects additional context for the current event.
fn build_context_output(event: &str, context: &str) -> Value {
    json!({
        "hookSpecificOutput": {
            "hookEventName": event,
            "additionalContext": context
        }
    })
}

/// POSTs JSON to the optional local sidecar and returns the parsed response on success.
async fn sidecar_post(path: &str, body: &Value, timeout: Duration) -> Option<Value> {
    let base =
        std::env::var("KLEOS_SIDECAR_URL").unwrap_or_else(|_| "http://127.0.0.1:7711".to_string());
    let url = format!("{}{}", base, path);
    let debug = std::env::var("KLEOS_HOOK_DEBUG")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let client = reqwest::Client::new();
    let mut req = client.post(&url).json(body).timeout(timeout);
    if let Ok(token) = std::env::var("KLEOS_SIDECAR_TOKEN") {
        req = req.header("Authorization", format!("Bearer {}", token));
    }

    match req.send().await {
        Ok(resp) if resp.status().is_success() => resp.json().await.ok(),
        Ok(resp) => {
            if debug {
                eprintln!("[kleos-hook] sidecar {} returned {}", path, resp.status());
            }
            None
        }
        Err(e) => {
            if debug {
                eprintln!("[kleos-hook] sidecar {} failed: {}", path, e);
            }
            None
        }
    }
}

/// Converts hook tool output into bounded text for sidecar observation storage.
///
/// Claude Code's PostToolUse hook payload carries the output under
/// `tool_response`; `tool_result` is kept as a legacy fallback for callers
/// that ever supplied that key. Reading only the legacy key meant every real
/// hook invocation stored an empty observation.
fn extract_tool_result_text(input: &Value, max_chars: usize) -> String {
    let value = input
        .get("tool_response")
        .or_else(|| input.get("tool_result"));
    let raw = value
        .and_then(|v| v.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| {
            value
                .map(|v| serde_json::to_string(v).unwrap_or_default())
                .unwrap_or_default()
        });
    raw.chars().take(max_chars).collect()
}

/// Recursively collect path-shaped string fields from bounded tool input JSON.
fn collect_touched_paths(value: &Value, depth: usize, paths: &mut Vec<String>) {
    if depth > 8 || paths.len() >= 64 {
        return;
    }
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                if matches!(
                    key.as_str(),
                    "file_path" | "filePath" | "path" | "notebook_path"
                ) {
                    if let Some(path) = value.as_str().filter(|path| !path.trim().is_empty()) {
                        let normalized = path.replace('\\', "/");
                        if !paths.contains(&normalized) {
                            paths.push(normalized);
                        }
                    }
                }
                collect_touched_paths(value, depth + 1, paths);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_touched_paths(item, depth + 1, paths);
            }
        }
        _ => {}
    }
}

/// Extract repository path hints from the hook event's tool input.
fn extract_touched_paths(input: &Value) -> Vec<String> {
    let mut paths = Vec::new();
    if let Some(tool_input) = input.get("tool_input") {
        collect_touched_paths(tool_input, 0, &mut paths);
    }
    paths.sort();
    paths
}

/// Return whether a successful tool event may have changed repository files.
fn tool_may_modify_repository(tool_name: &str) -> bool {
    let normalized = tool_name.to_ascii_lowercase().replace(['-', '_'], "");
    matches!(
        normalized.as_str(),
        "bash" | "write" | "edit" | "multiedit" | "notebookedit" | "applypatch"
    ) || normalized.ends_with("applypatch")
}

/// Whether a gate that cannot be reached should deny (fail closed) rather than
/// allow (fail open). Defaults to false to preserve the documented fail-open
/// behavior; security-conscious operators set KLEOS_HOOK_GATE_FAIL_CLOSED=1.
fn gate_fail_closed() -> bool {
    std::env::var("KLEOS_HOOK_GATE_FAIL_CLOSED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Maximum number of characters of upstream error text carried into a deny
/// reason. Long bodies (HTML error pages, stack traces) add no diagnostic value
/// at the point of denial and would flood the agent's context.
const GATE_FAILURE_DETAIL_MAX: usize = 300;

/// Extracts the leading HTTP status emitted by `kleos-client` errors.
///
/// Transport failures may contain status-like text later in their detail, so
/// only the canonical `HTTP <code>` prefix is accepted.
fn http_error_status(err: &str) -> Option<u16> {
    err.strip_prefix("HTTP ")
        .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|code| code.parse::<u16>().ok())
}

/// Returns whether a failed gate request should receive its one permitted retry.
fn should_retry_gate_check(err: &str) -> bool {
    http_error_status(err) == Some(401)
}

/// Posts a gate check and retries once after an authentication rejection.
///
/// `Client::post_with_timeout` clears its cached signing session before
/// returning HTTP 401, so the second call signs afresh. Other failures are
/// returned immediately, and a failed retry becomes the final gate error.
async fn request_gate_check(client: &Client, gate_body: Value) -> Result<Value, String> {
    match client
        .post_with_timeout("/gate/check", gate_body.clone(), GATE_TIMEOUT)
        .await
    {
        Err(err) if should_retry_gate_check(&err) => {
            client
                .post_with_timeout("/gate/check", gate_body, GATE_TIMEOUT)
                .await
        }
        result => result,
    }
}

/// Turns a raw client error into an operator-actionable one-line explanation
/// for a fail-closed deny.
///
/// The gate previously reported every failure class as "gate unreachable",
/// which conflated three very different situations and made the denial
/// impossible to diagnose from the agent side. `post_with_timeout` returns
/// `Err` for any non-2xx status, so a rate-limited, unauthorised, or
/// erroring-but-perfectly-reachable server looked identical to a severed
/// network. This distinguishes them and names the likely remedy.
///
/// Note the caller is a *deny* path: every genuine gate decision comes back as
/// HTTP 201 with its own reason, so anything reaching here is a transport or
/// status fault rather than a policy block.
fn describe_gate_failure(err: &str) -> String {
    let detail = redact_secrets(err);
    let detail = truncate_detail(&detail);

    // The client formats status failures as "HTTP <code>: <body>"; anything
    // else came from the transport layer (connect, DNS, TLS, timeout).
    let status = http_error_status(err);

    match status {
        Some(429) => format!(
            "server is reachable but rate-limited this request (HTTP 429); \
             retry after the window resets. Detail: {detail}"
        ),
        Some(401) | Some(403) => format!(
            "server is reachable but rejected this agent's credentials \
             (HTTP {}); check the API key or signer identity. Detail: {detail}",
            status.unwrap_or_default()
        ),
        Some(413) => format!(
            "server is reachable but the gate payload exceeded its body limit \
             (HTTP 413). Detail: {detail}"
        ),
        Some(code) if (500..=599).contains(&code) => format!(
            "server is reachable but returned a server error (HTTP {code}); \
             this is a Kleos-side fault, not a network outage. Detail: {detail}"
        ),
        Some(code) => format!(
            "server is reachable but rejected the gate request (HTTP {code}). \
             Detail: {detail}"
        ),
        None => format!(
            "could not complete the gate request (transport failure or timeout); \
             check KLEOS_URL reachability. Detail: {detail}"
        ),
    }
}

/// Truncates error detail on a character boundary so multibyte upstream text
/// cannot panic the slice.
fn truncate_detail(s: &str) -> String {
    if s.chars().count() <= GATE_FAILURE_DETAIL_MAX {
        return s.to_string();
    }
    let kept: String = s.chars().take(GATE_FAILURE_DETAIL_MAX).collect();
    format!("{kept}... (truncated)")
}

/// Strips credential-shaped material from text that is about to be surfaced to
/// the agent.
///
/// The deny reason is echoed straight into the model's context, so a bearer
/// token or signed-URL query parameter that appeared in an upstream error
/// string must not ride along. Kleos policy is to keep credentials and signed
/// URLs out of logs, CLI output, and MCP output alike.
fn redact_secrets(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    // A scheme keyword such as `Bearer` carries its secret in the *following*
    // whitespace-separated token, so redacting the keyword alone would leave the
    // credential in place. This flag consumes that trailing value too.
    let mut redact_next_value = false;

    for token in s.split_inclusive(char::is_whitespace) {
        let trimmed = token.trim_end();
        let had_trailing_space = token.len() > trimmed.len();
        let lower = trimmed.to_ascii_lowercase();

        // Keywords whose secret lives in the next token.
        let is_scheme_keyword = lower == "bearer" || lower == "authorization:" || lower == "token";
        // Tokens that embed the secret inline, typically `key=value` pairs.
        let is_inline_secret = lower.starts_with("bearer")
            || lower.contains("api_key=")
            || lower.contains("apikey=")
            || lower.contains("access_token=")
            || lower.contains("token=")
            || lower.contains("signature=")
            || lower.contains("x-kleos-session");

        if redact_next_value || is_scheme_keyword || is_inline_secret {
            out.push_str("[redacted]");
            if had_trailing_space {
                out.push(' ');
            }
            // A scheme keyword defers to the next token; an inline `key=value`
            // already swallowed its own secret and defers to nothing.
            redact_next_value = is_scheme_keyword;
        } else {
            out.push_str(token);
            redact_next_value = false;
        }
    }
    out
}

/// Builds a hook response that denies the current tool use with a reason.
fn build_deny_output(event: &str, reason: &str) -> Value {
    json!({
        "hookSpecificOutput": {
            "hookEventName": event,
            "permissionDecision": "deny",
            "permissionDecisionReason": reason
        }
    })
}

/// Recognize only dedicated patch tools, never shell tools that mention patches.
fn is_patch_tool(tool_name: &str) -> bool {
    matches!(tool_name, "apply_patch" | "functions.apply_patch")
}

/// Summarize patch destinations without treating source text as a shell command.
/// Unexpected framing or body syntax is denied rather than silently omitted.
fn patch_command(input: &Value) -> Result<String, &'static str> {
    if let Some(fields) = input.as_object() {
        if ["input", "patch", "command"]
            .iter()
            .filter(|key| fields.contains_key(**key))
            .count()
            != 1
        {
            return Err("Patch input must contain exactly one patch field");
        }
    }
    let patch = input
        .as_str()
        .or_else(|| input.get("input").and_then(Value::as_str))
        .or_else(|| input.get("patch").and_then(Value::as_str))
        .or_else(|| input.get("command").and_then(Value::as_str))
        .ok_or("Patch input must contain a patch string")?;
    let mut lines = patch.lines();
    if lines.next() != Some("*** Begin Patch") {
        return Err("Patch must start with its begin marker");
    }
    let mut paths = Vec::new();
    let mut operation = "";
    while let Some(line) = lines.next() {
        if line == "*** End Patch" {
            return if !paths.is_empty() && lines.next().is_none() {
                Ok(paths.join("\n"))
            } else {
                Err("Patch must contain file operations and no trailing content")
            };
        }
        let header = ["Update File", "Add File", "Delete File", "Move to"]
            .iter()
            .find_map(|kind| {
                line.strip_prefix(&format!("*** {kind}: "))
                    .map(|path| (*kind, path))
            });
        if let Some((kind, path)) = header {
            if path.trim().is_empty() || path.chars().any(char::is_control) {
                return Err("Patch file paths must be nonempty and contain no control characters");
            }
            if kind == "Move to" {
                if operation != "Update File" {
                    return Err("Patch move destination must follow an update");
                }
            } else {
                operation = kind;
            }
            paths.push(format!("Edit {path}"));
        } else {
            let valid = match operation {
                "Add File" => line.starts_with('+'),
                "Update File" => {
                    line.starts_with(['+', '-', ' '])
                        || line == "@@"
                        || line.starts_with("@@ ")
                        || line == "*** End of File"
                }
                _ => false,
            };
            if !valid {
                return Err("Patch contains an unexpected operation or body line");
            }
        }
    }
    Err("Patch must end with its end marker")
}

/// Derive the "command" string from Claude Code's tool_input JSON.
/// For Bash: the literal command. For Write/Edit: "Write to <path>" or "Edit <path>".
/// For others: serialized summary.
fn derive_command(tool_name: &str, tool_input: &Value) -> Result<String, &'static str> {
    if is_patch_tool(tool_name) {
        return patch_command(tool_input);
    }
    Ok(match tool_name {
        "Bash" => tool_input
            .get("command")
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string(),
        "Write" | "Edit" => {
            let path = tool_input
                .get("file_path")
                .and_then(|p| p.as_str())
                .unwrap_or("<unknown>");
            format!("{} {}", tool_name, path)
        }
        "WebFetch" => tool_input
            .get("url")
            .and_then(|u| u.as_str())
            .unwrap_or("WebFetch")
            .to_string(),
        "WebSearch" => tool_input
            .get("query")
            .and_then(|q| q.as_str())
            .unwrap_or("WebSearch")
            .to_string(),
        _ => format!(
            "{}: {}",
            tool_name,
            serde_json::to_string(tool_input).unwrap_or_default()
        ),
    })
}

// --- Hook handlers ---

/// Handles SessionStart by registering the session, fetching living context,
/// and injecting the coordination banner plus mandatory rules on stdout.
async fn handle_session_start(client: &Client, input: &Value) {
    let agent = resolve_agent();
    let project = cwd_project(input);
    let session_id = extract_session_id(input);
    let cwd = hook_cwd(input);

    // Read coordination state BEFORE registering this session, so the banner
    // reflects who was already working in this project, not our own arrival.
    let coordination = fetch_coordination_banner(client, project.as_deref()).await;

    // Register session with activity (best-effort). Report the real project
    // (working-directory basename) so Chiasm/Axon know which checkout this
    // session is in; the record previously always said "unknown".
    let _ = client
        .post_with_timeout(
            "/activity",
            json!({
                "agent": agent.clone(),
                "action": "session.start",
                "summary": "session started",
                "project": project.clone().unwrap_or_else(|| "unknown".to_string())
            }),
            DEFAULT_TIMEOUT,
        )
        .await;

    let _ = sidecar_post(
        "/session/start",
        &json!({
            "session_id": session_id,
            "agent": agent.clone(),
            "cwd": cwd,
        }),
        SIDECAR_SESSION_TIMEOUT,
    )
    .await;

    // Fetch growth context (best-effort)
    let growth_path = format!(
        "/growth/materialize?service={}&limit=30&max_bytes=16000",
        utf8_percent_encode(&agent, NON_ALPHANUMERIC)
    );
    let growth_text = match client.get_with_timeout(&growth_path, DEFAULT_TIMEOUT).await {
        Ok(v) => v
            .get("context")
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string(),
        Err(_) => String::new(),
    };

    // Living prompt: the brain-aware context built by build_living_prompt on the
    // server. This is the primary content -- the Gemini hook already uses this path;
    // the Claude hook previously only carried policy rules + growth, leaving the
    // block empty whenever the operator had no mandatory rules configured.
    let living_text = match client
        .post_with_timeout(
            "/prompt/generate",
            json!({
                "agent": agent,
                "task": bootstrap_task_query(input),
                "include_brain": true,
                // Growth context is appended separately from /growth/materialize
                // below; include_growth=true here duplicated it (memory #27946).
                "include_growth": false,
                "include_personality": true,
            }),
            DEFAULT_TIMEOUT,
        )
        .await
    {
        Ok(v) => v
            .get("prompt")
            .and_then(|p| p.as_str())
            .unwrap_or("")
            .to_string(),
        Err(_) => String::new(),
    };

    let rules = fetch_mandatory_rules(client).await;
    let mut ctx = String::from("=== EIDOLON LIVING CONTEXT ===\n\n");
    if !living_text.is_empty() {
        ctx.push_str(&living_text);
    }
    if !rules.is_empty() {
        ctx.push_str("\n\n--- Mandatory Rules ---\n");
        ctx.push_str(&rules);
    }
    if !growth_text.is_empty() {
        ctx.push_str("\n\n--- Growth Context ---\n");
        ctx.push_str(&growth_text);
    }
    if !coordination.is_empty() {
        ctx.push_str("\n\n--- Coordination ---\n");
        ctx.push_str(&coordination);
    }
    ctx.push_str("\n\n=== END EIDOLON CONTEXT ===");

    emit(&build_context_output("SessionStart", &ctx));
}

/// Handles UserPromptSubmit by recalling context and enforcing supervisor injections.
async fn handle_user_prompt(client: &Client, input: &Value) {
    let session_id = extract_session_id(input);

    // Recall relevant memories from the sidecar before the prompt is processed.
    let recall_context = match input
        .get("prompt")
        .and_then(|v| v.as_str())
        .filter(|p| !p.is_empty())
    {
        Some(user_message) => {
            let budget = std::env::var("KLEOS_RECALL_BUDGET").unwrap_or_else(|_| "mid".to_string());
            let max_tokens: usize = std::env::var("KLEOS_RECALL_MAX_TOKENS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1024);
            let context_turns: usize = std::env::var("KLEOS_RECALL_CONTEXT_TURNS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1);
            let max_query_chars: usize = std::env::var("KLEOS_RECALL_MAX_QUERY_CHARS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(800);

            let recall_message = contextual_recall_message(input, user_message, max_query_chars);
            let recall_body = json!({
                "message": recall_message,
                "budget": budget,
                "context_turns": context_turns,
                "max_tokens": max_tokens,
                "max_query_chars": max_query_chars,
                "session_id": session_id,
                "cwd": hook_cwd(input),
                "may_modify_repo": false,
            });

            sidecar_post("/recall", &recall_body, SIDECAR_RECALL_TIMEOUT)
                .await
                .and_then(|resp| {
                    resp.get("context")
                        .and_then(|c| c.as_str())
                        .filter(|ctx| !ctx.is_empty())
                        .map(ToOwned::to_owned)
                })
        }
        None => None,
    };

    // Drain supervisor for pending violations
    let encoded_session = utf8_percent_encode(&session_id, NON_ALPHANUMERIC).to_string();
    let pending_path = format!("/supervisor/pending?session_id={}", encoded_session);
    if let Ok(v) = client
        .get_with_timeout(&pending_path, DEFAULT_TIMEOUT)
        .await
    {
        let injections = v
            .get("injections")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        if !injections.is_empty() {
            let msg = injections
                .first()
                .and_then(|vio| vio.get("message").and_then(|m| m.as_str()))
                .unwrap_or("policy violation detected");
            emit(&build_deny_output(
                "UserPromptSubmit",
                &format!("Supervisor violation: {}", msg),
            ));
            return;
        }
    }

    if let Some(context) = recall_context {
        emit(&build_context_output("UserPromptSubmit", &context));
    }
}

/// Handles Stop by recording session end and notifying the optional sidecar.
async fn handle_stop(client: &Client, input: &Value) {
    let session_id = extract_session_id(input);
    complete_session_gates(client, &session_id).await;

    let _ = client
        .post_with_timeout(
            "/activity",
            json!({
                "agent": resolve_agent(),
                "action": "session.end",
                "summary": "session ended"
            }),
            DEFAULT_TIMEOUT,
        )
        .await;

    let _ = sidecar_post(
        "/end",
        &json!({ "session_id": session_id }),
        SIDECAR_END_TIMEOUT,
    )
    .await;
}

/// Close every eligible open gate at session end without spinning on a gate
/// whose memory-store precondition has not yet been satisfied.
async fn complete_session_gates(client: &Client, session_id: &str) {
    for _ in 0..MAX_GATE_COMPLETIONS_PER_STOP {
        let response = match client
            .post_with_timeout(
                "/gate/complete-latest",
                json!({
                    "session_id": session_id,
                    "output": "session completed",
                    "known_secrets": [],
                }),
                DEFAULT_TIMEOUT,
            )
            .await
        {
            Ok(response) => response,
            Err(error) => {
                eprintln!("kleos hook stop: gate completion failed ({error})");
                break;
            }
        };

        if !response
            .get("completed")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            break;
        }
    }
}

/// Handles PreToolUse by asking the server gate whether the proposed tool use is allowed.
async fn handle_pre_tool(client: &Client, input: &Value) {
    let tool_name = input
        .get("tool_name")
        .and_then(|t| t.as_str())
        .unwrap_or("");
    let tool_input = input.get("tool_input").cloned().unwrap_or(json!({}));
    let session_id = extract_session_id(input);

    let command = match derive_command(tool_name, &tool_input) {
        Ok(command) => command,
        Err(reason) => {
            emit(&build_deny_output(
                "PreToolUse",
                &format!("Invalid file edit: {reason}. Submit a well-formed patch."),
            ));
            return;
        }
    };
    // Dedicated patch tools use the existing edit approval policy, not an unknown-tool path.
    let gate_tool_name = if is_patch_tool(tool_name) {
        "Edit"
    } else {
        tool_name
    };

    // Derive agent name from signer (matches PIV enrollment)
    let agent = client.agent_label();

    // The server enforces Forge coverage for one path per request. Check every
    // patch destination separately, preserving multiline shell commands intact.
    let commands: Vec<&str> = if is_patch_tool(tool_name) {
        command.lines().collect()
    } else {
        vec![command.as_str()]
    };
    let mut enrichments = Vec::new();
    for command in commands {
        let gate_body = json!({
            "command": command,
            "agent": agent,
            "tool_name": gate_tool_name,
            "session_id": session_id,
            "context": format!("tool_input: {}", serde_json::to_string(&tool_input).unwrap_or_default()),
        });

        let result = match request_gate_check(client, gate_body).await {
            Ok(v) => v,
            Err(e) => {
                // The gate check did not produce a decision. By default this fails
                // open (see module doc): the same hook bundle also drives context
                // injection and activity reporting, so a Kleos fault must not
                // hard-block every tool use. Operators who want any gate-check
                // failure to deny instead set KLEOS_HOOK_GATE_FAIL_CLOSED=1.
                if gate_fail_closed() {
                    emit(&build_deny_output(
                        "PreToolUse",
                        &format!(
                            "kleos gate check failed and KLEOS_HOOK_GATE_FAIL_CLOSED is set: {}",
                            describe_gate_failure(&e)
                        ),
                    ));
                } else {
                    eprintln!("kleos hook pre-tool: gate check failed ({}), allowing", e);
                }
                return;
            }
        };

        // A reachable gate that omits or malforms `allowed` must not be treated as
        // an implicit allow -- default to deny so a partial response cannot bypass
        // the gate.
        let allowed = result
            .get("allowed")
            .and_then(|a| a.as_bool())
            .unwrap_or(false);
        let reason = result
            .get("reason")
            .and_then(|r| r.as_str())
            .unwrap_or("blocked by gate");
        let enrichment = result.get("enrichment").and_then(|e| e.as_str());

        if !allowed {
            emit(&build_deny_output("PreToolUse", reason));
            return;
        } else if let Some(enrich) = enrichment {
            enrichments.push(enrich.to_string());
        }
    }
    if !enrichments.is_empty() {
        emit(&build_context_output("PreToolUse", &enrichments.join("\n")));
    }
    // else: no output = implicit allow
}

/// Handles PostToolUse by reporting activity and forwarding an optional observation.
async fn handle_post_tool(client: &Client, input: &Value) {
    let tool_name = input
        .get("tool_name")
        .and_then(|t| t.as_str())
        .unwrap_or("unknown");
    let session_id = extract_session_id(input);
    let touched_paths = extract_touched_paths(input);
    let may_modify_repo = tool_may_modify_repository(tool_name);

    // Report activity (best-effort)
    let _ = client
        .post_with_timeout(
            "/activity",
            json!({
                "agent": resolve_agent(),
                "action": "tool.completed",
                "summary": format!("{} completed", tool_name),
            }),
            DEFAULT_TIMEOUT,
        )
        .await;

    let observe_body = json!({
        "tool_name": tool_name,
        "content": extract_tool_result_text(input, 1500),
        "role": "tool",
        "session_id": session_id,
        "importance": 3,
        "category": "discovery",
        "cwd": hook_cwd(input),
        "touched_paths": touched_paths,
        "may_modify_repo": may_modify_repo,
    });
    let _ = sidecar_post("/observe", &observe_body, SIDECAR_OBSERVE_TIMEOUT).await;
}

// --- Entry point ---

/// Dispatches a hook subcommand to its handler after reading JSON from stdin.
pub async fn run_hook(cmd: &HookCommands, client: &Client) {
    match cmd {
        HookCommands::SessionStart => {
            let input = read_stdin_json();
            handle_session_start(client, &input).await;
        }
        HookCommands::UserPrompt => {
            let input = read_stdin_json();
            handle_user_prompt(client, &input).await;
        }
        HookCommands::Stop => {
            let input = read_stdin_json();
            handle_stop(client, &input).await;
        }
        HookCommands::PreTool => {
            let input = read_stdin_json();
            handle_pre_tool(client, &input).await;
        }
        HookCommands::PostTool | HookCommands::PostBash => {
            let input = read_stdin_json();
            handle_post_tool(client, &input).await;
        }
    }
}

// --- Tests ---

/// Unit tests for hook helpers and output builders.
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Starts a minimal HTTP server that emits the supplied gate statuses and
    /// returns how many requests it served.
    async fn gate_status_server(statuses: &[&str]) -> (Client, tokio::task::JoinHandle<usize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind gate test server");
        let address = listener.local_addr().expect("read gate test address");
        let statuses: Vec<String> = statuses.iter().map(|status| status.to_string()).collect();
        let server = tokio::spawn(async move {
            let mut requests = 0;
            for status in statuses {
                let (mut stream, _) = listener.accept().await.expect("accept gate request");
                let mut request = [0_u8; 4096];
                let _ = stream.read(&mut request).await.expect("read gate request");
                let body = if status.starts_with("201") {
                    r#"{"allowed":true}"#
                } else {
                    r#"{"error":"gate test error"}"#
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write gate response");
                requests += 1;
            }
            requests
        });
        (Client::new(format!("http://{address}"), None, None), server)
    }

    /// Starts a minimal completion endpoint that returns each supplied JSON body.
    async fn gate_completion_server(bodies: &[&str]) -> (Client, tokio::task::JoinHandle<usize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind completion test server");
        let address = listener.local_addr().expect("read completion address");
        let bodies: Vec<String> = bodies.iter().map(|body| body.to_string()).collect();
        let server = tokio::spawn(async move {
            let mut requests = 0;
            for body in bodies {
                let (mut stream, _) = listener.accept().await.expect("accept completion request");
                let mut request = [0_u8; 4096];
                let _ = stream
                    .read(&mut request)
                    .await
                    .expect("read completion request");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write completion response");
                requests += 1;
            }
            requests
        });
        (Client::new(format!("http://{address}"), None, None), server)
    }

    /// A rate-limited server is reachable; saying "unreachable" sent operators
    /// hunting a network fault that did not exist.
    #[test]
    fn gate_failure_names_rate_limiting_as_reachable() {
        let d = describe_gate_failure(
            r#"HTTP 429 Too Many Requests: {"error":"Rate limit exceeded."}"#,
        );
        assert!(d.contains("reachable"), "{d}");
        assert!(d.contains("429"), "{d}");
        assert!(!d.contains("unreachable"), "{d}");
    }

    /// Auth rejections point at the signer/API key, not the network.
    #[test]
    fn gate_failure_names_auth_rejection() {
        let d = describe_gate_failure("HTTP 401 Unauthorized: bad signature");
        assert!(d.contains("credentials"), "{d}");
        assert!(!d.contains("unreachable"), "{d}");
    }

    /// Only an initial HTTP 401 should trigger the gate's one-shot retry.
    #[test]
    fn gate_retry_is_limited_to_http_401() {
        assert!(should_retry_gate_check(
            "HTTP 401 Unauthorized: stale session"
        ));
        assert!(!should_retry_gate_check(
            "HTTP 403 Forbidden: insufficient role"
        ));
        assert!(!should_retry_gate_check(
            "HTTP 429 Too Many Requests: slow down"
        ));
        assert!(!should_retry_gate_check(
            "HTTP 500 Internal Server Error: boom"
        ));
        assert!(!should_retry_gate_check(
            "POST http://kleos.example/gate/check failed (HTTP 401 in body)"
        ));
    }

    /// A rejected first request is repeated once and can recover successfully.
    #[tokio::test]
    async fn gate_check_retries_once_after_http_401() {
        let (client, server) = gate_status_server(&["401 Unauthorized", "201 Created"]).await;
        let result = request_gate_check(&client, json!({"command": "test"}))
            .await
            .expect("second gate request should recover");

        assert_eq!(result["allowed"], true);
        assert_eq!(server.await.expect("join gate test server"), 2);
    }

    /// A second HTTP 401 is returned without making a third request.
    #[tokio::test]
    async fn gate_check_stops_after_one_retry() {
        let (client, server) = gate_status_server(&["401 Unauthorized", "401 Unauthorized"]).await;
        let error = request_gate_check(&client, json!({"command": "test"}))
            .await
            .expect_err("second authentication rejection must remain an error");

        assert!(error.starts_with("HTTP 401"), "{error}");
        assert_eq!(server.await.expect("join gate test server"), 2);
    }

    /// A non-authentication status is returned after the first request.
    #[tokio::test]
    async fn gate_check_does_not_retry_http_403() {
        let (client, server) = gate_status_server(&["403 Forbidden"]).await;
        let error = request_gate_check(&client, json!({"command": "test"}))
            .await
            .expect_err("authorization rejection must remain an error");

        assert!(error.starts_with("HTTP 403"), "{error}");
        assert_eq!(server.await.expect("join gate test server"), 1);
    }

    /// Stop-time completion drains eligible gates and stops at the first waiting state.
    #[tokio::test]
    async fn session_gate_completion_stops_when_no_gate_completed() {
        let (client, server) = gate_completion_server(&[
            r#"{"ok":true,"completed":true,"gate_id":3}"#,
            r#"{"ok":true,"completed":true,"gate_id":2}"#,
            r#"{"ok":true,"completed":false,"gate_id":1,"reason":"awaiting memory store"}"#,
        ])
        .await;

        complete_session_gates(&client, "session-test").await;

        assert_eq!(server.await.expect("join completion server"), 3);
    }

    /// A 5xx is a Kleos-side fault and must be attributed as such.
    #[test]
    fn gate_failure_names_server_error_as_kleos_side() {
        let d = describe_gate_failure("HTTP 500 Internal Server Error: boom");
        assert!(d.contains("500"), "{d}");
        assert!(d.contains("Kleos-side"), "{d}");
    }

    /// Only a genuine transport fault should implicate reachability.
    #[test]
    fn gate_failure_names_transport_failure() {
        let d = describe_gate_failure(
            "POST http://kleos.example:4200/gate/check failed (tcp connect error)",
        );
        assert!(d.contains("transport failure or timeout"), "{d}");
        assert!(d.contains("KLEOS_URL"), "{d}");
    }

    /// The reason string is echoed into the agent's context, so credential-shaped
    /// material in upstream error text must never survive into it.
    #[test]
    fn gate_failure_redacts_credentials() {
        let d = describe_gate_failure(
            "HTTP 403 Forbidden: rejected Bearer sk-live-abcdef123456 for api_key=deadbeef",
        );
        assert!(!d.contains("sk-live-abcdef123456"), "{d}");
        assert!(!d.contains("deadbeef"), "{d}");
        assert!(d.contains("[redacted]"), "{d}");
    }

    /// Long upstream bodies are capped, and multibyte text must not panic the cut.
    #[test]
    fn gate_failure_truncates_multibyte_detail_without_panic() {
        let long = format!("HTTP 500: {}", "é".repeat(GATE_FAILURE_DETAIL_MAX * 2));
        let d = describe_gate_failure(&long);
        assert!(d.contains("truncated"), "{d}");
    }

    #[test]
    /// Verifies the bootstrap query derives from cwd and falls back when absent.
    fn test_bootstrap_task_query() {
        // No cwd in input and a current_dir always exists in tests, so build
        // the derived form from a real temp dir to pin the cwd-driven shape.
        let dir = std::env::temp_dir().join("kleos-bootstrap-query-test");
        let _ = std::fs::create_dir_all(&dir);
        let input = serde_json::json!({ "cwd": dir.to_string_lossy() });
        let q = bootstrap_task_query(&input);
        assert!(q.starts_with("kleos-bootstrap-query-test project"));
        assert!(q.ends_with("active-tasks recent-decisions agent-rules"));

        // A cwd with no basename (filesystem root) falls back to the legacy query.
        let root = serde_json::json!({ "cwd": "/" });
        assert_eq!(bootstrap_task_query(&root), LEGACY_BOOTSTRAP_QUERY);
    }

    #[test]
    /// Empty task list yields no banner (quiet when nobody else is working here).
    fn test_coordination_banner_empty() {
        assert!(format_coordination_banner("Kleos", &[]).is_empty());
    }

    #[test]
    /// A non-empty task list renders agent + title lines under a project header.
    fn test_coordination_banner_lists_active_tasks() {
        let tasks = vec![
            json!({"agent": "synapse", "status": "active", "title": "READ-ONLY security audit"}),
            json!({"agent": "codex", "status": "active", "title": "migration backfill"}),
        ];
        let out = format_coordination_banner("Kleos", &tasks);
        assert!(out.contains("2 active task(s) in project `Kleos`"));
        assert!(out.contains("synapse (active): READ-ONLY security audit"));
        assert!(out.contains("codex (active): migration backfill"));
        assert!(out.contains("separate git worktree"));
    }

    #[test]
    /// Verifies context hook output uses Claude's hookSpecificOutput shape.
    fn test_build_context_output_structure() {
        let out = build_context_output("SessionStart", "some context");
        let inner = &out["hookSpecificOutput"];
        assert_eq!(inner["hookEventName"], "SessionStart");
        assert_eq!(inner["additionalContext"], "some context");
        assert!(inner.get("permissionDecision").is_none());
    }

    #[test]
    /// Verifies deny hook output carries the permission decision and reason.
    fn test_build_deny_output_structure() {
        let out = build_deny_output("PreToolUse", "blocked!");
        let inner = &out["hookSpecificOutput"];
        assert_eq!(inner["hookEventName"], "PreToolUse");
        assert_eq!(inner["permissionDecision"], "deny");
        assert_eq!(inner["permissionDecisionReason"], "blocked!");
    }

    #[test]
    /// Verifies explicit session ids are preserved from hook input.
    fn test_extract_session_id_present() {
        let input = json!({ "session_id": "abc-123" });
        assert_eq!(extract_session_id(&input), "abc-123");
    }

    #[test]
    /// Verifies session id extraction still returns a non-empty fallback.
    fn test_extract_session_id_fallback() {
        let input = json!({});
        let id = extract_session_id(&input);
        assert!(!id.is_empty());
    }

    /// Verifies Codex rollout messages expose their role and textual content.
    #[test]
    fn test_transcript_message_reads_codex_payload() {
        let value = json!({
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "Codex Remote Control is failing"}]
            }
        });
        let (role, text) = transcript_message(&value).expect("message should parse");
        assert_eq!(role, "assistant");
        assert_eq!(text, "Codex Remote Control is failing");
    }

    /// Verifies a short follow-up gains its prior subject while skipping itself.
    #[test]
    fn test_contextual_recall_message_uses_recent_dialogue() {
        let path = std::env::temp_dir().join(format!(
            "kleos-recall-transcript-{}-{}.jsonl",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        let lines = [
            json!({"payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"Remote Control broke on every phone"}]}}),
            json!({"payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"I am checking Codex Remote Control versions"}]}}),
            json!({"payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"it worked yesterday"}]}}),
        ];
        let transcript = lines
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&path, transcript).expect("transcript fixture should write");
        let input = json!({"transcript_path": path});

        let query = contextual_recall_message(&input, "it worked yesterday", 800);

        let _ = std::fs::remove_file(input["transcript_path"].as_str().unwrap_or_default());
        assert!(query.starts_with("Current prompt: it worked yesterday"));
        assert!(query.contains("Codex Remote Control versions"));
        assert!(query.contains("Remote Control broke on every phone"));
        assert_eq!(query.matches("it worked yesterday").count(), 1);
    }

    /// Verifies self-contained long prompts are not diluted with transcript history.
    #[test]
    fn test_contextual_recall_message_preserves_long_prompt() {
        let prompt = "x".repeat(500);
        let query = contextual_recall_message(&json!({}), &prompt, 800);
        assert_eq!(query, prompt);
    }

    #[test]
    /// Verifies Bash tool inputs use the literal command string.
    fn test_derive_command_bash() {
        let input = json!({"command": "ls -la"});
        assert_eq!(derive_command("Bash", &input).unwrap(), "ls -la");
    }

    #[test]
    /// Verifies Write tool inputs summarize the destination path.
    fn test_derive_command_write() {
        let input = json!({"file_path": "/tmp/foo.rs"});
        assert_eq!(
            derive_command("Write", &input).unwrap(),
            "Write /tmp/foo.rs"
        );
    }

    #[test]
    /// Verifies Edit tool inputs summarize the edited path.
    fn test_derive_command_edit() {
        let input = json!({"file_path": "/tmp/bar.rs"});
        assert_eq!(derive_command("Edit", &input).unwrap(), "Edit /tmp/bar.rs");
    }

    /// Patch bodies are source data, while every affected path remains visible to policy.
    #[test]
    fn test_derive_command_patch_paths() {
        let patch = "*** Begin Patch\n*** Update File: src/a.rs\n@@\n-old\n+new\n*** Add File: src/b.rs\n+content\n*** End Patch";
        assert_eq!(
            derive_command("apply_patch", &json!(patch)).unwrap(),
            "Edit src/a.rs\nEdit src/b.rs"
        );
        assert_eq!(
            derive_command("functions.apply_patch", &json!({"input": patch})).unwrap(),
            "Edit src/a.rs\nEdit src/b.rs"
        );
        assert_eq!(
            derive_command("apply_patch", &json!({"command": patch})).unwrap(),
            "Edit src/a.rs\nEdit src/b.rs"
        );
    }

    /// Renames retain both destinations and deletes remain visible as mutations.
    #[test]
    fn test_derive_command_patch_move_and_delete() {
        let patch = "*** Begin Patch\n*** Update File: old.rs\n*** Move to: new.rs\n@@\n-old\n+new\n*** Delete File: retired.rs\n*** End Patch\n";
        assert_eq!(
            derive_command("apply_patch", &json!({"patch": patch})).unwrap(),
            "Edit old.rs\nEdit new.rs\nEdit retired.rs"
        );
    }

    /// Incomplete, ambiguous, and mixed executable input cannot pass as file edits.
    #[test]
    fn test_derive_command_patch_rejects_malformed_input() {
        for patch in [
            "",
            "*** Begin Patch\n*** End Patch",
            "*** Begin Patch\n*** Add File: a.rs\n+x",
            "*** Begin Patch\n*** Add File: a.rs\n+x\n*** End Patch\necho tail",
            "*** Begin Patch\n*** Add File: \n+x\n*** End Patch",
            "*** Begin Patch\n*** Move to: b.rs\n*** End Patch",
            "*** Begin Patch\n*** Delete File: a.rs\necho body\n*** End Patch",
            "*** Begin Patch\n*** Add File: a\tb.rs\n+x\n*** End Patch",
        ] {
            assert!(
                derive_command("apply_patch", &json!(patch)).is_err(),
                "{patch}"
            );
        }
        assert!(derive_command("apply_patch", &json!({"command": "echo text"})).is_err());
        let patch = "*** Begin Patch\n*** Add File: a.rs\n+x\n*** End Patch";
        assert!(derive_command("apply_patch", &json!({"input": patch, "command": patch})).is_err());
        assert!(derive_command("apply_patch", &json!({"input": null, "command": patch})).is_err());
    }

    /// Shell and unknown tools retain their full input even when it resembles a patch.
    #[test]
    fn test_derive_command_patch_does_not_reclassify_shell() {
        let patch = "*** Begin Patch\n*** Add File: a.rs\n+x\n*** End Patch";
        assert_eq!(
            derive_command("Bash", &json!({"command": patch})).unwrap(),
            patch
        );
        assert!(!is_patch_tool("Bash"));
        assert!(!is_patch_tool("unknown_apply_patch"));
        assert!(derive_command("unknown_apply_patch", &json!(patch))
            .unwrap()
            .contains("+x"));
    }

    #[test]
    /// Verifies WebFetch inputs derive a useful URL command summary.
    fn test_derive_command_other() {
        let input = json!({"url": "https://example.com"});
        let cmd = derive_command("WebFetch", &input).unwrap();
        assert_eq!(cmd, "https://example.com");
    }

    /// Nested tool inputs yield unique path hints and ignore unrelated strings.
    #[test]
    fn extracts_bounded_touched_paths() {
        let input = json!({
            "tool_input": {
                "file_path": "/repo/src/lib.rs",
                "edits": [
                    {"path": "src/main.rs"},
                    {"filePath": "/repo/src/lib.rs"},
                    {"message": "not/a/path/hint"}
                ]
            }
        });

        assert_eq!(
            extract_touched_paths(&input),
            vec!["/repo/src/lib.rs", "src/main.rs"]
        );
    }

    /// Mutating hook tools trigger incremental refresh while read-only tools do not.
    #[test]
    fn classifies_repository_mutators() {
        assert!(tool_may_modify_repository("Edit"));
        assert!(tool_may_modify_repository("NotebookEdit"));
        assert!(tool_may_modify_repository("mcp__filesystem__apply_patch"));
        assert!(tool_may_modify_repository("Bash"));
        assert!(!tool_may_modify_repository("Read"));
        assert!(!tool_may_modify_repository("WebSearch"));
    }
}
