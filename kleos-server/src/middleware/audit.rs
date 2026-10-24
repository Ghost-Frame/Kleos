use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use kleos_lib::auth::AuthContext;
use kleos_lib::db::Database;
use tokio_util::sync::CancellationToken;

use crate::middleware::client_ip::client_ip;
use crate::state::AppState;

/// Capacity of the audit event channel. Sized so short DB stalls do not drop
/// events, while a sustained stall sheds load instead of queueing unboundedly.
const AUDIT_CHANNEL_CAPACITY: usize = 1024;

/// One HTTP request's audit fields, captured in the middleware and written to
/// the audit trail by the dedicated worker task.
pub struct AuditEvent {
    /// Authenticated user id, when the request carried auth.
    pub user_id: Option<i64>,
    /// Agent id from the API key, when present.
    pub agent_id: Option<i64>,
    /// Identity-key id, when the request was PIV/identity authenticated.
    pub identity_id: Option<i64>,
    /// Identity tier label (e.g. "piv", "soft"), when present.
    pub tier: Option<String>,
    /// HTTP method (lowercased into the action string by the worker).
    pub method: String,
    /// Request path.
    pub path: String,
    /// Response status code.
    pub status: u16,
    /// Trusted-proxy-resolved client IP, if determinable.
    pub ip: Option<String>,
    /// MCP tool name when this event records one `tools/call` inside a
    /// `POST /mcp` request rather than the outer HTTP request itself. The
    /// worker writes such events as `mcp.tool` rows so per-tool counts are
    /// queryable even though every MCP call shares the same HTTP path.
    pub tool: Option<String>,
    /// Bounded preview of the search text for memory search tools, so the
    /// audit trail shows what a person was looking for, not just that they
    /// looked. Empty for every other tool.
    pub query_preview: Option<String>,
}

/// Spawn the dedicated audit-log worker and return the sender half.
///
/// Finding [57]: the middleware previously awaited a semaphore permit and the
/// background JoinSet mutex on the response path, so audit backpressure (or
/// lock contention) delayed every response. The worker owns the only DB writes;
/// the middleware just try_sends into the bounded channel. On shutdown the
/// worker drains what is already queued, then exits.
pub fn spawn_audit_worker(
    db: Arc<Database>,
    shutdown: CancellationToken,
) -> tokio::sync::mpsc::Sender<AuditEvent> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<AuditEvent>(AUDIT_CHANNEL_CAPACITY);
    tokio::spawn(async move {
        loop {
            let event = tokio::select! {
                _ = shutdown.cancelled() => {
                    // Close first so producers cannot enqueue after the final drain check.
                    rx.close();
                    // Drain without waiting for new events, then stop.
                    while let Ok(ev) = rx.try_recv() {
                        write_audit_event(&db, ev).await;
                    }
                    tracing::debug!("audit-log worker drained on shutdown");
                    break;
                }
                ev = rx.recv() => match ev {
                    Some(ev) => ev,
                    // All senders dropped (server tearing down).
                    None => break,
                },
            };
            write_audit_event(&db, event).await;
        }
    });
    tx
}

/// Write a single audit event to the audit trail; failures are logged, never
/// propagated (audit is best-effort by design).
async fn write_audit_event(db: &Database, ev: AuditEvent) {
    // An MCP tool call is recorded by tool name; the outer transport request
    // already produced its own `http.post path=/mcp` row.
    let (action, target_type, details) = match &ev.tool {
        Some(tool) => {
            let mut details = format!("tool={} status={}", tool, ev.status);
            if let Some(query) = &ev.query_preview {
                details.push_str(" query=");
                details.push_str(query);
            }
            ("mcp.tool".to_string(), "mcp", details)
        }
        None => (
            format!("http.{}", ev.method.to_lowercase()),
            "http",
            format!("path={} status={}", ev.path, ev.status),
        ),
    };
    if let Err(e) = kleos_lib::audit::log_request(
        db,
        ev.user_id,
        ev.agent_id,
        &action,
        Some(target_type),
        None,
        Some(&details),
        ev.ip.as_deref(),
        None,
        ev.identity_id,
        ev.tier.as_deref(),
    )
    .await
    {
        tracing::warn!("audit log failed: {}", e);
    }
}

/// Delivers an audit event without losing it if the background receiver has closed.
pub(crate) async fn dispatch_audit_event(
    db: &Database,
    audit_tx: &tokio::sync::mpsc::Sender<AuditEvent>,
    event: AuditEvent,
) {
    match audit_tx.try_send(event) {
        Ok(()) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            tracing::warn!("audit event dropped: channel full");
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(event)) => {
            write_audit_event(db, event).await;
        }
    }
}

/// Axum middleware that logs every HTTP request to the audit trail.
///
/// Runs after auth middleware so that `AuthContext` is available in extensions.
/// The response path normally uses a non-blocking bounded channel. If the
/// receiver has already closed, it writes directly so an in-flight request is
/// still recorded. A full channel continues to shed load (finding [57]).
#[tracing::instrument(skip_all, fields(middleware = "server.audit"))]
pub async fn audit_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    // Record activity timestamp so the dreamer can gate heavy work behind
    // idleness.  We use a monotonic millisecond counter rather than
    // wall-clock seconds: NTP steps and DST transitions can move
    // SystemTime backwards, which would make the dreamer either spin
    // (elapsed < 0 wraps via saturating_sub) or skip cycles forever.
    state.last_request_time.store(
        crate::dreamer::monotonic_millis(),
        std::sync::atomic::Ordering::Relaxed,
    );

    // Capture pre-request fields before the request is consumed.
    let auth_ctx = request.extensions().get::<AuthContext>().cloned();
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    // SECURITY: share the rate-limiter's trusted-proxy resolver so we
    // don't log attacker-controlled XFF/X-Real-IP values as if they were
    // the caller's real address.
    let ip = client_ip(&request, &state.config.trusted_proxies);

    let response = next.run(request).await;
    let status = response.status().as_u16();

    let (user_id, agent_id, identity_id, tier) = auth_ctx
        .map(|ctx| {
            let (iid, t) = ctx
                .identity
                .as_ref()
                .map(|id| (id.identity_id, Some(id.tier.as_str().to_string())))
                .unwrap_or((None, None));
            (Some(ctx.user_id), ctx.key.agent_id, iid, t)
        })
        .unwrap_or((None, None, None, None));

    dispatch_audit_event(
        &state.db,
        &state.audit_tx,
        AuditEvent {
            user_id,
            agent_id,
            identity_id,
            tier,
            method,
            path,
            status,
            ip,
            tool: None,
            query_preview: None,
        },
    )
    .await;

    response
}

#[cfg(test)]
/// Regression coverage for audit delivery behavior.
mod tests {
    use super::*;

    /// Verifies that a closed background receiver falls back to a direct database write.
    #[tokio::test]
    async fn closed_receiver_persists_event_directly() {
        let db = Database::connect_memory().await.unwrap();
        let (audit_tx, mut audit_rx) = tokio::sync::mpsc::channel(1);
        audit_rx.close();

        dispatch_audit_event(
            &db,
            &audit_tx,
            AuditEvent {
                user_id: Some(42),
                agent_id: None,
                identity_id: None,
                tier: None,
                method: "POST".to_string(),
                path: "/store".to_string(),
                status: 200,
                ip: Some("127.0.0.1".to_string()),
                tool: None,
                query_preview: None,
            },
        )
        .await;

        let count = db
            .read(|conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM audit_log WHERE user_id = 42
                     AND action = 'http.post' AND details = 'path=/store status=200'",
                    [],
                    |row| row.get::<_, i64>(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    /// Verifies that an MCP tool-call event is written as an `mcp.tool` row
    /// carrying the tool name, status, and search preview.
    #[tokio::test]
    async fn mcp_tool_event_is_written_by_tool_name() {
        let db = Database::connect_memory().await.unwrap();
        let (audit_tx, mut audit_rx) = tokio::sync::mpsc::channel(1);
        audit_rx.close();

        dispatch_audit_event(
            &db,
            &audit_tx,
            AuditEvent {
                user_id: Some(7),
                agent_id: None,
                identity_id: None,
                tier: None,
                method: "POST".to_string(),
                path: "/mcp".to_string(),
                status: 200,
                ip: None,
                tool: Some("memory_search".to_string()),
                query_preview: Some("vendor pricing".to_string()),
            },
        )
        .await;

        let count = db
            .read(|conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM audit_log WHERE user_id = 7
                     AND action = 'mcp.tool' AND target_type = 'mcp'
                     AND details = 'tool=memory_search status=200 query=vendor pricing'",
                    [],
                    |row| row.get::<_, i64>(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(count, 1);
    }
}
