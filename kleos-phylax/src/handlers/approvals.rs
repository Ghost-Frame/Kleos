//! Approval workflow handlers.
//!
//! Implements: request, list, get, decide, and wait-for-decision endpoints.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use kleos_cred::CredError;
use kleos_credd::auth::Auth;
use kleos_credd::handlers::AppError;

use crate::audit::{actions, log_phylax_audit};
use crate::models::approval::{self, ApprovalStatus};
use crate::models::lease;
use crate::state::{approval_ttl_secs, PhylaxState, DEFAULT_LEASE_TTL_SECS};

/// Return whether an approved operation resumes by observing approval status
/// directly instead of redeeming a generic secret-resolution lease.
fn uses_direct_approval_status(resolve_mode: &str) -> bool {
    matches!(resolve_mode, "ssh-sign" | "ssh_ca_sign" | "ssh_ca_mint")
}

/// Request body for creating an approval request.
#[derive(Deserialize)]
pub struct ApprovalRequest {
    /// Secret category.
    pub category: String,
    /// Secret name.
    pub secret_name: String,
    /// Resolve mode (text, proxy, raw).
    pub resolve_mode: String,
    /// Optional correlation ID for linking related operations.
    pub correlation_id: Option<String>,
}

/// Query params for listing approvals.
#[derive(Deserialize)]
pub struct ListQuery {
    /// Filter by status (0=pending, 1=approved, 2=denied, 3=expired).
    pub status: Option<i32>,
    /// Maximum number of results.
    pub limit: Option<i64>,
}

/// Request body for deciding an approval.
#[derive(Deserialize)]
pub struct DecisionRequest {
    /// Decision: "approved" or "denied".
    pub decision: String,
    /// Optional reason for the decision.
    pub reason: Option<String>,
}

/// Create a new approval request. Returns 202 Accepted with poll URL.
pub async fn request_approval(
    Auth(auth): Auth,
    State(state): State<PhylaxState>,
    Json(body): Json<ApprovalRequest>,
) -> Result<impl IntoResponse, AppError> {
    let agent_name = auth
        .agent_name()
        .ok_or_else(|| CredError::PermissionDenied("only agents can request approvals".into()))?;

    let expires_at = (chrono::Utc::now()
        + chrono::Duration::seconds(approval_ttl_secs(state.phone_approval_required)))
    .format("%Y-%m-%d %H:%M:%S")
    .to_string();

    let correlation_id = body
        .correlation_id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let (approval, raw_token) = approval::create_approval_with_token(
        &state.inner.db,
        auth.user_id(),
        agent_name,
        &body.category,
        &body.secret_name,
        &body.resolve_mode,
        Some(&correlation_id),
        &expires_at,
    )
    .await?;

    if state.phone_approval_required {
        let binding = approval::bind_phone_approval(&state.inner.db, &approval).await?;
        crate::notify::notify_phone_approval(
            approval.id,
            &body.resolve_mode,
            agent_name,
            &body.category,
            &body.secret_name,
            &expires_at,
            &raw_token,
            &binding,
        )
        .await;
    } else {
        crate::notify::notify_approval(
            approval.id,
            &body.resolve_mode,
            agent_name,
            &body.category,
            &body.secret_name,
            &expires_at,
            &raw_token,
        )
        .await;
    }

    let _ = log_phylax_audit(
        &state.inner.db,
        auth.user_id(),
        Some(agent_name),
        None,
        None,
        None,
        None,
        actions::APPROVAL_REQUESTED,
        &body.category,
        &body.secret_name,
        true,
        Some(&correlation_id),
    )
    .await;

    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "approval_id": approval.id,
            "poll_url": format!("/phylax/approvals/{}/wait", approval.id),
            "correlation_id": correlation_id,
            "expires_at": expires_at,
        })),
    ))
}

/// List approvals for the authenticated user.
pub async fn list_approvals(
    Auth(auth): Auth,
    State(state): State<PhylaxState>,
    Query(query): Query<ListQuery>,
) -> Result<impl IntoResponse, AppError> {
    let status = query.status.and_then(ApprovalStatus::from_i32);
    let limit = query.limit.unwrap_or(50);

    let approvals =
        approval::list_approvals(&state.inner.db, auth.user_id(), status, limit).await?;

    let items: Vec<_> = approvals.iter().map(|a| a.to_json()).collect();
    Ok(Json(json!({ "approvals": items })))
}

/// Get a specific approval by ID.
pub async fn get_approval(
    Auth(auth): Auth,
    State(state): State<PhylaxState>,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, AppError> {
    let a = approval::get_approval(&state.inner.db, id).await?;
    if a.user_id != auth.user_id() && !auth.is_master() {
        return Err(CredError::PermissionDenied("not your approval".into()).into());
    }
    Ok(Json(a.to_json()))
}

/// Approve or deny a pending approval. Master-only.
pub async fn decide_approval(
    Auth(auth): Auth,
    State(state): State<PhylaxState>,
    Path(id): Path<i64>,
    Json(body): Json<DecisionRequest>,
) -> Result<impl IntoResponse, AppError> {
    if !auth.is_master() {
        return Err(CredError::PermissionDenied("master key required".into()).into());
    }

    let decision = match body.decision.as_str() {
        "approved" => ApprovalStatus::Approved,
        "denied" => ApprovalStatus::Denied,
        _ => {
            return Err(
                CredError::InvalidInput("decision must be 'approved' or 'denied'".into()).into(),
            )
        }
    };

    // Get the approval first to know the secret details for audit/lease.
    let a = approval::get_approval(&state.inner.db, id).await?;
    if approval::phone_required(&state.inner.db, id).await? {
        return Err(CredError::PermissionDenied("enrolled phone signature required".into()).into());
    }

    approval::decide_approval(
        &state.inner.db,
        id,
        decision,
        "master",
        body.reason.as_deref(),
    )
    .await?;

    let audit_action = if decision == ApprovalStatus::Approved {
        actions::APPROVAL_GRANTED
    } else {
        actions::APPROVAL_DENIED
    };

    let _ = log_phylax_audit(
        &state.inner.db,
        auth.user_id(),
        Some(&a.agent_name),
        None,
        None,
        None,
        None,
        audit_action,
        &a.category,
        &a.secret_name,
        true,
        a.correlation_id.as_deref(),
    )
    .await;

    // Direct-status handlers read Approved status themselves. A redeemable
    // lease for one of those approvals would be a latent secret-resolution
    // capability unrelated to the requested signing operation.
    let can_issue_operation_lease = !uses_direct_approval_status(&a.resolve_mode)
        && approval::get_operation_digest(&state.inner.db, a.id)
            .await?
            .is_some();
    if decision == ApprovalStatus::Approved && can_issue_operation_lease {
        let l = lease::mint_lease(
            &state.inner.db,
            a.user_id,
            id,
            &a.agent_name,
            &a.category,
            &a.secret_name,
            a.correlation_id.as_deref(),
            DEFAULT_LEASE_TTL_SECS,
        )
        .await?;

        let _ = approval::set_approval_lease(&state.inner.db, id, l.id).await;

        let _ = log_phylax_audit(
            &state.inner.db,
            auth.user_id(),
            Some(&a.agent_name),
            None,
            None,
            None,
            None,
            actions::LEASE_MINTED,
            &a.category,
            &a.secret_name,
            true,
            a.correlation_id.as_deref(),
        )
        .await;

        return Ok(Json(json!({
            "status": "approved",
            "lease": l.to_json(),
        })));
    }

    // Direct-status operations return approved status without a lease.
    if decision == ApprovalStatus::Approved {
        return Ok(Json(json!({ "status": "approved" })));
    }

    Ok(Json(json!({
        "status": "denied",
        "reason": body.reason,
    })))
}

/// Long-poll waiting for an approval decision. Polls DB every 1s for up to 30s.
pub async fn wait_for_decision(
    Auth(auth): Auth,
    State(state): State<PhylaxState>,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, AppError> {
    let timeout = std::time::Duration::from_secs(30);
    let poll_interval = std::time::Duration::from_secs(1);
    let deadline = std::time::Instant::now() + timeout;

    loop {
        let a = approval::get_approval(&state.inner.db, id).await?;

        // A bearer for another agent under the same user must not collect the
        // one-shot lease. Master may inspect status but does not receive the
        // requesting agent's capability.
        if !auth.is_master()
            && (a.user_id != auth.user_id() || auth.agent_name() != Some(a.agent_name.as_str()))
        {
            return Err(CredError::PermissionDenied("not your approval".into()).into());
        }

        if a.status != ApprovalStatus::Pending {
            let mut response = a.to_json();
            if a.status == ApprovalStatus::Approved && !auth.is_master() {
                if let Some(active_lease) = lease::get_active_lease_for_approval(
                    &state.inner.db,
                    a.id,
                    a.user_id,
                    &a.agent_name,
                )
                .await?
                {
                    response["lease"] = active_lease.to_json();
                }
            }
            return Ok(Json(response));
        }

        if std::time::Instant::now() >= deadline {
            return Ok(Json(json!({
                "id": a.id,
                "status": a.status as i32,
                "message": "timeout waiting for decision",
            })));
        }

        tokio::time::sleep(poll_interval).await;
    }
}

/// Request body for a capability-token approval decision.
#[derive(Deserialize)]
pub struct DecideTokenRequest {
    /// The single-use capability token issued when the approval was raised.
    pub token: String,
    /// Legacy Telegram decision: "approved" or "denied".
    pub decision: Option<String>,
    /// Exact-phone signed decision envelope.
    pub phone: Option<crate::models::phone_approval::PhoneDecisionEnvelope>,
}

/// Decide an approval using a single-use capability token instead of a bearer.
///
/// `POST /phylax/approvals/{id}/decide-token`. This route is exempt from bearer
/// auth (see `auth_middleware`): the single-use token IS the capability. It lets
/// an external, operator-run notifier relay a human decision without holding a
/// credential. A wrong or already-used token is rejected without distinguishing
/// the cases.
pub async fn decide_with_token(
    State(state): State<PhylaxState>,
    Path(id): Path<i64>,
    Json(body): Json<DecideTokenRequest>,
) -> Result<impl IntoResponse, AppError> {
    let approval = approval::get_approval(&state.inner.db, id).await?;
    let phone_device_id = body.phone.as_ref().map(|phone| phone.device_id.as_str());
    let is_phone_decision = body.phone.is_some();
    let result = match (body.decision.as_deref(), body.phone.as_ref()) {
        (None, Some(phone)) => {
            approval::decide_with_phone(&state.inner.db, id, &body.token, phone).await
        }
        (Some("approved"), None) => {
            approval::decide_with_token(&state.inner.db, id, &body.token, true).await
        }
        (Some("denied"), None) => {
            approval::decide_with_token(&state.inner.db, id, &body.token, false).await
        }
        _ => Err(CredError::InvalidInput(
            "provide exactly one valid decision form".into(),
        )),
    };
    match result {
        Ok(status) => {
            let audit_action = if is_phone_decision {
                actions::PHONE_APPROVAL_DECIDED
            } else if status == ApprovalStatus::Approved {
                actions::APPROVAL_GRANTED
            } else {
                actions::APPROVAL_DENIED
            };
            let _ = log_phylax_audit(
                &state.inner.db,
                approval.user_id,
                Some(&approval.agent_name),
                phone_device_id,
                None,
                None,
                None,
                audit_action,
                &approval.category,
                &approval.secret_name,
                true,
                approval.correlation_id.as_deref(),
            )
            .await;

            let can_issue_operation_lease = !uses_direct_approval_status(&approval.resolve_mode)
                && approval::get_operation_digest(&state.inner.db, approval.id)
                    .await?
                    .is_some();
            if status == ApprovalStatus::Approved
                && approval.status == ApprovalStatus::Pending
                && can_issue_operation_lease
            {
                let issued_lease = lease::mint_lease(
                    &state.inner.db,
                    approval.user_id,
                    approval.id,
                    &approval.agent_name,
                    &approval.category,
                    &approval.secret_name,
                    approval.correlation_id.as_deref(),
                    DEFAULT_LEASE_TTL_SECS,
                )
                .await?;
                approval::set_approval_lease(&state.inner.db, approval.id, issued_lease.id).await?;
                let _ = log_phylax_audit(
                    &state.inner.db,
                    approval.user_id,
                    Some(&approval.agent_name),
                    phone_device_id,
                    None,
                    None,
                    None,
                    actions::LEASE_MINTED,
                    &approval.category,
                    &approval.secret_name,
                    true,
                    approval.correlation_id.as_deref(),
                )
                .await;
            }
            Ok(Json(json!({ "status": status as i32 })))
        }
        Err(_) => {
            if is_phone_decision {
                let _ = log_phylax_audit(
                    &state.inner.db,
                    approval.user_id,
                    Some(&approval.agent_name),
                    phone_device_id,
                    None,
                    None,
                    None,
                    actions::PHONE_APPROVAL_REJECTED,
                    &approval.category,
                    &approval.secret_name,
                    false,
                    approval.correlation_id.as_deref(),
                )
                .await;
            }
            Err(CredError::PermissionDenied("decision rejected".into()).into())
        }
    }
}
