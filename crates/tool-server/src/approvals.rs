//! Human approval queue for `autonomy: approval` tools.
//!
//! A call that policy flags `ApprovalRequired` is parked here instead of
//! being dropped. `POST /approvals/{id}/approve` re-runs the policy engine via
//! [`PolicyEngine::evaluate_approved`] — approval satisfies the autonomy gate
//! only, so the kill switch, args schema, protected assets and blast radius
//! checks still apply — then executes the stored call. The kill-switch state is
//! re-read at decision time (see [`decide_approved`]): approvals can arrive
//! while no `/invoke` traffic is flowing, which is exactly what happens after
//! the switch is engaged. `reject` records the human's refusal. Every decision
//! is audited with the approver as actor.
//!
//! Pending approvals live in memory: a restart forgets them, which fails
//! closed (a forgotten approval never executes). Persist to Postgres if you
//! need approvals to survive restarts.

use std::sync::Arc;

use agent_protocol::tool::{Decision, DecisionKind, ToolCall, ToolResult};
use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tracing::{error, info};
use uuid::Uuid;

use crate::AppState;

/// How long an approval stays actionable.
const EXPIRY: Duration = Duration::hours(24);

/// Lifecycle of an approval record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Waiting on a human.
    Pending,
    /// A human approved the call and it executed successfully.
    Approved,
    /// A human approved the call but execution failed; `result.error` says why.
    ExecutionFailed,
    /// A human refused the call.
    Rejected,
    /// Not decided within [`EXPIRY`].
    Expired,
}

/// One parked call awaiting a human decision.
#[derive(Debug, Clone, Serialize)]
pub struct Approval {
    /// Approval id, returned on the original `POST /invoke`.
    pub id: Uuid,
    /// The call that was parked.
    pub call: ToolCall,
    /// Why policy required approval.
    pub reason: String,
    /// Current lifecycle state.
    pub status: Status,
    /// When the call was parked.
    pub created_at: DateTime<Utc>,
    /// When the decision was made.
    pub decided_at: Option<DateTime<Utc>>,
    /// Who decided.
    pub decided_by: Option<String>,
    /// Execution result (approve only).
    pub result: Option<ToolResult>,
}

/// In-memory approval queue.
pub struct Store {
    items: DashMap<Uuid, Approval>,
}

impl Store {
    /// Empty queue.
    pub fn new() -> Self {
        Self {
            items: DashMap::new(),
        }
    }

    /// Parks `call` and returns its approval id.
    pub fn insert(&self, call: &ToolCall, reason: &str) -> Uuid {
        let id = Uuid::new_v4();
        self.items.insert(
            id,
            Approval {
                id,
                call: call.clone(),
                reason: reason.to_string(),
                status: Status::Pending,
                created_at: Utc::now(),
                decided_at: None,
                decided_by: None,
                result: None,
            },
        );
        id
    }

    /// One record, expired-on-read when stale.
    pub fn get(&self, id: &Uuid) -> Option<Approval> {
        let mut rec = self.items.get_mut(id)?;
        expire(&mut rec);
        Some(rec.clone())
    }

    /// Records, newest first, optionally filtered by status.
    pub fn list(&self, status: Option<Status>) -> Vec<Approval> {
        let mut out: Vec<Approval> = self
            .items
            .iter_mut()
            .map(|mut r| {
                expire(&mut r);
                r.clone()
            })
            .filter(|a| status.map(|s| a.status == s).unwrap_or(true))
            .collect();
        out.sort_by_key(|a| std::cmp::Reverse(a.created_at));
        out
    }

    /// Atomically moves a pending record to `status`. Fails when the record
    /// is absent, already decided, or past [`EXPIRY`] — that check is the
    /// double-execution guard.
    pub fn settle(&self, id: &Uuid, status: Status, by: &str) -> Result<Approval, SettleError> {
        let mut rec = self.items.get_mut(id).ok_or(SettleError::NotFound)?;
        expire(&mut rec);
        if rec.status != Status::Pending {
            return Err(SettleError::AlreadyDecided(rec.status));
        }
        rec.status = status;
        rec.decided_at = Some(Utc::now());
        rec.decided_by = Some(by.to_string());
        Ok(rec.clone())
    }

    /// Records that an approved call failed to execute, so `approved` always
    /// means "approved and succeeded" and failures stay visible in the state.
    pub fn mark_failed(&self, id: &Uuid) -> Result<Approval, SettleError> {
        let mut rec = self.items.get_mut(id).ok_or(SettleError::NotFound)?;
        if rec.status != Status::Approved {
            return Err(SettleError::AlreadyDecided(rec.status));
        }
        rec.status = Status::ExecutionFailed;
        Ok(rec.clone())
    }

    /// Attaches the execution result to a decided record.
    pub fn attach_result(&self, id: &Uuid, result: ToolResult) {
        if let Some(mut rec) = self.items.get_mut(id) {
            rec.result = Some(result);
        }
    }
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

/// Marks a pending record expired once [`EXPIRY`] has passed.
fn expire(rec: &mut Approval) {
    if rec.status == Status::Pending && Utc::now() - rec.created_at > EXPIRY {
        rec.status = Status::Expired;
    }
}

/// Why a settle failed.
#[derive(Debug, PartialEq, Eq)]
pub enum SettleError {
    /// No record with that id.
    NotFound,
    /// Already approved, rejected or expired.
    AlreadyDecided(Status),
}

/// Stable wire spelling for an approval status.
fn status_label(status: Status) -> &'static str {
    match status {
        Status::Pending => "pending",
        Status::Approved => "approved",
        Status::ExecutionFailed => "execution_failed",
        Status::Rejected => "rejected",
        Status::Expired => "expired",
    }
}

/// Query params for `GET /approvals`.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Filter by status (`pending`, `approved`, `rejected`, `expired`).
    status: Option<Status>,
}

/// Separation-of-duty gate for approve/reject: the decider must hold the
/// `approver` role and must not be the actor that requested the call. Runs
/// before [`Store::settle`] so a failed check leaves the record pending.
fn check_decider(
    approvals: &Store,
    id: &Uuid,
    actor: &http_limits::auth::Actor,
) -> Result<(), http_limits::error::ApiError> {
    if actor.role != "approver" {
        return Err(http_limits::error::ApiError::forbidden(
            "approver role required",
        ));
    }
    if let Some(rec) = approvals.get(id) {
        if rec.call.actor == actor.name {
            return Err(http_limits::error::ApiError::forbidden(
                "cannot decide your own request",
            ));
        }
    }
    Ok(())
}

/// `GET /approvals` — queue contents, newest first.
pub async fn list(
    State(s): State<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> Json<Vec<Approval>> {
    Json(s.approvals.list(q.status))
}

/// Body for approve/reject. The deciding identity comes from the
/// authenticated [`http_limits::auth::Actor`], never from the body.
#[derive(Debug, Deserialize)]
pub struct DecideBody {
    /// Optional note (reject reason).
    #[serde(default)]
    reason: Option<String>,
}

/// Approve/reject response: the record plus the fresh policy decision and
/// execution result (both absent on reject).
#[derive(Debug, Serialize)]
pub struct Outcome {
    /// The settled record.
    approval: Approval,
    /// Decision from re-evaluating the stored call (approve only).
    #[serde(skip_serializing_if = "Option::is_none")]
    decision: Option<Decision>,
    /// Execution result (approve only).
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<ToolResult>,
}

/// Re-evaluates an approved call with the **live** kill-switch state.
///
/// `/invoke` refreshes the cached `EvalCtx` flag on every call, but approvals
/// are decided precisely when `/invoke` traffic has stopped (the agents halt as
/// soon as the switch is engaged). Without this refresh a call parked before
/// the switch was pulled could still be approved and executed while the gate
/// denies everything else. Every other verdict input (schema, protected
/// assets, blast radius) is unchanged: approval only satisfies autonomy.
async fn decide_approved(s: &Arc<AppState>, call: &ToolCall) -> Decision {
    let mut ctx = s.eval_ctx.lock().await;
    ctx.refresh_kill_switch();
    s.engine.evaluate_approved(call, &mut ctx)
}

/// `POST /approvals/{id}/approve` — re-check policy, then execute.
pub async fn approve(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    axum::extract::Extension(actor): axum::extract::Extension<http_limits::auth::Actor>,
    _body: Option<Json<DecideBody>>,
) -> Result<Json<Outcome>, http_limits::error::ApiError> {
    check_decider(&s.approvals, &id, &actor)?;
    let by = actor.name;

    let settled = s
        .approvals
        .settle(&id, Status::Approved, &by)
        .map_err(|e| match e {
            SettleError::NotFound => {
                http_limits::error::ApiError::not_found(format!("approval not found: {id}"))
            }
            SettleError::AlreadyDecided(st) => http_limits::error::ApiError::conflict(format!(
                "approval {id} already decided: {}",
                status_label(st)
            )),
        })?;
    let call = settled.call.clone();

    let decision = decide_approved(&s, &call).await;

    let result = match &decision.kind {
        DecisionKind::Allow => crate::claim_and_execute(&s, &call).await,
        _ => ToolResult {
            call_id: call.id,
            ok: false,
            output: serde_json::Value::Null,
            error: Some(format!("denied after approval: {}", decision.reason)),
            dry_run: false,
        },
    };
    s.approvals.attach_result(&id, result.clone());
    if !result.ok {
        if let Err(e) = s.approvals.mark_failed(&id) {
            tracing::error!(approval = %id, error = ?e, "could not record execution failure");
        }
    }

    if let Some(writer) = &s.audit {
        if let Err(e) = writer
            .append(
                &by,
                &call.tool,
                &call.args,
                decision.kind,
                &format!("approved by {by}: {}", decision.reason),
                call.correlation_id,
            )
            .await
        {
            error!(error = %e, "audit append failed");
        }
    }
    info!(approval = %id, tool = %call.tool, approver = %by, "approval executed");

    Ok(Json(Outcome {
        approval: s.approvals.get(&id).unwrap_or(settled),
        decision: Some(decision),
        result: Some(result),
    }))
}

/// `POST /approvals/{id}/reject` — record the refusal, never execute.
pub async fn reject(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    axum::extract::Extension(actor): axum::extract::Extension<http_limits::auth::Actor>,
    body: Option<Json<DecideBody>>,
) -> Result<Json<Outcome>, http_limits::error::ApiError> {
    check_decider(&s.approvals, &id, &actor)?;
    let by = actor.name;
    let note = body.as_ref().and_then(|Json(b)| b.reason.clone());

    let settled = s
        .approvals
        .settle(&id, Status::Rejected, &by)
        .map_err(|e| match e {
            SettleError::NotFound => {
                http_limits::error::ApiError::not_found(format!("approval not found: {id}"))
            }
            SettleError::AlreadyDecided(st) => http_limits::error::ApiError::conflict(format!(
                "approval {id} already decided: {}",
                status_label(st)
            )),
        })?;
    let call = settled.call.clone();

    if let Some(writer) = &s.audit {
        let reason = match &note {
            Some(n) => format!("rejected by {by}: {n}"),
            None => format!("rejected by {by}"),
        };
        if let Err(e) = writer
            .append(
                &by,
                &call.tool,
                &call.args,
                DecisionKind::Deny,
                &reason,
                call.correlation_id,
            )
            .await
        {
            error!(error = %e, "audit append failed");
        }
    }
    info!(approval = %id, tool = %call.tool, approver = %by, "approval rejected");

    Ok(Json(Outcome {
        approval: settled,
        decision: None,
        result: None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use serde_json::json;

    fn call() -> ToolCall {
        ToolCall {
            id: Uuid::new_v4(),
            tool: "misp.sighting.add".to_string(),
            args: json!({"value": "203.0.113.9"}),
            actor: "response-agent".to_string(),
            idempotency_key: String::new(),
            correlation_id: Uuid::new_v4(),
        }
    }

    #[test]
    fn insert_parks_pending_and_lists_newest_first() {
        let store = Store::new();
        let a = store.insert(&call(), "needs approval");
        let b = store.insert(&call(), "needs approval");
        let all = store.list(None);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].id, b, "newest first");
        assert!(all.iter().all(|r| r.status == Status::Pending));
        assert_eq!(store.list(Some(Status::Pending)).len(), 2);
        assert_eq!(store.list(Some(Status::Approved)).len(), 0);
        assert!(store.get(&a).is_some());
    }

    #[test]
    fn settle_is_single_shot() {
        let store = Store::new();
        let id = store.insert(&call(), "needs approval");
        let ok = store.settle(&id, Status::Approved, "alice").unwrap();
        assert_eq!(ok.status, Status::Approved);
        assert_eq!(ok.decided_by.as_deref(), Some("alice"));
        assert_eq!(
            store.settle(&id, Status::Approved, "bob").unwrap_err(),
            SettleError::AlreadyDecided(Status::Approved)
        );
        assert_eq!(
            store
                .settle(&Uuid::new_v4(), Status::Rejected, "bob")
                .unwrap_err(),
            SettleError::NotFound
        );
    }

    #[test]
    fn reject_then_approve_is_conflict() {
        let store = Store::new();
        let id = store.insert(&call(), "needs approval");
        store.settle(&id, Status::Rejected, "alice").unwrap();
        assert_eq!(
            store.settle(&id, Status::Approved, "bob").unwrap_err(),
            SettleError::AlreadyDecided(Status::Rejected)
        );
    }

    fn actor(name: &str, role: &str) -> http_limits::auth::Actor {
        http_limits::auth::Actor {
            name: name.to_string(),
            role: role.to_string(),
        }
    }

    #[test]
    fn non_approver_cannot_decide() {
        let store = Store::new();
        let id = store.insert(&call(), "needs approval");
        let err = check_decider(&store, &id, &actor("alice", "operator")).unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert_eq!(store.get(&id).unwrap().status, Status::Pending);
    }

    #[test]
    fn requester_cannot_self_approve() {
        let store = Store::new();
        let id = store.insert(&call(), "needs approval");
        // call() requests as "response-agent".
        let err = check_decider(&store, &id, &actor("response-agent", "approver")).unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert_eq!(store.get(&id).unwrap().status, Status::Pending);
    }

    #[test]
    fn approver_other_than_requester_passes() {
        let store = Store::new();
        let id = store.insert(&call(), "needs approval");
        assert!(check_decider(&store, &id, &actor("alice", "approver")).is_ok());
    }

    #[test]
    fn stale_pending_records_expire() {
        let store = Store::new();
        let id = store.insert(&call(), "needs approval");
        {
            let mut rec = store.items.get_mut(&id).unwrap();
            rec.created_at = Utc::now() - EXPIRY - Duration::minutes(1);
        }
        assert_eq!(store.get(&id).unwrap().status, Status::Expired);
        assert_eq!(
            store.settle(&id, Status::Approved, "alice").unwrap_err(),
            SettleError::AlreadyDecided(Status::Expired)
        );
    }

    #[test]
    fn result_attaches_to_decided_record() {
        let store = Store::new();
        let id = store.insert(&call(), "needs approval");
        store.settle(&id, Status::Approved, "alice").unwrap();
        let res = ToolResult {
            call_id: Uuid::new_v4(),
            ok: true,
            output: json!({"saved": true}),
            error: None,
            dry_run: false,
        };
        store.attach_result(&id, res);
        assert!(store.get(&id).unwrap().result.unwrap().ok);
    }
}

#[cfg(test)]
mod state_tests {
    use super::*;
    use serde_json::json;

    fn call() -> ToolCall {
        ToolCall {
            id: Uuid::new_v4(),
            tool: "misp.sighting.add".to_string(),
            args: json!({"value": "203.0.113.9"}),
            actor: "response-agent".to_string(),
            idempotency_key: String::new(),
            correlation_id: Uuid::new_v4(),
        }
    }

    /// `approved` means approved *and* executed; a failed execution moves the
    /// record to its own state instead of masquerading as success.
    #[test]
    fn failed_execution_has_its_own_state() {
        let store = Store::new();
        let id = store.insert(&call(), "needs approval");
        store.settle(&id, Status::Approved, "alice").unwrap();
        let rec = store.mark_failed(&id).unwrap();
        assert_eq!(rec.status, Status::ExecutionFailed);
        assert_eq!(status_label(rec.status), "execution_failed");
    }

    #[test]
    fn only_approved_records_can_fail() {
        let store = Store::new();
        let id = store.insert(&call(), "needs approval");
        assert_eq!(
            store.mark_failed(&id).unwrap_err(),
            SettleError::AlreadyDecided(Status::Pending)
        );
        assert_eq!(
            store.mark_failed(&Uuid::new_v4()).unwrap_err(),
            SettleError::NotFound
        );
    }

    #[test]
    fn rejected_records_never_become_failures() {
        let store = Store::new();
        let id = store.insert(&call(), "needs approval");
        store.settle(&id, Status::Rejected, "alice").unwrap();
        assert_eq!(
            store.mark_failed(&id).unwrap_err(),
            SettleError::AlreadyDecided(Status::Rejected)
        );
    }
}

/// Approval decisions must observe the **live** kill switch: a call parked
/// while the switch was off is denied if the operator engages it before the
/// approval is decided.
#[cfg(test)]
mod kill_switch_tests {
    use super::*;
    use axum::extract::Extension;
    use policy_engine::{EvalCtx, PolicyEngine};
    use serde_json::json;
    use std::path::Path as FsPath;
    use tokio::sync::Mutex;

    /// The kill switch is process-global, so tests that engage it must not run
    /// concurrently with each other.
    static KILL_ENV_LOCK: Mutex<()> = Mutex::const_new(());

    fn policies_dir() -> std::path::PathBuf {
        FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../policies")
            .canonicalize()
            .expect("policies dir")
    }

    fn state() -> Arc<AppState> {
        let engine = PolicyEngine::load(&policies_dir()).expect("load policies");
        Arc::new(AppState {
            engine,
            registry: crate::executors::build_registry(&connectors::ConnectorConfig::from_env()),
            audit: None,
            idem: crate::idempotency::Store::mem(),
            approvals: Store::new(),
            eval_ctx: Mutex::new(EvalCtx::new()),
        })
    }

    fn parked_exec() -> ToolCall {
        ToolCall {
            id: Uuid::new_v4(),
            tool: "exec.sandbox".to_string(),
            args: json!({"command": "echo", "args": ["hi"]}),
            actor: "response-agent".to_string(),
            idempotency_key: String::new(),
            correlation_id: Uuid::new_v4(),
        }
    }

    fn approver() -> http_limits::auth::Actor {
        http_limits::auth::Actor {
            name: "alice".to_string(),
            role: "approver".to_string(),
        }
    }

    /// Clears the kill-switch inputs so each test starts from a known state.
    fn clear_kill_env() {
        for var in [
            "ARES_KILL_SWITCH",
            "ARES_KILL_FILE",
            "ARES_CONTROL_DIR",
            "POLICIES_DIR",
        ] {
            std::env::remove_var(var);
        }
    }

    #[tokio::test]
    async fn parked_call_is_denied_while_kill_switch_engaged() {
        let _guard = KILL_ENV_LOCK.lock().await;
        clear_kill_env();
        let s = state();
        let call = parked_exec();
        let id = s.approvals.insert(&call, "requires approval");

        // Engage through the same predicate the shipped control plane writes:
        // a non-empty `kill` file in the policies/control directory.
        let dir = std::env::temp_dir().join(format!("ares-approval-kill-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("kill"), "engaged\n").unwrap();
        std::env::set_var("POLICIES_DIR", &dir);

        let out = approve(State(s.clone()), Path(id), Extension(approver()), None)
            .await
            .expect("approval handler");
        std::env::remove_var("POLICIES_DIR");
        std::fs::remove_dir_all(&dir).ok();

        let decision = out.decision.as_ref().expect("decision");
        assert!(
            matches!(decision.kind, DecisionKind::Deny),
            "parked call must not execute during a kill switch: {decision:?}"
        );
        assert!(
            decision.reason.contains("kill switch"),
            "{}",
            decision.reason
        );
        assert_eq!(out.approval.status, Status::ExecutionFailed);
        assert!(out.result.as_ref().map(|r| !r.ok).unwrap_or(false));
    }

    #[tokio::test]
    async fn parked_call_executes_when_kill_switch_is_off() {
        let _guard = KILL_ENV_LOCK.lock().await;
        clear_kill_env();
        let s = state();
        let call = ToolCall {
            id: Uuid::new_v4(),
            tool: "misp.sighting.add".to_string(),
            args: json!({"value": "203.0.113.9"}),
            actor: "response-agent".to_string(),
            idempotency_key: String::new(),
            correlation_id: Uuid::new_v4(),
        };
        let id = s.approvals.insert(&call, "requires approval");

        let out = approve(State(s.clone()), Path(id), Extension(approver()), None)
            .await
            .expect("approval handler");

        let decision = out.decision.as_ref().expect("decision");
        assert!(
            matches!(decision.kind, DecisionKind::Allow),
            "approval must still execute when the switch is off: {decision:?}"
        );
        assert_eq!(out.approval.status, Status::Approved);
    }
}
