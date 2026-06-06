//! Reference orchestrator (Phase 3, milestone M1).
//!
//! Trusted code, driven by an untrusted principal. The orchestrator mints a
//! root capability from the trusted task manifest, then for every tool call the
//! principal emits it attenuates a single-use, short-TTL, request-bound child
//! and runs it through the PEP/PDP before any side effect. Every mint,
//! attenuation, and decision is recorded in the hash-chained audit log.
//!
//! The `AUTHZ` toggle selects between [`AuthzMode::Enforced`] (the framework)
//! and [`AuthzMode::Bypassed`] (the deliberately vulnerable ambient-authority
//! baseline). The principal's intent is identical across both modes; the only
//! variable is whether enforcement runs.

use uuid::Uuid;
use warden_audit::{chain_entry, AuditEntry, AuditError, AuditEvent};
use warden_capability::{AttenuationRequest, CapabilityError, RootCapability};
use warden_manifest::TaskManifest;
use warden_tools::{dispatch, execute, request_binding_for, ToolCall, ToolError, ToolOutput};

/// How long each per-call child capability lives. Seconds-wide by design.
const CHILD_TTL_SECONDS: u64 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzMode {
    /// The framework: every tool call is authorized against a capability.
    Enforced,
    /// The vulnerable baseline: ambient authority, no capability check.
    Bypassed,
}

impl AuthzMode {
    /// Parse an `AUTHZ` environment value. Anything that is not an explicit
    /// "off" switch enforces — fail closed.
    pub fn from_env_value(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" | "0" | "false" | "no" | "bypass" => AuthzMode::Bypassed,
            _ => AuthzMode::Enforced,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OrchestratorError {
    #[error("failed to mint root capability: {0}")]
    Mint(#[from] CapabilityError),
    #[error("failed to write audit entry: {0}")]
    Audit(#[from] AuditError),
}

/// The outcome of a single tool call as seen by the orchestrator.
#[derive(Debug)]
pub struct StepOutcome {
    pub call: ToolCall,
    pub decision: StepDecision,
}

#[derive(Debug)]
pub enum StepDecision {
    /// Authorized and executed; carries the tool's output.
    Allowed(ToolOutput),
    /// Structurally refused — either no capability could be minted for it or
    /// the PDP denied it. Carries a human-readable reason.
    Denied(String),
    /// Authorized (or bypassed) but the side effect itself failed (e.g. a
    /// refused network connection). Distinct from a policy denial.
    Errored(String),
}

pub struct Orchestrator {
    mode: AuthzMode,
    task_id: Uuid,
    root: RootCapability,
    audit_log: Vec<AuditEntry>,
    previous_hash: [u8; 32],
}

impl Orchestrator {
    pub fn new(manifest: &TaskManifest, mode: AuthzMode) -> Result<Self, OrchestratorError> {
        let now = chrono::Utc::now();
        let root = RootCapability::mint(manifest, now)?;
        let mut orchestrator = Self {
            mode,
            task_id: manifest.task_id,
            root,
            audit_log: Vec::new(),
            previous_hash: [0u8; 32],
        };
        orchestrator.record(AuditEvent::RootMinted {
            task_id: manifest.task_id,
        })?;
        Ok(orchestrator)
    }

    pub fn mode(&self) -> AuthzMode {
        self.mode
    }

    pub fn audit_log(&self) -> &[AuditEntry] {
        &self.audit_log
    }

    /// Run a whole sequence of principal-emitted tool calls in order.
    pub fn run(&mut self, calls: Vec<ToolCall>) -> Vec<StepOutcome> {
        calls.into_iter().map(|call| self.step(call)).collect()
    }

    pub fn step(&mut self, call: ToolCall) -> StepOutcome {
        match self.mode {
            AuthzMode::Enforced => self.step_enforced(call),
            AuthzMode::Bypassed => self.step_bypassed(call),
        }
    }

    /// Vulnerable baseline: execute with ambient authority, no capability.
    fn step_bypassed(&mut self, call: ToolCall) -> StepOutcome {
        match execute(&call) {
            Ok(output) => {
                self.record_lossy(AuditEvent::ToolAllowed {
                    tool_name: call.tool_name().to_string(),
                });
                StepOutcome {
                    call,
                    decision: StepDecision::Allowed(output),
                }
            }
            Err(error) => {
                self.record_lossy(AuditEvent::ToolDenied {
                    tool_name: call.tool_name().to_string(),
                    reason: format!("execution error: {error}"),
                });
                StepOutcome {
                    call,
                    decision: StepDecision::Errored(error.to_string()),
                }
            }
        }
    }

    /// Enforced path: attenuate to a single-use child bound to this exact call,
    /// then verify (PEP) + decide (PDP) before any side effect.
    fn step_enforced(&mut self, call: ToolCall) -> StepOutcome {
        let now = chrono::Utc::now();
        let nonce = Uuid::new_v4();
        let request = call.to_request();

        let binding = match request_binding_for(&request, nonce) {
            Ok(binding) => binding,
            Err(error) => return self.deny(call, format!("request binding failed: {error}")),
        };

        // Child carries the root's scope (narrowing is "<=", equal is allowed),
        // narrowed in time (seconds TTL) and bound to this one invocation.
        let permissions = self.root.permissions();
        let attenuation = AttenuationRequest {
            readable_roots: permissions.readable_roots().clone(),
            writable_roots: permissions.writable_roots().clone(),
            exec_binaries: permissions.exec_binaries().clone(),
            network: permissions.network(),
            ttl_seconds: CHILD_TTL_SECONDS,
            request_binding: Some(binding),
        };

        let child = match self.root.attenuate(attenuation, now) {
            Ok(child) => child,
            // An attenuation that cannot be minted is itself a structural deny.
            Err(error) => return self.deny(call, format!("capability not mintable: {error}")),
        };
        self.record_lossy(AuditEvent::CapabilityAttenuated {
            task_id: self.task_id,
        });

        match dispatch(child, &call, Some(nonce)) {
            Ok(output) => {
                self.record_lossy(AuditEvent::ToolAllowed {
                    tool_name: call.tool_name().to_string(),
                });
                StepOutcome {
                    call,
                    decision: StepDecision::Allowed(output),
                }
            }
            Err(ToolError::Denied(reason)) => self.deny(call, reason),
            Err(ToolError::Verification(error)) => self.deny(call, error.to_string()),
            Err(ToolError::Serialize(error)) => {
                self.deny(call, format!("argument serialization failed: {error}"))
            }
            Err(ToolError::Io(error)) => {
                // Authorized, but the side effect failed.
                self.record_lossy(AuditEvent::ToolDenied {
                    tool_name: call.tool_name().to_string(),
                    reason: format!("execution error: {error}"),
                });
                StepOutcome {
                    call,
                    decision: StepDecision::Errored(error.to_string()),
                }
            }
        }
    }

    fn deny(&mut self, call: ToolCall, reason: String) -> StepOutcome {
        self.record_lossy(AuditEvent::ToolDenied {
            tool_name: call.tool_name().to_string(),
            reason: reason.clone(),
        });
        StepOutcome {
            call,
            decision: StepDecision::Denied(reason),
        }
    }

    fn record(&mut self, event: AuditEvent) -> Result<(), OrchestratorError> {
        let entry = chain_entry(self.previous_hash, chrono::Utc::now(), event)?;
        self.previous_hash = entry.entry_hash;
        self.audit_log.push(entry);
        Ok(())
    }

    /// Audit chaining is infallible in practice (`chain_entry` only hashes); a
    /// failure here must not change a tool decision, so we keep the decision and
    /// drop the entry rather than unwinding an already-made allow/deny.
    fn record_lossy(&mut self, event: AuditEvent) {
        let _ = self.record(event);
    }
}
