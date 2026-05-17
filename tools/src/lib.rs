use uuid::Uuid;
use warden_capability::{hash_tool_arguments, ChildCapability, RequestBinding};
use warden_pdp::{decide, Decision, ToolRequest};
use warden_pep::{verify, VerificationError};

#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error("authorization failed: {0}")]
    Verification(#[from] VerificationError),
    #[error("failed to serialize tool request arguments: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("tool request denied: {0}")]
    Denied(String),
}

pub fn authorize_only(
    capability: ChildCapability,
    request: ToolRequest,
    nonce: Option<Uuid>,
) -> Result<(), ToolError> {
    let actual_binding = nonce
        .map(|nonce| request_binding_for(&request, nonce))
        .transpose()?;
    let verified = verify(capability, chrono::Utc::now(), actual_binding.as_ref())?;
    match decide(verified.capability().permissions(), &request) {
        Decision::Allow => Ok(()),
        Decision::Deny { reason } => Err(ToolError::Denied(reason)),
    }
}

pub fn request_binding_for(
    request: &ToolRequest,
    nonce: Uuid,
) -> Result<RequestBinding, serde_json::Error> {
    let tool_name = tool_name(request).to_string();
    let canonical_arguments = serde_json::to_vec(request)?;
    let argument_hash = hash_tool_arguments(&tool_name, &canonical_arguments, nonce);

    Ok(RequestBinding {
        tool_name,
        argument_hash,
        nonce,
    })
}

fn tool_name(request: &ToolRequest) -> &'static str {
    match request {
        ToolRequest::Read { .. } => "fs_read",
        ToolRequest::Write { .. } => "fs_write",
        ToolRequest::Exec { .. } => "exec",
        ToolRequest::Network => "network",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    use warden_capability::{AttenuationRequest, RootCapability};
    use warden_manifest::{ExecPolicy, FilesystemPolicy, NetworkPolicy, TaskManifest};

    fn bound_read_capability(request: &ToolRequest, nonce: Uuid) -> ChildCapability {
        let now = chrono::Utc::now();
        let manifest = TaskManifest {
            task_id: Uuid::nil(),
            repo_root: PathBuf::from("/repo"),
            ttl_seconds: 60,
            filesystem: FilesystemPolicy {
                readable_roots: vec![PathBuf::from("/repo")],
                writable_roots: vec![],
            },
            exec: ExecPolicy {
                allowed_binaries: vec![],
            },
            network: NetworkPolicy::DenyAll,
        };
        let root = RootCapability::mint(&manifest, now).unwrap();
        let binding = request_binding_for(request, nonce).unwrap();

        root.attenuate(
            AttenuationRequest {
                readable_roots: BTreeSet::from([PathBuf::from("/repo")]),
                writable_roots: BTreeSet::new(),
                exec_binaries: BTreeSet::new(),
                network: NetworkPolicy::DenyAll,
                ttl_seconds: 30,
                request_binding: Some(binding),
            },
            now,
        )
        .unwrap()
    }

    #[test]
    fn authorizes_matching_request_binding() {
        let request = ToolRequest::Read {
            path: "/repo/src/lib.rs".to_string(),
        };
        let nonce = Uuid::new_v4();
        let capability = bound_read_capability(&request, nonce);

        assert!(authorize_only(capability, request, Some(nonce)).is_ok());
    }

    #[test]
    fn rejects_replayed_request_binding_with_different_nonce() {
        let request = ToolRequest::Read {
            path: "/repo/src/lib.rs".to_string(),
        };
        let capability = bound_read_capability(&request, Uuid::new_v4());

        assert!(matches!(
            authorize_only(capability, request, Some(Uuid::new_v4())),
            Err(ToolError::Verification(
                VerificationError::RequestBindingMismatch
            ))
        ));
    }
}
