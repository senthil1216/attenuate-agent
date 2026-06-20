use serde::{Deserialize, Serialize};
use std::io::Write as _;
use std::path::PathBuf;
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
    #[error("tool execution io error: {0}")]
    Io(#[from] std::io::Error),
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
    match decide(verified.permissions(), &request) {
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

/// A concrete tool invocation requested by the (untrusted) principal.
///
/// This is the *execution* view: it carries the parameters needed to actually
/// perform the action. Its `to_request()` projection is the *authorization*
/// view consumed by the PEP/PDP — the policy decision never needs the payload,
/// only the shape of the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolCall {
    FsRead {
        path: PathBuf,
    },
    FsWrite {
        path: PathBuf,
        contents: String,
    },
    Exec {
        binary: String,
        args: Vec<String>,
    },
    Network {
        host: String,
        port: u16,
        payload: String,
    },
}

impl ToolCall {
    /// Project the execution intent down to the authorization request the
    /// PDP reasons about.
    pub fn to_request(&self) -> ToolRequest {
        match self {
            ToolCall::FsRead { path } => ToolRequest::Read {
                path: path.display().to_string(),
            },
            ToolCall::FsWrite { path, .. } => ToolRequest::Write {
                path: path.display().to_string(),
            },
            ToolCall::Exec { binary, .. } => ToolRequest::Exec {
                binary: binary.clone(),
            },
            ToolCall::Network { .. } => ToolRequest::Network,
        }
    }

    pub fn tool_name(&self) -> &'static str {
        match self {
            ToolCall::FsRead { .. } => "fs_read",
            ToolCall::FsWrite { .. } => "fs_write",
            ToolCall::Exec { .. } => "exec",
            ToolCall::Network { .. } => "network",
        }
    }
}

/// The result of actually executing a tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolOutput {
    Read {
        content: String,
    },
    Write {
        bytes_written: usize,
    },
    Exec {
        status: Option<i32>,
        stdout: String,
        stderr: String,
    },
    Network {
        bytes_sent: usize,
    },
}

/// Perform the side effect with NO authorization check.
///
/// This is the ambient-authority path used by the deliberately vulnerable
/// `AUTHZ=off` baseline. It is intentionally not reachable when enforcement is
/// on — `dispatch` is the only authorized entry point.
pub fn execute(call: &ToolCall) -> Result<ToolOutput, ToolError> {
    match call {
        ToolCall::FsRead { path } => Ok(ToolOutput::Read {
            content: std::fs::read_to_string(path)?,
        }),
        ToolCall::FsWrite { path, contents } => {
            std::fs::write(path, contents)?;
            Ok(ToolOutput::Write {
                bytes_written: contents.len(),
            })
        }
        ToolCall::Exec { binary, args } => {
            let output = std::process::Command::new(binary).args(args).output()?;
            Ok(ToolOutput::Exec {
                status: output.status.code(),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            })
        }
        ToolCall::Network {
            host,
            port,
            payload,
        } => {
            let mut stream = std::net::TcpStream::connect((host.as_str(), *port))?;
            stream.write_all(payload.as_bytes())?;
            Ok(ToolOutput::Network {
                bytes_sent: payload.len(),
            })
        }
    }
}

/// The single authorized tool entry point: verify the capability at the PEP,
/// decide at the PDP, and only then perform the side effect. A denial returns
/// before any side effect occurs.
pub fn dispatch(
    capability: ChildCapability,
    call: &ToolCall,
    nonce: Option<Uuid>,
) -> Result<ToolOutput, ToolError> {
    authorize_only(capability, call.to_request(), nonce)?;
    execute(call)
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
