use serde::{Deserialize, Serialize};
use std::path::Path;
use warden_capability::PermissionSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolRequest {
    Read { path: String },
    Write { path: String },
    Exec { binary: String },
    Network,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny { reason: String },
}

pub fn decide(permissions: &PermissionSet, request: &ToolRequest) -> Decision {
    match request {
        ToolRequest::Read { path } if permissions.allows_read(Path::new(path)) => Decision::Allow,
        ToolRequest::Write { path } if permissions.allows_write(Path::new(path)) => Decision::Allow,
        ToolRequest::Exec { binary } if permissions.allows_exec(binary) => Decision::Allow,
        ToolRequest::Network => match permissions.network() {
            warden_capability::NetworkPolicy::DenyAll => Decision::Deny {
                reason: "network policy denies all egress".to_string(),
            },
            _ => Decision::Deny {
                reason: "network policy is not explicitly allowed".to_string(),
            },
        },
        ToolRequest::Read { .. } => Decision::Deny {
            reason: "read path is outside capability scope".to_string(),
        },
        ToolRequest::Write { .. } => Decision::Deny {
            reason: "write path is outside capability scope".to_string(),
        },
        ToolRequest::Exec { .. } => Decision::Deny {
            reason: "binary is outside capability exec allowlist".to_string(),
        },
    }
}
