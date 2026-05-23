use serde::{Deserialize, Serialize};
use std::path::Path;
use warden_capability::PermissionSet;

pub mod linter;

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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::path::PathBuf;
    use uuid::Uuid;
    use warden_capability::{NetworkPolicy, RootCapability};
    use warden_manifest::{ExecPolicy, FilesystemPolicy, TaskManifest};

    fn root_manifest() -> TaskManifest {
        TaskManifest {
            task_id: Uuid::nil(),
            repo_root: PathBuf::from("/repo"),
            ttl_seconds: 60,
            filesystem: FilesystemPolicy {
                readable_roots: vec![PathBuf::from("/repo")],
                writable_roots: vec![PathBuf::from("/repo/src")],
            },
            exec: ExecPolicy {
                allowed_binaries: vec!["python".to_string(), "pytest".to_string()],
            },
            network: NetworkPolicy::DenyAll,
        }
    }

    fn permissions() -> PermissionSet {
        let now = chrono::Utc::now();
        RootCapability::mint(&root_manifest(), now)
            .unwrap()
            .permissions()
            .clone()
    }

    fn is_allow(d: &Decision) -> bool {
        matches!(d, Decision::Allow)
    }

    fn is_deny(d: &Decision) -> bool {
        matches!(d, Decision::Deny { .. })
    }

    proptest! {
        #[test]
        fn read_decision_matches_allows_read(suffix in "[a-z]{1,12}") {
            let perms = permissions();
            let path = format!("/repo/{suffix}");
            let decision = decide(&perms, &ToolRequest::Read { path: path.clone() });
            prop_assert_eq!(is_allow(&decision), perms.allows_read(&path));
        }

        #[test]
        fn read_outside_roots_is_denied(suffix in "[a-z]{1,12}") {
            let perms = permissions();
            let path = format!("/outside/{suffix}");
            let decision = decide(&perms, &ToolRequest::Read { path });
            prop_assert!(is_deny(&decision));
        }

        #[test]
        fn write_decision_matches_allows_write(suffix in "[a-z]{1,12}") {
            let perms = permissions();
            let path = format!("/repo/src/{suffix}");
            let decision = decide(&perms, &ToolRequest::Write { path: path.clone() });
            prop_assert_eq!(is_allow(&decision), perms.allows_write(&path));
        }

        #[test]
        fn write_outside_roots_is_denied(suffix in "[a-z]{1,12}") {
            let perms = permissions();
            let path = format!("/repo/{suffix}");
            let decision = decide(&perms, &ToolRequest::Write { path });
            prop_assert!(is_deny(&decision));
        }

        #[test]
        fn exec_decision_matches_allows_exec(binary in "[a-z]{1,16}") {
            let perms = permissions();
            let decision = decide(&perms, &ToolRequest::Exec { binary: binary.clone() });
            prop_assert_eq!(is_allow(&decision), perms.allows_exec(&binary));
        }

        #[test]
        fn exec_outside_allowlist_is_denied(binary in "(curl|wget|nc|bash|sh|rm|dd|ssh)[0-9]*") {
            let perms = permissions();
            let decision = decide(&perms, &ToolRequest::Exec { binary });
            prop_assert!(is_deny(&decision));
        }

        #[test]
        fn network_request_is_always_denied(_dummy in any::<u8>()) {
            let perms = permissions();
            let decision = decide(&perms, &ToolRequest::Network);
            prop_assert!(is_deny(&decision));
        }
    }
}
