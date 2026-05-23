use std::path::Path;
use warden_capability::PermissionSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LintFinding {
    AlwaysAllowRead { root: String },
}

pub fn lint(permissions: &PermissionSet) -> Vec<LintFinding> {
    let mut findings = Vec::new();

    for root in permissions.readable_roots() {
        if root == Path::new("/") {
            findings.push(LintFinding::AlwaysAllowRead {
                root: root.display().to_string(),
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use uuid::Uuid;
    use warden_capability::{NetworkPolicy, RootCapability};
    use warden_manifest::{ExecPolicy, FilesystemPolicy, TaskManifest};

    fn manifest_with_readable_roots(roots: Vec<PathBuf>) -> TaskManifest {
        TaskManifest {
            task_id: Uuid::nil(),
            repo_root: roots.first().cloned().unwrap_or_else(|| PathBuf::from("/")),
            ttl_seconds: 60,
            filesystem: FilesystemPolicy {
                readable_roots: roots,
                writable_roots: vec![],
            },
            exec: ExecPolicy {
                allowed_binaries: vec![],
            },
            network: NetworkPolicy::DenyAll,
        }
    }

    #[test]
    fn flags_filesystem_root_as_always_allow_read() {
        let now = chrono::Utc::now();
        let manifest = manifest_with_readable_roots(vec![PathBuf::from("/")]);
        let root = RootCapability::mint(&manifest, now).unwrap();

        let findings = lint(root.permissions());
        assert_eq!(
            findings,
            vec![LintFinding::AlwaysAllowRead {
                root: "/".to_string()
            }]
        );
    }

    #[test]
    fn does_not_flag_scoped_readable_roots() {
        let now = chrono::Utc::now();
        let manifest = manifest_with_readable_roots(vec![PathBuf::from("/repo")]);
        let root = RootCapability::mint(&manifest, now).unwrap();

        assert!(lint(root.permissions()).is_empty());
    }
}
