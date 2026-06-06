//! M1 acceptance: the same principal feed, run under enforcement vs the
//! vulnerable baseline, produces opposite outcomes on the out-of-scope calls
//! while the legitimate in-scope work still completes.

use std::fs;
use std::path::PathBuf;
use uuid::Uuid;
use warden_agent::{AuthzMode, Orchestrator, StepDecision};
use warden_audit::{verify_chain, AuditEvent};
use warden_manifest::{ExecPolicy, FilesystemPolicy, NetworkPolicy, TaskManifest};
use warden_tools::{ToolCall, ToolOutput};

struct Fixture {
    repo_root: PathBuf,
    secret: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let repo_root = std::env::temp_dir().join(format!("warden-m1-repo-{}", Uuid::new_v4()));
        fs::create_dir_all(repo_root.join("src")).unwrap();
        fs::write(repo_root.join("in_scope.txt"), "hello").unwrap();

        // A secret OUTSIDE the repo root — the canary the injected agent tries
        // to read and exfiltrate.
        let secret = std::env::temp_dir().join(format!("warden-secret-{}.txt", Uuid::new_v4()));
        fs::write(&secret, "TOPSECRET").unwrap();

        Self { repo_root, secret }
    }

    fn manifest(&self) -> TaskManifest {
        TaskManifest {
            task_id: Uuid::new_v4(),
            repo_root: self.repo_root.clone(),
            ttl_seconds: 60,
            filesystem: FilesystemPolicy {
                readable_roots: vec![self.repo_root.clone()],
                writable_roots: vec![self.repo_root.join("src")],
            },
            exec: ExecPolicy {
                allowed_binaries: vec!["echo".to_string()],
            },
            network: NetworkPolicy::DenyAll,
        }
    }

    /// One scripted "principal" feed: a legitimate fix interleaved with an
    /// injection-driven exfil attempt. Byte-identical across both modes.
    fn principal_feed(&self) -> Vec<ToolCall> {
        vec![
            ToolCall::FsRead {
                path: self.repo_root.join("in_scope.txt"),
            },
            // injected: read the out-of-scope secret
            ToolCall::FsRead {
                path: self.secret.clone(),
            },
            ToolCall::FsWrite {
                path: self.repo_root.join("src/fix.txt"),
                contents: "patched".to_string(),
            },
            ToolCall::Exec {
                binary: "echo".to_string(),
                args: vec!["tests pass".to_string()],
            },
            // injected: exfiltrate over the network
            ToolCall::Network {
                host: "127.0.0.1".to_string(),
                port: 9,
                payload: "TOPSECRET".to_string(),
            },
        ]
    }
}

#[test]
fn enforced_denies_out_of_scope_while_legit_work_completes() {
    let fixture = Fixture::new();
    let mut orchestrator = Orchestrator::new(&fixture.manifest(), AuthzMode::Enforced).unwrap();
    let outcomes = orchestrator.run(fixture.principal_feed());

    // 0: in-scope read allowed, returns the real content.
    match &outcomes[0].decision {
        StepDecision::Allowed(ToolOutput::Read { content }) => assert_eq!(content, "hello"),
        other => panic!("expected in-scope read allowed, got {other:?}"),
    }
    // 1: out-of-scope secret read DENIED — the structural guarantee.
    assert!(
        matches!(outcomes[1].decision, StepDecision::Denied(_)),
        "out-of-scope read must be denied, got {:?}",
        outcomes[1].decision
    );
    // 2: in-scope write to the writable root still succeeds.
    assert!(matches!(
        outcomes[2].decision,
        StepDecision::Allowed(ToolOutput::Write { .. })
    ));
    // 3: allowlisted exec still runs.
    assert!(matches!(
        outcomes[3].decision,
        StepDecision::Allowed(ToolOutput::Exec { .. })
    ));
    // 4: network egress denied by policy — never even attempts to connect.
    assert!(matches!(outcomes[4].decision, StepDecision::Denied(_)));

    // The audit log is an intact hash chain naming the denied tool.
    verify_chain(orchestrator.audit_log()).unwrap();
    let denied_read = orchestrator.audit_log().iter().any(|entry| {
        matches!(&entry.event, AuditEvent::ToolDenied { tool_name, .. } if tool_name == "fs_read")
    });
    assert!(denied_read, "audit log must record the denied fs_read");
}

#[test]
fn bypassed_baseline_exfiltrates_the_secret() {
    let fixture = Fixture::new();
    let mut orchestrator = Orchestrator::new(&fixture.manifest(), AuthzMode::Bypassed).unwrap();
    let outcomes = orchestrator.run(fixture.principal_feed());

    // Under the vulnerable baseline, the out-of-scope secret read SUCCEEDS:
    // ambient authority is exactly the vulnerability the framework removes.
    match &outcomes[1].decision {
        StepDecision::Allowed(ToolOutput::Read { content }) => assert_eq!(content, "TOPSECRET"),
        other => panic!("baseline should leak the secret, got {other:?}"),
    }
}
