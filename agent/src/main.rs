use anyhow::{Context, Result};
use warden_agent::{AuthzMode, Orchestrator, StepDecision};
use warden_manifest::TaskManifest;
use warden_tools::ToolCall;

/// Reference orchestrator CLI.
///
/// Usage:
///   AUTHZ=on|off warden-agent <manifest.json> <calls.json>
///
/// `manifest.json` is the trusted task manifest (operator-authored). `calls.json`
/// is a JSON array of tool calls standing in for an untrusted principal's
/// emitted tool requests — the scripted-adversary feed for milestone M1.
fn main() -> Result<()> {
    let mode = std::env::var("AUTHZ")
        .map(|value| AuthzMode::from_env_value(&value))
        .unwrap_or(AuthzMode::Enforced);

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "usage: AUTHZ=on|off {} <manifest.json> <calls.json>",
            args[0]
        );
        std::process::exit(2);
    }

    let manifest: TaskManifest =
        serde_json::from_str(&std::fs::read_to_string(&args[1]).context("reading manifest")?)
            .context("parsing manifest json")?;
    let calls: Vec<ToolCall> =
        serde_json::from_str(&std::fs::read_to_string(&args[2]).context("reading calls")?)
            .context("parsing calls json")?;

    let mut orchestrator = Orchestrator::new(&manifest, mode)?;
    println!("AUTHZ = {:?}\n", orchestrator.mode());

    for outcome in orchestrator.run(calls) {
        let (tag, detail) = match &outcome.decision {
            StepDecision::Allowed(output) => ("ALLOW", format!("{output:?}")),
            StepDecision::Denied(reason) => ("DENY ", reason.clone()),
            StepDecision::Errored(reason) => ("ERROR", reason.clone()),
        };
        println!("[{tag}] {:8} {detail}", outcome.call.tool_name());
    }

    println!(
        "\n--- audit log ({} entries) ---",
        orchestrator.audit_log().len()
    );
    for entry in orchestrator.audit_log() {
        println!("{:?}", entry.event);
    }

    Ok(())
}
