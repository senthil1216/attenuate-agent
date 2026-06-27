//! Runnable demonstration of the serde-boundary privilege-escalation bug
//! closed in PR #22.
//!
//! Run: `cargo run -p warden-pep --example serde_boundary_attack`
//!
//! The story in 30 seconds:
//!
//! 1. A root capability is minted and legitimately attenuated to read ONLY
//!    `/repo/pkg` — no write, no exec.
//! 2. The child is serialized to JSON (as it would be crossing a process
//!    boundary) and the plaintext `permissions` struct is widened back toward
//!    the root's authority — while the signed `token` bytes are left untouched.
//! 3. The OLD check (`verify_signature`) passes, because the signature was
//!    never over the struct. This is the vulnerability.
//! 4. The FIXED check (`verify` via the PEP) catches the divergence and
//!    rejects — because it recovers authority FROM the signed token, then
//!    cross-checks the struct.

use std::collections::BTreeSet;
use std::path::PathBuf;
use warden_capability::{AttenuationRequest, ChildCapability, NetworkPolicy, RootCapability};
use warden_manifest::{ExecPolicy, FilesystemPolicy, TaskManifest};
use warden_pep::{verify, VerificationError};

fn main() {
    let now = chrono::Utc::now();

    // ── 1. Mint a root and attenuate it to read ONLY /repo/pkg ──────────
    let manifest = TaskManifest {
        task_id: uuid::Uuid::nil(),
        repo_root: PathBuf::from("/repo"),
        ttl_seconds: 60,
        filesystem: FilesystemPolicy {
            readable_roots: vec![PathBuf::from("/repo")],
            writable_roots: vec![PathBuf::from("/repo/src")],
        },
        exec: ExecPolicy {
            allowed_binaries: vec!["python".to_string()],
        },
        network: NetworkPolicy::DenyAll,
    };
    let root = RootCapability::mint(&manifest, now).unwrap();
    let child = root
        .attenuate(
            AttenuationRequest {
                readable_roots: [PathBuf::from("/repo/pkg")].into_iter().collect(),
                writable_roots: BTreeSet::new(),
                exec_binaries: BTreeSet::new(),
                network: NetworkPolicy::DenyAll,
                ttl_seconds: 30,
                request_binding: None,
            },
            now,
        )
        .unwrap();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  STEP 1 — Legitimate attenuation                            ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!("  Root authority:  read /repo, write /repo/src, exec {{python}}");
    println!("  Child attenuated: read /repo/pkg ONLY (no write, no exec)");
    println!();

    // ── 2. Tamper: widen the plaintext struct, leave the signed token ───
    let mut json = serde_json::to_value(&child).unwrap();
    json["permissions"]["readable_roots"] = serde_json::json!(["/repo"]);
    json["permissions"]["writable_roots"] = serde_json::json!(["/repo/src"]);
    json["permissions"]["exec_binaries"] = serde_json::json!(["python"]);
    let tampered: ChildCapability = serde_json::from_value(json).unwrap();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  STEP 2 — Attacker widens the plaintext struct              ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!("  Token bytes:      UNTOUCHED (the signed blob is intact)");
    println!("  Struct widened:   read /repo, write /repo/src, exec {{python}}");
    println!("  → The struct now claims MORE authority than the token grants.");
    println!();

    // ── 3. The OLD check: signature only — passes on the tampered cap ──
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  STEP 3 — OLD check: verify_signature() only                 ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    match tampered.verify_signature() {
        Ok(()) => {
            println!("  ✓ Signature VERIFIES — the token bytes are authentic.");
            println!();
            println!("  ⚠️  But the struct field was widened! A downstream PDP reading");
            println!("     capability.permissions() would see widened authority and");
            println!("     authorize read/write/exec that was never granted.");
            println!();
            println!("     → THE SIGNATURE VERIFIED, THE AUTHORITY WIDENED ANYWAY.");
        }
        Err(e) => {
            println!("  ✗ Signature check failed: {e}");
        }
    }
    println!();

    // ── 4. The FIXED check: verify() recovers state from the token ─────
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  STEP 4 — FIXED check: verify() via the PEP                  ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    match verify(tampered, now, None) {
        Err(VerificationError::StateTampered) => {
            println!("  ✗ REJECTED — VerificationError::StateTampered");
            println!();
            println!("  The PEP decoded the authoritative state FROM the signed token");
            println!("  and found it disagrees with the plaintext struct. The widening");
            println!("  was caught — even though the signature itself is valid.");
        }
        other => {
            println!("  Unexpected result: {other:?}");
        }
    }
    println!();

    // ── 5. Contrast: the honest capability passes both checks ──────────
    let honest_child = root
        .attenuate(
            AttenuationRequest {
                readable_roots: [PathBuf::from("/repo/pkg")].into_iter().collect(),
                writable_roots: BTreeSet::new(),
                exec_binaries: BTreeSet::new(),
                network: NetworkPolicy::DenyAll,
                ttl_seconds: 30,
                request_binding: None,
            },
            now,
        )
        .unwrap();
    let verified = verify(honest_child, now, None).unwrap();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  STEP 5 — Honest capability (no tampering)                   ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!("  ✓ verify() passes — struct agrees with token.");
    println!("  ✓ PDP sees the token-derived (authoritative) state:");
    println!(
        "     allows_read(\"/repo/pkg/file\")  = {}",
        verified.permissions().allows_read("/repo/pkg/file")
    );
    println!(
        "     allows_read(\"/repo/other\")     = {}",
        verified.permissions().allows_read("/repo/other")
    );
    println!(
        "     allows_write(\"/repo/src/x\")    = {}",
        verified.permissions().allows_write("/repo/src/x")
    );
    println!();
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  SUMMARY                                                     ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!("  • The signature covers the TOKEN, not the struct next to it.");
    println!("  • verify_signature() alone cannot catch struct tampering.");
    println!("  • verify() recovers authority from the signed token and");
    println!("    cross-checks the struct — catching the divergence.");
    println!();
    println!("  Lesson: decide from what you signed, not from what's convenient.");
}
