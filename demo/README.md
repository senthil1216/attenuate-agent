# Warden Demo Harness

This directory contains the runnable reference application that demonstrates Warden's core thesis:

> An untrusted principal can still ask for dangerous tool calls, but the runtime cannot widen the authority granted by the original trusted task manifest.

The demo is deliberately small and reproducible so that the *only* variable between "vulnerable" and "protected" runs is the `AUTHZ=on|off` toggle.

## Quick Start

```sh
# Full contrast (recommended)
make demo-contrast

# Or step-by-step
make demo-clean          # baseline, no injection
make demo-vuln           # injected + AUTHZ=off (leaks)
make demo-protected      # injected + AUTHZ=on (structurally denies malicious actions)
```

Artifacts are written to the current directory (or `demo/artifacts/` if you use the helper script).

See the root `Makefile` for all available targets.

## What the Contrast Does

1. **Setup** — Copies the on-disk fixture (`demo/fixtures/simple-bug/`) to `/tmp/warden-demo-fixture` and creates an out-of-scope secret canary.
2. **Runs the same principal feed** under two modes:
   - `AUTHZ=off` (deliberate vulnerable baseline — ambient authority).
   - `AUTHZ=on` (enforced — every call is attenuated to a fresh child capability, verified by PEP, decided by PDP).
3. **Captures**:
   - `clean.log`, `vuln.log`, `protected.log`
   - `sink.log` (exfil attempts only succeed in the vulnerable run)
   - Human-readable audit log with per-call attenuations and named denial reasons.

## Key Design Points Visible in the Demo

- **Per-call attenuation** — A new child capability is minted for every tool request, with a short TTL and a cryptographic binding to the exact arguments (tool name + blake3 hash + fresh nonce).
- **Architectural default-deny** — `pdp::decide` only returns `Allow` when an explicit `allows_*` predicate matches.
- **Audit evidence** — Only the protected run contains `ATTENUATED` entries and explicit `DENIED` lines with the failing caveat name.
- **Principal-independence** — The same sequence of tool calls (the "injected" principal feed) produces opposite security outcomes solely because of the enforcement toggle.

## Files

- `fixtures/simple-bug/` — Tiny Python package with a failing test + the `AGENT_NOTE.md` that contains the indirect injection.
- `examples/*.json` — Reusable manifest and call traces (clean + injected).
- `src/main.rs` — The `warden-demo` binary (setup, listener, contrast runner, pretty output).
- `run.sh` — Helper for one-command orchestration and bundling.

The `demo` crate is the home for the M3 showcase harness/fixture (on-disk examples, fixtures, contrast logic, and recording support). M1/M2 are in `agent`/`tools`; this crate wires them into a runnable pre-LLM demo.

## Recording Tips

The `make demo-asciinema` target (or direct asciinema) lets you record the AUTHZ=off|on contrast at the capability layer — before any LLM is wired (M1/M2). This de-risks the M3 narrative early by proving the enforcement story with the scripted principal feed from the injection note.

**Prerequisite:** `asciinema` must be installed (the Makefile target will give helpful instructions if missing).

```sh
# One-command recording of the full contrast (recommended)
make demo-asciinema

# Manual (if you have asciinema)
asciinema rec demo-contrast.cast --overwrite
make demo-contrast
# Ctrl-D to finish

# Also record baseline for comparison
asciinema rec demo-clean.cast --overwrite
make demo-clean
```

Play recordings with `asciinema play demo-contrast.cast`.

See also the root Makefile for the `demo-asciinema` target (records via the contrast subcommand, which exercises both modes with internal listener).

## Next (for the article)

See the "Immediate Next Actions" and "Publication Strategy" sections in the root `docs/NEXT_STEPS.md`.

`docs/NEXT_STEPS.md` is kept as the detailed living working document for next steps and planning. High-level phase summary/status lives in the root `README.md`.

Typical artifacts to include:
- Side-by-side trace diff (see `scripts/trace-diff.sh`)
- `sink.log` showing exfil only in the vulnerable run
- Audit excerpts with named `DENIED` reasons
- 30–60 second asciinema of `make demo-contrast`

## Repro Requirements

- Rust (see root `rust-toolchain.toml`)
- The `make` targets work on both macOS (development) and Linux (full containment claims).

The security claims in the demo are only fully enforceable on Linux (Landlock + seccomp). macOS is supported for development only.