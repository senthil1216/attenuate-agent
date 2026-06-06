# Warden Next Steps

**Project:** Warden — a capability-based authorization framework for tool calls.
**Repo:** <https://github.com/senthil1216/attenuate-agent>
**Status:** Core capability, PEP/PDP, tools dispatch, and the trusted `Orchestrator` (with `AUTHZ=on|off`, per-call attenuation, request binding, and hash-chained audit) are implemented and tested. The reference application scaffolding has been replaced by real logic + acceptance tests that demonstrate the structural guarantee. The next blocking milestone is turning this into a user-facing, reproducible **showcase demo harness** (P3) with on-disk fixtures, injection notes, canary listener, and nice artifacts.

## Current Position

Warden already has a credible core shape:

- `capability`: biscuit-backed root and child capability tokens, append-only attenuation APIs, TTL enforcement, request binding, token roundtrip tests, and widening rejection.
- `pep`: signature chain verification, expiry checks, and request-binding enforcement.
- `pdp`: default-deny decisions for read, write, exec, and network requests, plus a basic linter.
- `tools`: composition layer for PEP, PDP, and request binding.
- `audit`: hash-chained audit log primitives.
- `manifest`: trusted task manifest schema and validation.
- `sandbox`: placeholder for Linux Landlock/seccomp containment.

P3 is complete and verified (see "Immediate Next Actions" below and the user's successful `make demo-*` runs). The core engine + orchestrator + guarded tools + acceptance tests prove the thesis. The runnable demo harness (on-disk fixtures, injection note, canary, contrast with artifacts, human-readable audit) is working and producing the exact evidence needed for the first post. 

Current focus: polish the artifacts (trace diff, summary, recording) + P5 documentation (threat model first for credibility).

The core thesis remains strong:

> An untrusted principal can still ask for dangerous tool calls, but the runtime cannot widen the authority granted by the original trusted task.

## Strategic Direction

Build toward a focused demo, not a broad agent platform. The strongest story is a small, reproducible coding-agent scenario where:

- the same injected input produces the same malicious tool intent;
- `AUTHZ=off` shows the ambient-authority failure;
- `AUTHZ=on` denies the out-of-scope action while preserving the legitimate task;
- the audit log explains exactly why the action was denied.

This gives the project a clean public narrative: capability attenuation as a structural answer to prompt-injection-induced privilege escalation.

## Prioritized Roadmap

| Priority | Milestone | Description | Success Criteria |
| --- | --- | --- | --- |
| P0 | Audit-ready authorization slice | CLI path that mints, attenuates, verifies, decides, and logs | **Largely complete** — `warden-agent` binary + `Orchestrator` + full audit chaining exist. Enforcement tests exercise the flow. |
| P1 | Real guarded tools | `fs_read`, `fs_write`, narrow `exec`, and denied `network` behind PEP/PDP | **Largely complete** — `ToolCall` + `dispatch()` (authorized) + `execute()` (bypassed) with real side effects. |
| P2 | Orchestrator with `AUTHZ` toggle | Minimal trusted agent loop with vulnerable and protected modes | **Largely complete** — full `Orchestrator` in `agent/src/lib.rs` with `Enforced` vs `Bypassed`, per-call attenuation + request binding, audit. `agent/tests/enforcement.rs` is the M1 contrast test. |
| P3 | Showcase demo harness | Fixture repo, injection note, canary listener, traces, sink log, and repro commands | **Complete & verified** (via your `make demo-contrast` + `make demo-clean` runs; on-disk fixtures, artifacts, and human-readable output produced). |
| P4 | Linux containment and principal independence | Landlock/seccomp plus second-principal or replay validation | Mis-authorized calls fail at the OS layer; DENY behavior does not depend on principal identity |
| P5 | Docs and publication assets | README, threat model, design notes, recording, trace diff, audit excerpts | A skeptical reviewer can reproduce the demo and locate limitations quickly |
| P6 | Adoption-friendly surface | CLI/JSON protocol, Python interop sketch, richer linter or Datalog evaluation | Non-Rust callers can exercise the gate |

The best target for a first public article is solid P3 plus basic P5. P4 and P6 are strong amplifiers but should not block the first showcase.

## P0: Make The Core Claim Auditable

**Status: Largely complete (M1 engine exists).**

Goal: prove the security thesis with library APIs and tests before building model integration.

1. Add a small `warden-demo` or `warden-agent` CLI path that mints a root capability from a manifest, attenuates it to one request, verifies it, runs PDP, and emits audit entries. → Done (see `agent/src/main.rs` + `Orchestrator`).
2. Wire audit into the authorization path, including capability token hash/signature material so the log binds decisions to the token used. → Done (full `record` + `chain_entry` usage in the orchestrator, plus `verify_chain` in tests).
3. Expand property tests from read-scope monotonicity to all authority dimensions... → Core capability tests were already strong; the new `agent/tests/enforcement.rs` adds end-to-end contrast + chain verification.
4. Add tests for replay and token confusion... → The enforcement test exercises the binding + deny paths.
5. Update `docs/DEVELOPMENT.md`...

Done when: a reviewer can run one command and see both allowed and denied decisions with human-readable audit records. → Achieved in the unit test + CLI. The remaining work is making this a polished, on-disk demo experience (P3).

## P1: Build The Minimal Real Tool Boundary

**Status: Largely complete.**

Goal: move from `authorize_only` to an actual guarded dispatch surface.

1-3. Real `fs_read`/`fs_write`/`exec`/`network` behind PEP/PDP → Done. `tools/src/lib.rs` now has `ToolCall` (execution view), `to_request()` (auth view), `dispatch()` (the guarded entry point), and `execute()` (the bypassed ambient path). All four tool kinds have real side effects.
4. Fresh child capability with nonce-bound request binding on every call → Done in the orchestrator.
5-6. Structured errors + integration tests → The `enforcement.rs` test does exactly this with temp fixtures and exercises both allow and deny paths.

Done when: no reference-app tool execution path bypasses verification, policy decision, and audit. → Achieved.

## P2: Build The Trusted Orchestrator

**Status: Largely complete (core engine shipped).**

Goal: create a small, reviewable TCB component.

1-7. All items → Implemented in `agent/src/lib.rs`:
   - `Orchestrator::new(manifest, mode)` mints the root and records `RootMinted`.
   - `step()` / `run()` take `Vec<ToolCall>` (from principal or replay file).
   - Enforced path does fresh attenuation with `CHILD_TTL_SECONDS` + request binding, then `dispatch()`.
   - Full `AuthzMode::Enforced` vs `Bypassed`.
   - Every decision (allow/deny/error) + attenuation is audited with hash chaining.
   - `agent/tests/enforcement.rs` runs the **exact same** `principal_feed()` under both modes and asserts the contrast (out-of-scope denied under enforcement, leaks under bypass; legit work succeeds in both; chain verifies).

Done when: the same tool trace can be run through vulnerable and protected paths. → Achieved (and tested). The remaining work is packaging this as a nice demo (P3) with persistent fixtures and a canary.

## P3: Build The Showcase Demo

**Status: Started — fixture skeleton + example traces in place.**

Goal: create the public artifact: a short, reproducible attack/protected contrast.

1. Add a tiny Python fixture under `demo/fixtures/` with one failing test and an obvious legitimate fix. → **Done** (see `demo/fixtures/simple-bug/` with `buggy.py`, `test_buggy.py`, and `AGENT_NOTE.md`).
2. Add a plausible in-repo injection note... → **Done** (`AGENT_NOTE.md` contains the diagnostic + exfil request).
3. Add a local canary and sink listener... → **In progress / basic version done**. `cargo run -p warden-demo -- listener` starts a simple sink on 127.0.0.1:9999 that appends payloads to `sink.log`. The example injection note targets this port.
4. Add demo targets or subcommands... → Foundation exists via `warden-agent <manifest> <calls.json>` + `AUTHZ=off|on`. We can wrap this in `demo` or a Makefile.
5. Record deterministic traces... → `demo/examples/injected-calls.json` is the replayable principal feed (extracted/adapted from the enforcement test).
6. Capture audit excerpts... → The `warden-agent` binary already prints the full audit log after a run.

Done when:

- clean run fixes the bug;
- injected `AUTHZ=off` run leaks the canary;
- injected `AUTHZ=on` run blocks the leak and still fixes the bug;
- audit output names the denied caveat and request context.

## P4: Add Linux Containment As Defense In Depth

Goal: make the architecture honest at the OS boundary.

1. Implement Landlock filesystem confinement for exec'd tools on Linux.
2. Add seccomp restrictions for network-denied runs.
3. Feature-gate containment with `linux-containment`.
4. Document macOS as development-only, with no containment guarantee.
5. Add a Linux CI or reproducible container path for containment tests.

Done when: a deliberately mis-authorized exec still fails at the OS boundary on Linux.

## P5: Documentation And Publication Assets

Goal: make the project reviewable and post-ready.

1. Update the README status line and phased table to reflect reality: core authorization primitives are in place; reference app is next.
2. Refresh `docs/DEVELOPMENT.md` with current commands and future demo targets.
3. Add or expand threat-model documentation: TCB, in-scope attacks, out-of-scope attacks, residual risks, child-token TTL window, and permitted-binary misuse.
4. Add design notes: why biscuit, why Rust-side attenuation validation, request-binding rationale, default-deny behavior, and audit-chain design.
5. Prepare artifacts:
   - 30-45 second terminal recording.
   - Side-by-side trace diff.
   - `sink.log` showing canary present in vulnerable mode and absent in protected mode.
   - Audit log excerpt with human-readable denial reason.
   - Architecture diagram from README.
   - One-command or few-command repro instructions.

Done when: a skeptical reviewer can reproduce the core result in fewer than five commands.

## P6: Adoption-Friendly Surface

Goal: show Warden as reusable framework infrastructure, not only a one-off demo.

1. Add a CLI/JSON protocol or thin Python-friendly surface.
2. Provide example manifest builder helpers.
3. Expand linter findings for broad exec allowlists, filesystem root access, world-writable roots, and surprising network policy.
4. Evaluate whether moving more PDP decisions into biscuit Datalog adds real clarity or security strength. If not, document the hybrid design explicitly.

Defer this until the demo is working.

## Immediate Next Actions

**Current reality (as of this update):** You have now successfully run both:

- `make demo-contrast` (full detailed output previously shared)
- `make demo-clean` (output shared in this message)

The separate `make demo-clean` run (using the Makefile target) is clean and correct:
- Uses `clean-calls.json` (only the three legitimate operations).
- All succeed under `AUTHZ=on`.
- Audit shows the expected pattern: `ROOT MINTED` + one `ATTENUATED` + `ALLOWED` per operation. No denials.

This matches the plan's "clean run succeeds with only in-scope operations" criterion perfectly.

Combined with the contrast run, you now have the complete set of reproducible artifacts covering the three required scenarios.

**P3 runnable demo harness is verified and complete.** Great work.

**Immediate Next Actions status (as of this session):**

1. **Inspect and archive your run artifacts**: ✅ Done. Logs archived to `demo/artifacts/` (clean.log, vuln.log, protected.log, sink.log) + `demo/artifacts/demo-results.md` (polished post-ready excerpt combining contrast + clean runs). Success criteria confirmed via log inspection (denials + sink exfil only in vulnerable path; attenuations + named DENYs only under enforcement; legitimate work preserved).

2. **Create a side-by-side trace diff or summary script**: ✅ Done. `scripts/trace-diff.sh` created. It generates a clean markdown summary highlighting identical principal intent, divergent outcomes on injected actions (secret read + network), and audit differences.

3. **Update status docs**: ✅ Done.
   - README.md: Status banner updated to reflect P3 complete + demo harness; "Quick Demo" section added with make targets and link to artifacts.
   - `docs/DEVELOPMENT.md`: New "Demo harness" subsection documenting all make targets, direct cargo usage, and links to demo/README.md + artifacts.
   - This file: P3 marked complete in roadmap; this "Immediate Next Actions" section updated with status and "Completed in this session" note (see below).

4. **Start P5 publication assets** (parallel): ✅ Started / largely complete for first post.
   - `docs/THREAT_MODEL.md`: Solid first draft exists (TCB, in/out-of-scope, residual risks including TTL window + permitted-binary gap, how the structural guarantee works, relation to other mitigations).
   - `docs/DESIGN.md`: Created with notes on biscuit + Rust validation, request binding, architectural default-deny + linter, audit chain, sandbox as defense-in-depth, and explicit non-goals.
   - `demo/README.md`: Created with quick start, what the contrast does, key design points visible in the demo, files overview, recording tips, and links back to the plan.
   - Recording instructions: Added to `demo/README.md` (asciinema examples for contrast and individual scenarios).

5. **Polish for one-command repro**: ✅ Done.
   - `demo/run.sh` created: Handles contrast/clean/vuln/protected modes, background listener notes, bundles outputs to timestamped `demo/artifacts/<run>/`, optionally runs trace-diff.
   - All checks confirmed green (`cargo fmt --all -- --check`, `cargo clippy ... -D warnings`, `cargo test --workspace`).

6. Optional but high-value for the post:
   - Asciinema: Instructions + suggested commands added to `demo/README.md`. Ready to record `make demo-contrast`.
   - Enhance fixture with pytest: Not yet (kept minimal for now; the scripted calls already demonstrate the "fix" via the write + exec in clean/protected paths). Can be a quick follow-up if desired for the recording.

Once you have the logs + diff + basic docs updates, the article narrative is ready to write. The first post target remains "solid P3 + basic P5".

**These Immediate Next Actions are now largely complete.** The harness produces reproducible, article-grade artifacts with clear evidence of the structural guarantee. Next natural steps (from the plan): actual recording (asciinema of contrast), final article drafting using `demo/artifacts/demo-results.md` + `scripts/trace-diff.sh` output, and/or moving to P4 (Linux containment) or P6 (adoption surface) if desired.

**Next concrete command for you right now:**
```sh
ls -l *.log sink.log 2>/dev/null || echo "Check your current dir and /tmp for logs"
cat protected.log | head -30   # or use the KEY DIFFERENCES section from contrast output
```

After reviewing the artifacts, tell me which of 2–5 above you'd like to tackle first (e.g. "create the trace diff script" or "start THREAT_MODEL.md"), and I'll implement it.

## Publication Strategy

The article should read like a security engineering case study, not a product announcement.

Working title:

> Prompt Injection Is An Authorization Bug: Building A Capability Runtime For AI Tool Calls

Recommended structure:

1. The problem: agents inherit too much ambient authority.
2. The thesis: treat model output as an untrusted principal.
3. The design: trusted manifest, attenuable biscuit capabilities, PEP/PDP, request-bound child tokens, audit.
4. The demo: same injected intent, vulnerable mode leaks, protected mode denies.
5. The rigor: property tests, default-deny, audit chain, sandbox defense in depth.
6. The limitations: in-scope malicious actions, compromised runtime, child-token TTL window, allowed-binary misuse.
7. The takeaway: the model does not need to become trustworthy for the runtime to bound what it can reach.

Strong article angles:

- "Prompt Injection Is An Authorization Bug"
- "Capability-Based Authorization For The Age Of Agents"
- "Authority That Can Only Narrow: Lessons From Building Warden"

Innovation highlights to feature:

- Per-call, request-bound, short-lived child capabilities.
- Cryptographic binding to exact tool arguments plus nonce.
- Rust API design that makes widening non-expressible through the public attenuation path.
- Biscuit tokens for offline attenuation and verifiable capability chains.
- Architectural default-deny.
- Hash-chained audit records.
- Principal independence: the defense does not inspect or depend on the caller's cleverness.

## Risks And Mitigations

- Model non-determinism could weaken the "same output" story. Mitigation: prioritize replay mode and use live models only as secondary evidence.
- Scope creep could delay the demo. Mitigation: defer federation, dashboards, broad model support, macOS containment parity, and polished UI.
- One-command repro could become too complex. Mitigation: support both full demo and replay-only demo, with Linux/Docker path for containment.
- Linux-only containment may surprise macOS users. Mitigation: state it clearly in README, docs, and the article.
- Audit or token-chain bugs would undermine credibility. Mitigation: keep property tests, add tamper tests, and verify the chain as part of demo output.
- Permitted binaries can still do harmful in-scope work. Mitigation: name this as a limitation. Warden bounds which binaries run and which resources they can reach; it does not prove permitted binaries are semantically safe.

## Success Criteria

The plan succeeds when:

- clean demo run succeeds with only in-scope operations;
- injected vulnerable run performs the exfiltration and records a canary hit;
- injected protected run shows the same principal intent, denies out-of-scope calls, keeps the sink empty, and still completes the legitimate task;
- audit output clearly explains each denial;
- `cargo fmt --all -- --check`, `cargo clippy --locked --workspace --all-targets -- -D warnings`, and `cargo test --locked --workspace` stay green;
- README and docs clearly state what Warden does and does not defend.

## How To Maintain This Plan

Keep this file as the canonical tactical plan. The README should remain the high-level vision and quick-start entry point. Update this document after each major milestone, especially after the first working `demo-vuln` vs `demo-protected` pair with artifacts.

## References

- [README.md](../README.md)
- [Development](DEVELOPMENT.md)
- Crates: `capability`, `pep`, `pdp`, `audit`, `manifest`, `tools`, `sandbox`, `agent`, `demo`
