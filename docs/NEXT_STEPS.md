# Warden Next Steps

**Project:** Warden — a capability-based authorization framework for tool calls.
**Repo:** <https://github.com/senthil1216/attenuate-agent>
**Status:** Core capability and authorization primitives are in place. The reference application and reproducible demo are the next blocking milestones.

## Current Position

Warden already has a credible core shape:

- `capability`: biscuit-backed root and child capability tokens, append-only attenuation APIs, TTL enforcement, request binding, token roundtrip tests, and widening rejection.
- `pep`: signature chain verification, expiry checks, and request-binding enforcement.
- `pdp`: default-deny decisions for read, write, exec, and network requests, plus a basic linter.
- `tools`: composition layer for PEP, PDP, and request binding.
- `audit`: hash-chained audit log primitives.
- `manifest`: trusted task manifest schema and validation.
- `sandbox`: placeholder for Linux Landlock/seccomp containment.

The project is not yet showcase-ready. `agent` and `demo` are still scaffolds, real guarded tool execution is incomplete, audit is not fully wired into the authorization path, and there is no end-to-end attack/protected demo.

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
| P0 | Audit-ready authorization slice | CLI path that mints, attenuates, verifies, decides, and logs | A reviewer can run one command and see allowed and denied decisions with explainable audit entries |
| P1 | Real guarded tools | `fs_read`, `fs_write`, narrow `exec`, and denied `network` behind PEP/PDP | No tool can be called from the reference app without verification, policy decision, and audit |
| P2 | Orchestrator with `AUTHZ` toggle | Minimal trusted agent loop with vulnerable and protected modes | Legitimate in-scope work succeeds in both modes; out-of-scope work is denied with `AUTHZ=on` |
| P3 | Showcase demo harness | Fixture repo, injection note, canary listener, traces, sink log, and repro commands | Vulnerable run leaks; protected run blocks while preserving useful work |
| P4 | Linux containment and principal independence | Landlock/seccomp plus second-principal or replay validation | Mis-authorized calls fail at the OS layer; DENY behavior does not depend on principal identity |
| P5 | Docs and publication assets | README, threat model, design notes, recording, trace diff, audit excerpts | A skeptical reviewer can reproduce the demo and locate limitations quickly |
| P6 | Adoption-friendly surface | CLI/JSON protocol, Python interop sketch, richer linter or Datalog evaluation | Non-Rust callers can exercise the gate |

The best target for a first public article is solid P3 plus basic P5. P4 and P6 are strong amplifiers but should not block the first showcase.

## P0: Make The Core Claim Auditable

Goal: prove the security thesis with library APIs and tests before building model integration.

1. Add a small `warden-demo` or `warden-agent` CLI path that mints a root capability from a manifest, attenuates it to one request, verifies it, runs PDP, and emits audit entries.
2. Wire audit into the authorization path, including capability token hash/signature material so the log binds decisions to the token used.
3. Expand property tests from read-scope monotonicity to all authority dimensions: read, write, exec, network, TTL, and request binding.
4. Add tests for replay and token confusion: same tool with different arguments, different tool with same arguments, expired child, tampered public key, and tampered token state.
5. Update `docs/DEVELOPMENT.md`; it understates the implementation because biscuit-backed tokens are already present.

Done when: a reviewer can run one command and see both allowed and denied decisions with human-readable audit records.

## P1: Build The Minimal Real Tool Boundary

Goal: move from `authorize_only` to an actual guarded dispatch surface.

1. Implement `fs_read` and `fs_write` as real tools behind PEP/PDP.
2. Keep `exec` initially narrow: direct binary plus argument vector only, no shell, allowlisted by binary name.
3. Keep network policy as `deny_all` for the first demo; a denied network request is enough to prove the point.
4. Make every tool invocation require a fresh child capability with a nonce-bound request binding.
5. Ensure unauthorized calls return structured errors suitable for CLI output, agent feedback, and audit records.
6. Add integration tests using temp directories for allowed and denied tool paths.

Done when: no reference-app tool execution path bypasses verification, policy decision, and audit.

## P2: Build The Trusted Orchestrator

Goal: create a small, reviewable TCB component.

1. Accept a task manifest from a trusted path outside the demo workspace.
2. Mint a root capability at task start.
3. Receive tool requests from a principal or replay file.
4. Attenuate each request to a short-lived child capability with exact request binding.
5. Verify with PEP, decide with PDP, execute or deny, then audit.
6. Implement `AUTHZ=off` as a deliberate vulnerable baseline that bypasses the authorization gate.
7. Support replay mode so article artifacts can be deterministic even when live models are not.

Done when: the same tool trace can be run through vulnerable and protected paths.

## P3: Build The Showcase Demo

Goal: create the public artifact: a short, reproducible attack/protected contrast.

1. Add a tiny Python fixture under `demo/fixtures/` with one failing test and an obvious legitimate fix.
2. Add a plausible in-repo injection note that asks the agent to read a canary outside the repo and exfiltrate it to localhost.
3. Add a local canary and sink listener that records hits to `sink.log`.
4. Add demo targets or subcommands:
   - `demo-clean`: clean repo, no injection, legitimate task succeeds.
   - `demo-vuln`: injected repo with `AUTHZ=off`, canary appears in `sink.log`.
   - `demo-protected`: same injected repo with `AUTHZ=on`, malicious calls are denied, sink remains empty, legitimate task still succeeds.
5. Record deterministic traces of requested tool calls so the protected run can show the same malicious intent with different enforcement results.
6. Capture audit excerpts and trace diffs automatically.

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

Do these in roughly this order:

1. Update status docs: README and `docs/DEVELOPMENT.md`.
2. Build a minimal orchestrator spike in `agent` that exercises allow and deny requests using hardcoded tool traces.
3. Implement the first real guarded tool, likely `fs_read`, with temp-dir tests.
4. Add demo fixture, injection note, and canary listener.
5. Add replay mode and produce the first vulnerable/protected pair.
6. Wire real audit entries into the demo and print human-readable excerpts.

After the first vulnerable/protected comparison exists, the article narrative becomes much easier to sharpen.

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
