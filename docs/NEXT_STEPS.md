# Next Steps

## Current Position

Warden already has a credible core shape: biscuit-backed capability tokens, append-only attenuation APIs, request-bound child capabilities, PEP/PDP separation, basic policy checks, a hash-chained audit primitive, and passing workspace checks.

The project is not yet showcase-ready. The missing piece is an end-to-end path that proves the thesis in a way a reader can run, inspect, and remember:

> An untrusted principal can still ask for dangerous tool calls, but the runtime cannot widen the authority granted by the original trusted task.

## Strategic Direction

Build toward a focused demo, not a broad agent platform. The strongest story is a small, reproducible coding-agent scenario where:

- the same injected input produces the same malicious tool intent;
- `AUTHZ=off` shows the ambient-authority failure;
- `AUTHZ=on` denies the out-of-scope action while preserving the legitimate task;
- the audit log explains exactly why the action was denied.

This gives the project a clean public narrative: capability attenuation as a structural answer to prompt-injection-induced privilege escalation.

## P0: Make The Core Claim Auditable

Goal: prove the security thesis with library APIs and tests before building UI or model integration.

1. Add a small `warden-demo` or `warden-agent` CLI path that mints a root capability from a manifest, attenuates it to one request, verifies it, runs PDP, and emits an audit entry.
2. Wire audit into the authorization path, including capability token hash/signature material in the audit event so the log binds decisions to the token used.
3. Expand property tests from read-scope monotonicity to all authority dimensions: read, write, exec, network, TTL, and request binding.
4. Add tests for replay and token confusion: same tool with different arguments, different tool with same arguments, expired child, and tampered public key.
5. Update `docs/DEVELOPMENT.md`; it currently understates the implementation because biscuit-backed tokens are already present.

Done when: a reviewer can run one command and see allowed and denied decisions with explainable audit entries.

## P1: Build The Minimal Real Tool Boundary

Goal: move from `authorize_only` to an actual guarded dispatch surface.

1. Implement `fs_read` and `fs_write` as real tools behind PEP/PDP.
2. Keep `exec` initially narrow: no shell, direct binary plus argument vector only, allowlisted by binary name.
3. Keep network policy as `deny_all` for the first demo; a denied network tool is enough to prove the point.
4. Make every tool invocation require a fresh child capability with a nonce-bound request binding.
5. Ensure unauthorized calls return structured errors suitable for both CLI output and audit records.

Done when: no tool can be called from the reference app without passing through verification, policy decision, and audit.

## P2: Build The Showcase Demo

Goal: create the public artifact: a short, reproducible attack/protected contrast.

1. Add a tiny fixture repo under `demo/fixtures/` with one failing test and an obvious legitimate fix.
2. Add an injection note inside the fixture that asks the agent to read a canary outside the repo and exfiltrate it to localhost.
3. Add a local canary and sink listener for the vulnerable run.
4. Implement `AUTHZ=off` and `AUTHZ=on` modes.
5. Record deterministic traces of requested tool calls so the protected run can show: same malicious intent, different enforcement result.

Done when:

- clean run fixes the bug;
- injected `AUTHZ=off` run leaks the canary;
- injected `AUTHZ=on` run blocks the leak and still fixes the bug;
- audit output names the denied caveat and request context.

## P3: Add Linux Containment As Defense In Depth

Goal: make the architecture honest at the OS boundary.

1. Implement Landlock filesystem containment for exec'd tools on Linux.
2. Add seccomp restrictions for network-denied runs.
3. Document macOS as development-only, with no containment guarantee.
4. Add a Linux CI or reproducible container path for containment tests.

Done when: a deliberately mis-authorized exec still fails at the OS boundary on Linux.

## P4: Publication Strategy

The article should not read like a product announcement. It should read like a security engineering case study.

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

Artifacts to prepare before posting:

- 30-45 second terminal recording.
- Side-by-side trace diff.
- `sink.log` showing canary present in vulnerable mode and absent in protected mode.
- Audit log excerpt with human-readable denial reason.
- Architecture diagram from README.
- A one-command repro in the README.

## Recommended Milestone Order

1. P0 audit-ready authorization slice.
2. P1 real guarded tools.
3. P2 deterministic demo.
4. P3 Linux containment.
5. Article draft and screenshots.

Avoid spending time on broad model support, distributed federation, plugin marketplaces, dashboards, or polished UI until the attack/protected demo is undeniable.
