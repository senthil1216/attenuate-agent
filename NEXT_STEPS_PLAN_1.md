# Warden Next Steps Plan (Plan 1)

**Project:** Warden — A capability-based authorization framework for tool calls (Rust + biscuit-auth)  
**Repo:** https://github.com/senthil1216/attenuate-agent  
**Date:** 2026-06 (post initial analysis)  
**Current Status:** Core security invariants (P0 gate) largely complete. Reference application (agent + demo) is the blocking milestone for validation and showcase.

---

## 1. Executive Summary of Current State

### What's Strongly Implemented
- **Capability core (`capability` crate)**: Full `RootCapability::mint` and `ChildCapability::attenuate` using biscuit-auth for tokens. Strict Rust-side `validate_attenuation` that rejects *any* widening of read/write/exec/TTL scopes. Type-level + API design enforces append-only narrowing.
- **Property-based tests + hardening**: Proptests prove read-scope widening is rejected and narrowing is accepted (including chained attenuation monotonicity). Additional tests for symlink escape, TTL overflow, unsafe paths, deterministic argument hashing + nonce binding for replay protection, and token roundtrips (encode/decode state + signature verification).
- **PEP (`pep`)**: Signature chain verification, expiry check, and request-binding enforcement (tool name + blake3(arg hash) + nonce).
- **PDP (`pdp`)**: `decide()` mapping `PermissionSet` to `ToolRequest` (Read/Write/Exec/Network) with architectural default-deny. Basic static linter (flags `/` root reads). Proptests cover all operation classes.
- **Supporting crates**:
  - `manifest`: Trusted task manifest schema + validation (TCB boundary).
  - `audit`: Hash-chained append-only log (`chain_entry` / `verify_chain`) binding previous hash + events (RootMinted, CapabilityAttenuated, ToolAllowed, ToolDenied).
  - `tools`: Glue layer (`authorize_only`, `request_binding_for`) that composes PEP + PDP + binding.
- **Quality**: All workspace tests pass, `cargo clippy -- -D warnings` clean, `cargo fmt` clean. CI enforces format + clippy + test + Linux feature check on every PR/push. Signed commits + strict branch protection on `main`.
- **Documentation**: Excellent high-level README with threat model, one-sentence hook, architecture diagrams, honest non-claims, and original phased plan.

### Current Gaps (the "Reference Application" is incomplete)
- `agent/` and `demo/` are scaffolds (`println!("... scaffold only")`).
- No real tool implementations (`fs_read`, `fs_write`, `exec`, `network`) behind the authorization gate.
- No orchestrator loop with `AUTHZ=off|on` toggle.
- No end-to-end demo harness: Python fixture, injection corpus, canary listener (`127.0.0.1:9999`), deterministic principal traces, `sink.log`, audit artifacts, or one-command repro targets.
- Sandbox is a stub (Linux Landlock + seccomp only; macOS is explicitly dev-only with no containment guarantee).
- PDP uses Rust-side `PermissionSet` matching today (biscuit facts are primarily for token serialization/attenuation). Richer Datalog policy evaluation at decision time and expanded linter rules are partial.
- Full documentation suite (THREAT_MODEL.md, DESIGN.md, FEDERATION.md) and Phase 7 polish missing.
- No visualization, second principal validation, or Python-friendly surface yet.

**Bottom line:** The structural thesis ("authority can only narrow; the widening operation does not exist") is already defended in the core crates and tests. The missing piece is wiring it into a compelling, reproducible **coding-agent reference application** that produces the evidence (traces, logs, denials) needed to prove the claim to others.

**Platform note:** Development and unit tests work on macOS. The final "still denied at the OS boundary" sandbox proof and full demo require Linux.

---

## 2. Goals for This Plan

1. **Complete the reference application** so the bundled coding-agent demo runs end-to-end and demonstrates the structural guarantee.
2. Produce high-quality, reproducible **artifacts** suitable for a strong technical LinkedIn/Medium post (side-by-side runs, audit excerpts, one-command repro, trace diffs).
3. Maintain (and improve) the existing rigor: property tests, default-deny architecture, honest limitations, no scope creep.
4. Position Warden as a reusable framework (not just one demo) while using the demo as the primary validation and storytelling vehicle.
5. Create a living plan that can be updated after each milestone.

**Non-goals for this plan:** Multi-tenant service, custom policy language, macOS containment parity, full SPIFFE federation (keep as one-page design sketch), defending a compromised runtime binary.

---

## 3. Prioritized Roadmap

| Priority | Milestone | Description | Key Deliverables | Success Criteria | Estimated Effort |
|----------|-----------|-------------|------------------|------------------|------------------|
| **P0 (Gate)** | Core capability invariants | Already largely achieved | Type-safe append-only attenuation, biscuit integration, proptests, request binding | Widening attempts are not expressible; proptests pass; tokens roundtrip correctly | Done (verify + minor polish) |
| **P1** | Tools + basic enforcement wiring | Real tool implementations + authorize path | `fs_read`/`fs_write`/`exec`/`network` behind `authorize_only` (or full PEP+PDP); audit integration points | A tool call is denied with a human-readable reason when out of scope | 2–4 days |
| **P2** | Orchestrator (agent) with AUTHZ toggle | Trusted orchestrator loop | `agent` crate that can run with `AUTHZ=off` (vulnerable baseline) vs `on` (per-call attenuate → PEP → PDP → tool) | Toggle works; legitimate in-scope work succeeds in both modes | 2–4 days |
| **P3** | Reference demo harness (hero artifact) | End-to-end reproducible scenario | Python fixture + failing test, injection "maintenance note", canary listener, deterministic/replay principal mode, injection corpus (4–5 variants), make/cargo targets or scripts (`demo-clean`, `demo-vuln`, `demo-protected`), outputs: traces, `sink.log`, audit log excerpts | Run 2 (vuln) shows canary exfil; Run 3 (protected) shows identical model output + structural DENYs + task still passes + sink empty | 4–7 days (biggest value item) |
| **P4** | Defense-in-depth + principal independence | Sandbox + cross-principal validation | Linux Landlock/seccomp wiring (or clear demo of it), run protected demo against a second unrelated principal (different model or simulator) with zero orchestrator changes | Mis-authorized call fails at OS layer (when enabled); identical DENY outcomes across principals | 3–5 days |
| **P5** | Polish, docs, and showcase assets | Make it reviewable and post-ready | Updated README status, THREAT_MODEL.md (or section), DESIGN.md notes, one-command repro instructions (Docker/Linux path preferred), asciinema or clean recording, side-by-side diff artifact, basic visualizer (TUI or small web view of audit + attenuation chain) optional but high-ROI | Skeptical reviewer can reproduce in <5 commands and locate limitations without searching | 3–5 days |
| **P6 (Stretch)** | Adoption-friendly surface | Make the framework usable beyond the demo | Python interop sketch (CLI/JSON protocol or thin PyO3 binding), example manifest builder, expanded linter rules, richer PDP Datalog usage if it adds clarity | Non-Rust callers can exercise the gate; policy review story is stronger | After P3–P5 |

**Overall target for a strong post:** Reach a solid P3 + basic P5 (reproducible demo + artifacts + honest docs). P4 and P6 are powerful amplifiers but not required for the first article.

---

## 4. Detailed Task Breakdown

### 4.1 Documentation & Planning (Start here)
- [ ] Update `README.md` status line and phased table to reflect reality (P0 largely complete; current focus = reference application + demo).
- [ ] Refresh `docs/DEVELOPMENT.md` (current milestone, exact commands, how to run the future demo targets).
- [ ] Create or expand `THREAT_MODEL.md` (or a prominent section) — explicit TCB, in-scope, out-of-scope, residual risks (child TTL window, permitted-binary misuse, etc.).
- [ ] Add `DESIGN.md` notes: why biscuit facts for state + Rust validation instead of full Datalog authorizer today; request-binding design rationale; why default-deny is structural.
- [ ] Add this `NEXT_STEPS_PLAN_1.md` (and future `NEXT_STEPS_PLAN_2.md` etc.) as living artifacts.

### 4.2 Tools Layer (`tools/` + related)
- [ ] Implement actual guarded tools (`fs_read`, `fs_write`, `exec`, `network`).
  - Each should call the authorization gate first, then perform the operation (respecting the already-attenuated scope).
  - Return structured errors on denial (for the orchestrator to feed back to the principal).
- [ ] Wire basic audit emission on allow/deny (and on attenuation).
- [ ] Add integration-style tests that exercise a full allow path end-to-end (using temp dirs where possible).

### 4.3 Agent / Orchestrator (`agent/`)
- [ ] Build a minimal trusted orchestrator.
  - Accept a task manifest (provenance outside workspace).
  - Mint root capability from manifest (trusted path only).
  - Loop: receive tool request from principal → attenuate to single-use child (with request binding + short TTL) → PEP verify + PDP decide → (optional sandbox) → execute tool (or structured denial) → feed result back → audit.
- [ ] Implement `AUTHZ=off` mode as a deliberate, clearly isolated vulnerable baseline (direct calls, no attenuation/PEP/PDP).
- [ ] Support both "live" principal (HTTP OpenAI/Anthropic-compatible) and "replay/deterministic" mode (feed exact prior tool-call JSONs). The latter is essential for reproducible article artifacts.
- [ ] Keep the orchestrator code small and reviewable — it is part of the TCB.

### 4.4 Demo Harness (`demo/`)
- [ ] Define a small, real, fixable Python fixture (e.g., a tiny package with a failing test that `pytest` can run and the agent can legitimately fix using only in-scope tools).
- [ ] Embed one or more indirect prompt injections as plausible in-repo content ("agent maintenance note", comment in source, etc.).
- [ ] Implement a tiny canary listener (binds to localhost, logs hits with timestamp + payload to `sink.log` or stdout).
- [ ] Create the injection corpus (4–5 phrasings) and a way to switch between clean repo vs injected repo.
- [ ] Add demo targets/scripts (Makefile, justfile, or Rust binary subcommands):
  - `demo-clean`: baseline success with no injection.
  - `demo-vuln`: AUTHZ=off on injected repo → expect legitimate work + exfil (canary appears).
  - `demo-protected`: AUTHZ=on on same injected repo → byte-identical principal output (when using replay), structural DENYs (named caveats in audit), sink empty, test still passes.
- [ ] Capture and surface artifacts automatically: trace diffs, audit excerpts (human-readable "ToolDenied: read path outside..." lines), `sink.log` presence/absence.
- [ ] Document exact one-command or few-command reproduction (include Linux/Docker path).

### 4.5 Sandbox & Containment (`sandbox/`)
- [ ] Implement real Landlock filesystem confinement (restrict to `repo_root` for exec'd processes) and seccomp syscall filtering (block network under `network: deny_all`).
- [ ] Feature-gate properly (`linux-containment`). Keep the "Disabled" error path clear.
- [ ] Add a test or demo mode that proves a deliberately over-authorized call still fails at the OS boundary.
- [ ] Document clearly: "Linux only for the enforced proof. macOS development has no containment guarantee."

### 4.6 PDP / Linter / Policy Evolution (`pdp/`)
- [ ] Expand the linter with additional findings (e.g., overly broad exec allowlists, world-writable roots, network allow when policy intends deny).
- [ ] Evaluate whether evolving the PDP decision to use biscuit's authorizer (Datalog over the facts already embedded in the token) adds meaningful strength or clarity. If yes, do it; if not, document the current hybrid design.
- [ ] Keep default-deny as a structural property (no shadowing possible).

### 4.7 Audit Integration
- [ ] Wire `audit` crate into the real flow (mint, every attenuation, every allow/deny decision).
- [ ] Ensure audit entries are emitted even on denial paths and contain enough context for a human reviewer (exact failing caveat + request).
- [ ] Add chain verification as part of demo outputs or a post-run check.

### 4.8 Showcase & Innovation Amplifiers (after P3 baseline)
- [ ] Principal-independence run (second model or a completely different caller simulator — e.g., a "maximally compliant attacker" script). Zero changes to orchestrator/tool dispatch code.
- [ ] Small visualizer (optional but high value for the post):
  - Ratatui TUI or a tiny web view that ingests the hash-chained audit log + capability tokens.
  - Renders attenuation DAG, per-call decisions, "what the principal saw vs what was allowed".
- [ ] Python-friendly surface (CLI protocol or minimal binding) so the story can include "usable from common agent frameworks."
- [ ] Comparative notes or mini-benchmark (structural guarantee vs prompt hardening vs pure sandboxing) — qualitative is fine.

### 4.9 Release & Distribution Hygiene
- [ ] Ensure `cargo test --workspace`, clippy, and fmt remain green at every step.
- [ ] Add a Linux CI job or note for the full demo when ready.
- [ ] Tag a milestone release or pre-release once P3 + basic artifacts exist.
- [ ] Prepare a short, high-signal README "Quick Demo" section.

---

## 5. Strategy for Interesting + Innovative Showcase (LinkedIn / Medium)

### Why This Story Works
- **Timely pain**: Indirect prompt injection in coding agents and tool-using LLMs is widely discussed and has no purely probabilistic fix.
- **Structural vs probabilistic**: The core claim is architectural ("the widening operation cannot be expressed"), not "our detector was 99% effective this week."
- **Reproducible evidence**: Byte-identical principal output + divergent outcome (vuln exfil vs protected denial) + preserved utility is unusually strong for a security demo.
- **Honest framing**: Explicit non-claims, named residual risks (child TTL window, permitted binary behavior), and TCB boundaries read as credible.
- **Framework, not one-off**: The crates are reusable; the demo is one (important) worked example.

### Recommended Hero Artifact
A clean, recorded run (asciinema or high-quality terminal capture) showing:
1. Clean baseline (no injection) — agent succeeds.
2. Injected + `AUTHZ=off` — attack succeeds (additive damage).
3. Same injected + `AUTHZ=on` — identical tool-call intent from the model, every out-of-scope call structurally denied (audit lines visible), sink empty, legitimate test still passes.

Supporting visuals:
- Attenuation flow diagram (update/extend the one in README).
- Audit log sample with named caveats.
- Side-by-side trace diff.
- "One command to reproduce" badge/instructions.
- Optional: live attenuation DAG from the visualizer.

### Article Angles (pick one primary + supporting)
- Primary: "How We Made Prompt Injection Structurally Impossible in an LLM Coding Agent"
- Supporting: "Capability-Based Authorization for the Age of Agents", "Authority That Can Only Narrow: Lessons from Building Warden"
- Structure suggestion: Problem (ambient authority + real examples) → Why detection/sanitization is insufficient → Thesis & architecture → Building it (Rust + biscuit + types + PDP) → The demo (the magic moment) → Limitations (honest) → How to adopt / what next → Conclusion.

### Innovation Highlights to Feature
- Per-call, request-bound, single-use child capabilities with cryptographic binding to exact arguments + nonce (replay resistance built in).
- Hybrid design: Rust type/API enforcement for the "no widening" invariant + biscuit for offline-attenuable, verifiable tokens.
- Architectural default-deny that cannot be shadowed.
- Hash-chained audit that binds both log integrity and capability signatures.
- Principal-independence as a validation method (defense does not inspect or depend on the caller's cleverness).

### Distribution Plan
1. Land the working demo + artifacts first.
2. Write the post while details are fresh (use the implementation decisions as source material).
3. Publish: Medium (longform + diagrams) → LinkedIn (thread + video clip) → X (short clip + link) → relevant communities (r/rust, security forums, agent-framework discussions).
4. Repo as primary artifact: excellent README, clear repro instructions, recorded demo, and the crates themselves.
5. Goal: credible, linkable technical piece that positions Warden as thoughtful infrastructure for agentic systems.

---

## 6. Risks & Mitigations

- **Model non-determinism breaks "identical output" story** — Mitigation: Prioritize a replay/deterministic mode that feeds pre-captured or fixed tool-call JSONs. Use live models only for exploration or secondary runs. Document that production is non-deterministic; enforcement never relies on predicting the principal.
- **Scope creep (federation, macOS parity, full Datalog PDP, etc.)** — Mitigation: Hard fence per the original non-goals. Anything beyond the reference demo + one amplifier goes into a future plan or design sketch only.
- **Demo complexity makes one-command repro hard** — Mitigation: Provide both "full" and "replay-only" modes. Offer a Docker/Linux container image or documented setup for the complete experience.
- **Linux-only containment disappoints macOS users** — Mitigation: State it clearly and early (README, docs, post). macOS remains fully useful for development and unit tests.
- **Audit or token chain has a subtle bug** — Mitigation: Keep the existing property tests + add chain verification as part of demo outputs. The audit crate already has continuity and hash tests.
- **"Permitted binary" gap (e.g., `python` or `pip` can still do bad things in-scope)** — Mitigation: Name it explicitly as a known limitation and a named future hardening target. The framework bounds *which* binaries, not *what* they do once running.

---

## 7. Immediate Next Actions (Start Here)

Do these in roughly this order for fastest progress toward a showcaseable demo:

1. **Update status docs** (30–60 min): Edit README status line + phased table + DEVELOPMENT.md to reflect "P0 core complete; building reference application."
2. **Minimal orchestrator spike** (half day): In `agent/`, create a tiny loop that mints a root cap from a manifest, accepts a list of tool requests (hardcoded for now), and exercises `attenuate` + `tools::authorize_only` (or direct PEP+PDP) for both allow and deny cases. Add an `AUTHZ` env toggle that bypasses for the "off" path. Print clear decisions and simulated audit events.
3. **First real guarded tool** (half–1 day): Implement `fs_read` (the simplest) behind the authorization gate using temp directories for tests. Wire it so an in-scope read succeeds and an out-of-scope read produces a structured denial with the PDP reason.
4. **Demo skeleton + fixture** (1–2 days): Create the Python fixture package (buggy but fixable test), an injection note file, and a tiny canary listener. Add basic demo entrypoints or a Makefile that can prepare clean vs injected workspaces.
5. **Replay mode + first vuln/protected pair** (1–2 days): Add support in the agent for feeding exact prior tool-call traces. Run the first "vuln" (AUTHZ=off) and "protected" (on) pair against the same trace. Capture the diff, audit, and sink evidence even if tools are still partial.
6. **Audit wiring + basic visual output** (parallelizable): Emit real `AuditEntry` records during the above runs and print or save human-readable excerpts.

After you have a working (even partially mocked) vuln vs protected comparison with logs, the rest of the plan accelerates dramatically and the article narrative becomes obvious.

---

## 8. Success Criteria for This Plan

- A reviewer (or future you) can run the demo harness and see:
  - Clean run succeeds with only in-scope operations.
  - Injected + vulnerable run performs the exfil (canary hit recorded).
  - Injected + protected run shows structurally identical principal output, every out-of-scope call denied with a named caveat in the audit log, sink remains empty, and the legitimate task still completes.
- `cargo test --workspace`, clippy, and fmt remain green.
- README + at least a THREAT_MODEL or prominent limitations section clearly states what is and is not defended.
- Artifacts exist that can be dropped into a high-signal technical post (recording, logs, diagrams, one-command repro instructions).
- The crates remain reusable and the orchestrator remains a small, auditable TCB component.

---

## 9. How to Use This Plan

- Treat this as `NEXT_STEPS_PLAN_1.md`. After major milestones, create `NEXT_STEPS_PLAN_2.md` (or just update and append a new section).
- Keep the original phased plan in README as the high-level vision; this document is the tactical, reality-adjusted execution plan.
- Before starting a new major item, update the checklist and add any new risks or scope decisions.
- When the demo is solid, revisit the "showcase & innovation amplifiers" section and pick the highest-ROI extension for the article.

---

**References**
- [README.md](./README.md) — Original vision, threat model, architecture, success definition.
- [docs/DEVELOPMENT.md](./docs/DEVELOPMENT.md) — Build commands, current (slightly stale) milestone notes.
- Crates: `capability`, `pep`, `pdp`, `audit`, `manifest`, `tools`, `sandbox`, `agent`, `demo`.

---

*This plan is a living document. Update it as you learn and ship.*

**Next review trigger:** After the first working `demo-vuln` vs `demo-protected` pair with artifacts.