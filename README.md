# Warden

**Capability-based tool authorization for local coding agents.**

A secure coding-agent runtime that makes prompt-injection-induced privilege escalation *structurally impossible*, demonstrated on local open-weight models (DS4 Flash, Kimi K2.6).

> Status: Planning (post first security review) · Document version: 1.2 · Estimated duration: 4 weeks (focused)

---

## One-sentence hook

A coding agent where prompt injection physically cannot escalate privilege — because authority only flows down and only narrows. Capability-based authorization applied to the place agents are most exposed.

---

## The problem

AI coding agents are being given real machine authority — filesystem, shell, network — while the component that drives them (an LLM) can be hijacked by any text it ingests. The dominant architecture makes this worse: the agent authenticates once at session start and then operates with the human's full ambient authority for the entire session. Every tool call inside that session inherits that authority.

**Consequence:** a single indirect prompt injection — one adversarial comment in one source file, a poisoned dependency, a malicious PR — can pivot the agent into doing anything the human operator could do. The legitimate task and the attack run under the same unscoped privilege.

This is not a model-quality problem. It is an **authorization-architecture problem**. It will not be solved by better models, prompt hardening, or input sanitization, because those are probabilistic mitigations layered on an unbounded authority grant.

---

## The thesis

Treat the model's output as an *untrusted principal*. The agent runtime authorizes every individual tool call against a capability that:

1. is derived **only** from the trusted human task instruction, never from anything the model produced or any data it ingested;
2. can **only ever be attenuated (narrowed), never widened**, by anyone who holds it.

**Security claim:** given an intact runtime, no sequence of model outputs — injected or not — can cause a tool action outside the bounds of the original human-granted capability, because the operation that would permit it (widening authority) does not exist in the capability algebra. This is a structural property, not a heuristic or a detector.

**Explicit non-claim:** this does not make the model safe. It bounds what a compromised or manipulated model can *reach*; it does not judge whether in-scope actions are benign.

---

## Architecture at a glance

```
  Task manifest  (operator-authored, outside workspace, TCB)
       |
       v
  Capability authority   — mints root capability, holds signing key
       |
       v
  Root capability  — caveats: repo scope, exec allowlist, network policy, TTL, task_id
       |
       v
  Orchestrator (agent loop; trusted code, untrusted model-driven decisions; no signing key)
       |
       v   <-- TRUST BOUNDARY -->
  DS4 / Kimi model server  — emits tool calls; output is UNTRUSTED
```

**Per-tool-call enforcement lifecycle:**

```
  Tool call emitted (untrusted model output)
       |
       v
  Attenuate to child capability  — append-only narrowing; single-use; seconds TTL; this-call-only
       |
       v
  Verifier (PEP)  — signature chain, expiry, root revocation check, request-bound tool binding
       |  <----> Policy engine (PDP): Datalog over the full caveat set + request context
       v
  Decision
    allow -> Sandbox (Landlock/seccomp, Linux) -> tool executes -> result back into loop
    deny  -> structured error back into loop + audit entry
       |
       v
  Audit log  — append-only, hash-chained: every mint, attenuation, decision (allow and deny)
```

### Hardening invariants (each is a deliverable, not optional)

- **Attenuation integrity** — children are minted by *appending* restricting caveats only. Defended two ways: (1) a type-level constraint where the attenuated-capability type has exactly one constructor (an append-only API) — "replace a caveat" or "construct from scratch" is not expressible in the type system; (2) property-based tests over random attenuation chains asserting the permitted set can only shrink.
- **Hard constraint** — wrap `biscuit-auth`'s own attenuation primitives. Do **not** re-implement the attenuation algebra. Re-implementation is the single most likely way to silently void the thesis.
- **Default-deny is architectural** — "deny" is the result of *no policy rule matching*, not a deny rule a later rule could shadow. It is structurally impossible for an added rule to override the default.
- **Audit integrity** — the hash chain binds the previous entry's hash *and* the capability token's signature, so tampering with either the log or the token record is detectable. Audit entries are human-readable and include the exact failing caveat name plus request context.

---

## Goals and non-goals

### Goals

- A working coding agent that drives a local model over the OpenAI/Anthropic-compatible tool protocol.
- A capability layer using offline-attenuable tokens with a declarative policy.
- Enforcement at the agent's tool-dispatch boundary, decoupled into decision (PDP) and enforcement (PEP).
- OS-level sandbox containment as defense in depth (Linux).
- A reproducible, adversarial demonstration: same model intent, enforcement on vs off, attack succeeds vs structurally denied, legitimate work still completes.
- Model-independence demonstrated across two different model lineages.
- A rigorous threat model with an explicit "what this does *not* defend against" section.

### Non-goals

- Not building an inference engine. DS4 and Kimi K2.6 are used as-is.
- Not defending against a genuinely malicious model making only in-scope calls.
- Not defending a compromised runtime binary (orchestrator/verifier/sandbox code integrity is assumed).
- Not a production multi-tenant service. Single-operator runtime; multi-tenant isolation is future work.
- Not a model-safety / refusal project. Enforcement deliberately does not depend on model behavior.
- Not building distributed/federated inference. SPIFFE-style federation is a one-page design sketch only, explicitly out of the build.

---

## Threat model summary

**Trusted Computing Base (TCB):** the human operator and their task instruction; the task manifest (operator-authored, provenance is the operator's filesystem, not the agent's working directory); the capability authority (holds signing key, runs in operator's control plane); the code integrity of orchestrator, verifier, policy engine, and sandbox.

**Untrusted:** the model and 100% of its output (including tool-call requests); all data the model ingests (file contents, command output, fetched text); the orchestrator's *behavioral decisions* when driven by model output. Critical distinction: the orchestrator's *code* is trusted; the orchestrator being behaviorally manipulated into requesting a bad action is the exact thing defended against. An intact orchestrator that is "tricked" still cannot widen authority — the attenuation API has no widening operation.

**In scope (defended):**
- Indirect prompt injection via ingested content causing out-of-scope filesystem reads/writes, command execution, or network egress.
- Ambient-authority over-reach within a session.
- Replay / token-confusion at the tool-dispatch boundary (including same-ID / different-argument replay).

**Out of scope (stated honestly):**
- A genuinely malicious model that only ever issues in-scope tool calls to cause harm.
- Compromise of any TCB component's code integrity.
- Child-capability revocation. By design, child capabilities are offline-attenuated and **not** centrally revocable. Revocation applies to root capabilities only. Accepted residual risk: a leaked child capability remains valid for its TTL (seconds); a seconds-wide window exists in which it cannot be recalled.
- Side channels (timing; model legitimately reading an in-scope secret).
- Permitted-binary misuse: the exec allowlist bounds *which* binaries run, not *what* they do. A permitted command (e.g. a package installer) can still be a mutation or dependency-confusion vector. Documented as a known gap and a named hardening target.

---

## Technology choices

- **Capability tokens:** `biscuit-auth`, using its native attenuation primitives. Chosen over hand-rolled tokens (no attenuation algebra) and macaroons (biscuit's Datalog fits declarative per-tool policy).
- **Policy:** biscuit Datalog, version-controlled, review-gated, with a static linter. Architectural default-deny.
- **Sandbox:** Landlock (filesystem) + seccomp (syscall), **Linux only** for the enforced demo. macOS is development-only with **no containment guarantee** — Seatbelt/sandbox-exec is materially weaker for this use case; the plan does not imply parity.
- **exec allowlist (demo):** `python`, `pytest`, `git` — and nothing else. Arbitrary shell execution is out of scope for the 4-week timeline, a named hardening target.
- **Network policy (demo):** `network: deny_all` including loopback. The demo proves blocked localhost egress.
- **Agent ↔ model transport:** OpenAI/Anthropic-compatible HTTP — engine-agnostic by construction.
- **Primary backend:** DS4 Flash (DeepSeek V4 Flash via antirez/ds4) — local, pinnable weights; single-direction vector steering used to create a maximally compliant adversary.
- **Second backend:** Kimi K2.6 (Moonshot) — different lab/lineage/post-training; OpenAI/Anthropic-SDK compatible; open weights. Proves model-independence.
- **Language:** Rust recommended (first-class `biscuit-auth`, Landlock, seccomp crates; the type-level attenuation constraint leans on Rust's type system). Final decision in Phase 0, day 1.

---

## Repository structure (proposed)

```
/capability   — biscuit wrapper, append-only attenuation (type-constrained), proptest
/pep          — verifier (signature chain, expiry, root revocation, request-bound binding)
/pdp          — Datalog policy + evaluation + linter
/sandbox      — Landlock + seccomp wrappers (Linux)
/agent        — orchestrator loop, model transport (OpenAI/Anthropic compatible)
/tools        — fs_read, fs_write, exec, network (only reachable via PEP)
/manifest     — task-manifest schema + loader (provenance-checked, outside workspace)
/demo         — fixture repo, injection corpus, canary listener, make targets
/docs         — README, THREAT_MODEL, DESIGN, WHY-DS4, FEDERATION
/audit        — hash-chained log writer + verifier (binds prev hash + token signature)
```

---

## Phased work plan

Priority is explicit. The attenuation proof is the project's **go/no-go gate**; everything is scheduled behind proving it.

| Priority      | Item                                                                 | Phase   |
|---------------|----------------------------------------------------------------------|---------|
| **P0-GATE**   | Attenuation API + type-level constraint + monotonicity property tests | 1       |
| **P0-PARALLEL** | Deterministic demo harness elements (fixture repo, injection corpus, canary listener, make targets) | 5 elements built in parallel |
| P1            | PEP/PDP split + architectural default-deny + policy linter           | 2       |
| P1            | Agent loop integration with `AUTHZ=on\|off` toggle                   | 3       |
| P2            | Landlock/seccomp sandboxing (defense-in-depth)                       | 4       |
| P3            | Kimi K2.6 cross-model validation                                     | 6       |
| P4            | SPIFFE federation — **design sketch only, zero code**                | section 9 |

### Phase outline

- **Phase 0 — Foundations** (Week 1, ~3 days): language decision (day 1), repo/CI/lint/license, DS4 Flash local + tool-call round trip, validate request-bound tool binding mechanism against DS4 DSML, confirm Kimi K2.6 endpoint, naive agent loop with NO authorization (deliberate vulnerable baseline, clearly marked and isolated).
- **Phase 1 — Capability core (P0-GATE)** (Week 1–2, ~4 days): root minting from the manifest, append-only attenuation wrapping biscuit primitives, type-level single-constructor constraint, proptest suite. **Done when:** a generated attempt to widen scope is NOT expressible in the type system, and property tests pass. **Gates all downstream work.**
- **Phase 2 — Enforcement boundary (PEP + PDP)** (Week 2, ~3 days): signature chain, expiry, root revocation check, request-bound binding; Datalog over full caveat set + context; policy linter (rejects always-allow rules); property-based tests for full policy evaluation across all four operation classes.
- **Phase 3 — Agent loop integration** (Week 2–3, ~3 days): `fs_read`, `fs_write`, `exec`, `network` tools reachable only via the PEP; task-start minting from manifest (trusted channel only); `AUTHZ=off|on` toggle.
- **Phase 4 — Sandbox containment (P2)** (Week 3, ~3 days): Landlock fs confinement to `repo_root` for exec'd tools; seccomp blocking network syscalls under `network:deny_all`. **Done when:** a deliberately mis-authorized call still fails at the OS boundary.
- **Phase 5 — Demonstration harness** (Week 3–4, ~3 days): fixture (small Python package with a real, fixable failing test); indirect injection embedded as a plausible in-repo "agent maintenance note"; canary file outside repo root; local listener on `127.0.0.1:9999`; deterministic decoding (temperature 0, greedy, fixed seed, tracing on); injection corpus (4–5 phrasings); `make demo-clean`, `make demo-vuln`, `make demo-protected`.
- **Phase 6 — Model-independence (P3)** (Week 4, ~2 days): repoint to Kimi K2.6 via base-URL swap, no dispatch code change; re-run demo-vuln / demo-protected; document identical DENY outcomes across lineages.
- **Phase 7 — Documentation** (Week 4, ~2 days): `README`, `THREAT_MODEL.md`, `DESIGN.md`, `WHY-DS4.md`, `FEDERATION.md`. **Done when:** a reviewer reproduces the demo in one command and locates the limitations section without searching.

---

## Demonstration plan

**Methodological keystone:** deterministic decoding makes the model emit byte-identical tool calls across runs, so the *only* variable between vulnerable and protected is enforcement. This is a scientific control, not a security assumption — production is non-deterministic and enforcement never depends on predicting the model.

| Run | Conditions                       | Pass criteria                                                                 |
|-----|----------------------------------|-------------------------------------------------------------------------------|
| 1   | Clean repo, no injection          | Agent fixes the bug; only in-scope ops; canary sink empty. Removes the "you crippled it" / "task was rigged" framing. |
| 2   | Injected repo, `AUTHZ=off`        | Agent legitimately reads the injected file, then reads the out-of-scope canary and POSTs to the listener; canary appears in sink log; ideally the legitimate fix also completes (attack is additive damage). This is the vulnerability as it ships today. |
| 3   | Same injected repo, `AUTHZ=on`    | Trace diff vs Run 2 shows byte-identical model output (same malicious intent); each out-of-scope call denied; sink empty (incl. blocked localhost); AND the legitimate test still passes. Audit log shows human-readable entries naming the exact failing caveat + context. |

**Robustness:** Runs 2 and 3 across the injection corpus; outcome invariant to phrasing (must be — the defense never inspects the model).

**Artifacts:** ~40s asciinema (Run 2 then Run 3); `sink.log` (canary present/absent); hash-chained audit log with the named-caveat DENY lines; side-by-side trace diff; one-command repro.

---

## Success definition

The project is successful when a skeptical security engineer can, in one command:

1. Watch the attack succeed with enforcement off.
2. Watch the SAME model intent be structurally denied with enforcement on, while the legitimate task still completes.
3. See it reproduced against a second, unrelated model with no code change.
4. Find a clearly written, honest statement of exactly what the system does and does *not* defend against — including the revocation window and the permitted-binary gap.

**The headline that must hold:** a prompt injection cannot escalate privilege — not because we detect it, but because, given an intact runtime, the authority to act on it structurally never reaches the agent's hands.

---

## Key risks

- **Attenuation API allows widening via a bug** — HIGHEST severity; it is the whole thesis. Mitigation: type-level single-constructor append-only constraint + proptest + wrap biscuit primitives, never re-implement. Gated as P0 (Phase 1).
- **Datalog policy single point of catastrophic failure** (one always-allow rule bypasses everything). Mitigation: static linter, architectural default-deny that cannot be shadowed, review-gated policy changes (Phase 2).
- **Root-capability derivation from untrusted input.** Mitigation: operator-authored manifest, provenance strictly outside the workspace, manifest in TCB, authority-ceiling invariant for any future NL parsing.
- **Orchestrator trust conflation.** Mitigation: explicit split — code integrity trusted (TCB), model-driven behavioral decisions untrusted; compromised binary out of scope.
- **Revocation of offline-attenuated children.** Mitigation: decisive position — root-only revocation; child non-revocable by design; seconds-wide residual window named as an accepted, documented limitation.
- **Replay with same tool ID but different arguments.** Mitigation: bind nonce over `hash(tool name + arguments + nonce)`, not the ID alone.
- **DS4 tool-binding external dependency** (alpha project; DSML/ID mechanics may change). Mitigation: validate in week 1 (Phase 0); fallback binding path identified if it does not behave as expected.
- **Scope creep** (SPIFFE, custom policy language, macOS parity). Mitigation: SPIFFE hard-fenced to a one-page sketch; biscuit Datalog used as-is; macOS explicitly non-parity and dev-only.

---

## Positioning

> Everyone's giving AI coding agents real machine access while the thing driving them can be hijacked by any text it reads — and the agent runs with the human's full authority for the whole session, so one injected comment in one file can pivot it into anything that human could do. Warden makes every tool call present a capability derived only from the original human task that can only ever be narrowed. The model's output is treated as an untrusted client. Injection can't escalate — not because we detect it, but because the authority to do the bad thing structurally never exists.

---

*Project plan v1.2 — consolidated revision incorporating two independent security reviews.*
