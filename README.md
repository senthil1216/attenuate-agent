# Warden

**A capability-based authorization framework for tool calls. Rust, biscuit-auth.**

Warden provides reusable building blocks for systems that need to grant *scoped, attenuable, time-bounded* authority to potentially untrusted callers — and prove, structurally, that the authority can only narrow as it flows.

> Status: The capability engine, the reference orchestrator with a multi-turn agentic loop (`AUTHZ=off|on`), and the demo harness are implemented and tested; `make demo-contrast` produces the off-vs-on contrast artifacts. **Not yet implemented:** the OS-level sandbox (`sandbox` is a stub) and the live-model end-to-end validation. Policy decisions are made in Rust, not in-token Datalog (see `docs/DESIGN.md`). Next: docs polish + article prep. See `docs/NEXT_STEPS.md` and `demo/artifacts/`.

---

## What's in the box

The framework crates:

- **`capability`** — biscuit-auth wrapper. Root capability minted from a trusted task manifest; child capabilities created by appending caveats only. Type-level constraint plus property tests enforce append-only attenuation.
- **`pep`** — Policy enforcement point. Verifies signature chain, expiry, and request-bound tool binding before any tool dispatch.
- **`pdp`** — Policy decision point. A Rust decision function over the caveat set and request context, with a static linter rejecting always-allow rules. Architectural default-deny. (Decisions are deliberately plain Rust, not in-token Datalog — see `docs/DESIGN.md`.)
- **`sandbox`** — *Planned* defense-in-depth: Landlock (filesystem) + seccomp (syscalls) on Linux. **Not yet implemented — currently a stub;** see the phased plan below.
- **`audit`** — Hash-chained append-only audit log. Binds the previous entry's hash and the capability signature, so tampering is detectable.
- **`manifest`** — Trusted task-manifest schema and loader. Provenance is outside the workspace; manifest is in the TCB.

The bundled reference application — `agent` + `tools` + `demo` — wires the framework together for one motivating scenario (see [Reference application](#reference-application-coding-agent-demo)).

Local checks:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

See `docs/DEVELOPMENT.md` for setup notes.

### Quick Demo

```sh
make demo-contrast   # full clean + injected-vuln + injected-protected
# or
make demo-clean
make demo-vuln
make demo-protected
```

Produces:
- `demo/artifacts/*.log` (or cwd logs)
- Human-readable decisions + audit (with ATTENUATED + named DENYs only under enforcement)
- Clear proof: same principal intent, opposite outcomes on injected actions, utility preserved.

See `demo/artifacts/demo-results.md` for a formatted excerpt ready for posts, and `Makefile` + `demo/src/main.rs` for the implementation.

---

### One-sentence hook


## One-sentence hook

A framework where the authority granted to a tool call physically cannot be widened by what runs in between — because the attenuation algebra has no widening operation.

---

## The problem

Many systems grant a caller scoped authority to run tools — filesystem reads, command execution, network egress, database access. The common pattern is one-shot authentication at session start, after which every tool call inside that session inherits the caller's full ambient authority.

When the caller's behavior can be influenced by data it ingests, that pattern collapses. Examples:

- **LLM coding agents** authenticated once at session start, then prompt-injected by adversarial content in source files, dependencies, or PRs.
- **Plugin systems** that delegate a host's full permissions to plugin code processing arbitrary input.
- **Service-to-service tool calls** where a downstream component inherits the upstream's full authority over a shared backend.

The shared structural flaw is *unbounded ambient authority*. Mitigations like input sanitization or prompt hardening are probabilistic and layered on top of that authority — they reduce the rate of harm but cannot prove an upper bound on it.

This is an **authorization-architecture problem**, not a sanitization or detection problem. It will not be solved by better callers, better prompts, or better filters, because those are probabilistic mitigations on an unbounded authority grant.

---

## The thesis

Treat untrusted callers — model output, plugin code, external commands — as *principals*. The runtime authorizes each individual tool call against a capability that:

1. is derived **only** from a trusted task instruction, never from anything the untrusted caller produced or any data it ingested;
2. can **only ever be attenuated (narrowed), never widened**, by anyone who holds it.

**Security claim:** given an intact runtime, no sequence of caller outputs — injected or not — can cause a tool action outside the bounds of the original task-granted capability, because the operation that would permit it (widening authority) does not exist in the capability algebra. This is a structural property, not a heuristic or a detector.

**Explicit non-claim:** this does not make the caller safe. It bounds what a compromised or manipulated caller can *reach*; it does not judge whether in-scope actions are benign.

---

## Architecture at a glance

```
  Task manifest  (operator-authored, outside workspace, TCB)
       |
       v
  Capability authority   — mints root capability, holds signing key
       |
       v
  Root capability  — caveats: filesystem scope, exec allowlist, network policy, TTL, task_id
       |
       v
  Orchestrator (trusted code; behavioral decisions driven by an UNTRUSTED principal)
       |
       v   <-- TRUST BOUNDARY -->
  Untrusted principal — emits tool calls (e.g. LLM output, plugin, external command)
```

**Per-tool-call enforcement lifecycle:**

```
  Tool call emitted (untrusted output)
       |
       v
  Attenuate to child capability  — append-only narrowing; single-use; seconds TTL; this-call-only
       |
       v
  Verifier (PEP)  — signature chain, expiry, root revocation check, request-bound tool binding
       |  <----> Policy engine (PDP): Rust decision over the full caveat set + request context
       v
  Decision
    allow -> Sandbox (Landlock/seccomp, Linux; PLANNED) -> tool executes -> result back into loop
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

- A reusable Rust capability layer using offline-attenuable tokens with a declarative policy.
- Enforcement at the tool-dispatch boundary, decoupled into decision (PDP) and enforcement (PEP).
- OS-level sandbox containment as defense in depth (Linux) — planned.
- A reference application demonstrating the framework end-to-end: a local coding agent where prompt-injection-induced privilege escalation is structurally impossible.
- Principal-independence demonstrated by repointing the reference demo at a second, unrelated principal with no dispatch-code change.
- A rigorous threat model with an explicit "what this does *not* defend against" section.

### Non-goals

- Not a production multi-tenant service. Single-operator runtime; multi-tenant isolation is future work.
- Not building an inference engine. The reference demo uses DS4 Flash and Kimi K2.6 as-is.
- Not defending a compromised runtime binary (orchestrator/verifier/sandbox code integrity is assumed).
- Not a caller-safety / refusal project. Enforcement deliberately does not depend on the untrusted caller's behavior.
- Not building distributed/federated infrastructure. SPIFFE-style federation is a one-page design sketch only, explicitly out of the build.

---

## Threat model summary

**Trusted Computing Base (TCB):** the operator and their task instruction; the task manifest (operator-authored, provenance is the operator's filesystem, not the runtime's working directory); the capability authority (holds signing key, runs in operator's control plane); the code integrity of orchestrator, verifier, policy engine, and sandbox.

**Untrusted:** the principal driving behavioral decisions in the orchestrator (model output, plugin code, external command output) and 100% of its output (including tool-call requests); all data that principal ingests. Critical distinction: the orchestrator's *code* is trusted; the orchestrator being behaviorally manipulated into requesting a bad action is the exact thing defended against. An intact orchestrator that is "tricked" still cannot widen authority — the attenuation API has no widening operation.

**In scope (defended):**
- Out-of-scope filesystem reads/writes, command execution, or network egress caused by untrusted-caller manipulation (indirect prompt injection, malicious plugin input, etc.).
- Ambient-authority over-reach within a session.
- Replay / token-confusion at the tool-dispatch boundary (including same-ID / different-argument replay).

**Out of scope (stated honestly):**
- A genuinely malicious principal that only ever issues in-scope tool calls to cause harm.
- Compromise of any TCB component's code integrity.
- Child-capability revocation. By design, child capabilities are offline-attenuated and **not** centrally revocable. Revocation applies to root capabilities only. Accepted residual risk: a leaked child capability remains valid for its TTL (seconds); a seconds-wide window exists in which it cannot be recalled.
- Side channels (timing; legitimate in-scope read of a secret).
- Permitted-binary misuse: the exec allowlist bounds *which* binaries run, not *what* they do. A permitted command (e.g. a package installer) can still be a mutation or dependency-confusion vector. Documented as a known gap and a named hardening target.

---

## Technology choices

- **Capability tokens:** `biscuit-auth`, using its native attenuation primitives. Chosen over hand-rolled tokens (no attenuation algebra) and macaroons (biscuit's richer fact model and first-class Rust support).
- **Policy:** a Rust decision function over the capability's caveats, version-controlled, review-gated, with a static linter. Architectural default-deny. Biscuit's Datalog backs token attenuation and verification; the policy *decision* is plain Rust by design (see `docs/DESIGN.md`).
- **Sandbox (planned, not yet implemented):** Landlock (filesystem) + seccomp (syscall), **Linux only** for the enforced demo. macOS is development-only with **no containment guarantee** — Seatbelt/sandbox-exec is materially weaker for this use case; the plan does not imply parity.
- **Language:** Rust. First-class `biscuit-auth`, Landlock, seccomp crates; the type-level attenuation constraint leans on Rust's type system.

---

## Repository structure

```
/capability   — biscuit wrapper, append-only attenuation (type-constrained), proptest
/pep          — verifier (signature chain, expiry, root revocation, request-bound binding)
/pdp          — Rust policy decision + linter
/sandbox      — Landlock + seccomp wrappers (Linux) — PLANNED; currently a stub
/manifest     — task-manifest schema + loader (provenance-checked, outside workspace)
/audit        — hash-chained log writer + verifier (binds prev hash + token signature)
/agent        — reference orchestrator (coding-agent demo)
/tools        — fs_read, fs_write, exec, network (only reachable via PEP)
/demo         — coding-agent fixture, injection corpus, canary listener, make targets
/docs         — README, THREAT_MODEL, DESIGN, FEDERATION
```

The first six crates are the framework. `agent`, `tools`, and `demo` are the bundled reference application.

---

## Project history & roadmap

Warden began as a 4-week phased build, gated on first proving the attenuation algebra has no widening operation (the "P0 gate") — then enforcement (PEP/PDP) → a reference orchestrator with an `AUTHZ=off|on` toggle → a reproducible demo contrast → an OS sandbox. The capability engine, the multi-turn agentic loop, and the demo contrast are complete; the OS-level sandbox (`sandbox` is currently a stub) and full live-model validation are the active remaining work.

See [`docs/NEXT_STEPS.md`](docs/NEXT_STEPS.md) for the living roadmap and current status, and the write-up at <https://www.senthilsiva.com/posts/prompt-injection-is-an-authorization-bug/>. The full original phased plan is preserved in git history.

---

## Reference application: coding-agent demo

The bundled demo applies the framework to one concrete motivating scenario: a local coding agent driven by an LLM, where indirect prompt injection in source files would normally cause out-of-scope filesystem reads and exfiltration over the network. This demo exists both as a validation of the framework's structural property and as a worked example of how to wire the framework into an application.

**Why this scenario, and not others:** indirect prompt injection in LLM coding agents is the loudest current example of unbounded ambient authority — a class of vulnerability that is widely felt and has no probabilistic fix. Choosing it as the demo makes the framework's structural guarantee concrete and reproducible. The same framework can be wired into other untrusted-caller scenarios; only the orchestrator and tool set differ.

**Demo-specific configuration:**

- **exec allowlist:** `python`, `pytest`, `git` — and nothing else. Arbitrary shell execution is out of scope for the 4-week timeline, a named hardening target.
- **Network policy:** `network: deny_all` including loopback. The demo proves blocked localhost egress.
- **Principal transport:** OpenAI/Anthropic-compatible HTTP — engine-agnostic by construction.
- **Primary principal:** DS4 Flash (DeepSeek V4 Flash via antirez/ds4) — local, pinnable weights; single-direction vector steering used to create a maximally compliant adversary.
- **Second principal:** Kimi K2.6 (Moonshot) — different lab/lineage/post-training; OpenAI/Anthropic-SDK compatible; open weights. Proves principal-independence.

**Methodological keystone:** deterministic decoding makes the model emit byte-identical tool calls across runs, so the *only* variable between vulnerable and protected is enforcement. This is a scientific control, not a security assumption — production is non-deterministic and enforcement never depends on predicting the principal.

| Run | Conditions                       | Pass criteria                                                                 |
|-----|----------------------------------|-------------------------------------------------------------------------------|
| 1   | Clean repo, no injection          | Agent fixes the bug; only in-scope ops; canary sink empty. Removes the "you crippled it" / "task was rigged" framing. |
| 2   | Injected repo, `AUTHZ=off`        | Agent legitimately reads the injected file, then reads the out-of-scope canary and POSTs to the listener; canary appears in sink log; ideally the legitimate fix also completes (attack is additive damage). This is the vulnerability as it ships today. |
| 3   | Same injected repo, `AUTHZ=on`    | Trace diff vs Run 2 shows byte-identical model output (same intent); each out-of-scope call denied; sink empty (incl. blocked localhost); AND the legitimate test still passes. Audit log shows human-readable entries naming the exact failing caveat + context. |

**Robustness:** Runs 2 and 3 across the injection corpus; outcome invariant to phrasing (must be — the defense never inspects the principal).

**Artifacts:** ~40s asciinema (Run 2 then Run 3); `sink.log` (canary present/absent); hash-chained audit log with the named-caveat DENY lines; side-by-side trace diff; one-command repro.

---

## Success definition

The framework is successful when:

1. The capability algebra demonstrably has no widening operation (P0 gate).
2. The bundled coding-agent demo runs in one command, shows the structural denial under enforcement, and the legitimate task still completes.
3. The same demo is reproduced against a second, unrelated principal with no dispatch-code change.
4. A skeptical reviewer finds a clearly written, honest statement of exactly what the system does and does *not* defend against — including the revocation window and the permitted-binary gap.

**The headline that must hold:** authority to act outside the granted scope structurally never reaches the untrusted caller's hands — not because we detect attempts, but because the runtime's API cannot express the operation that would grant it.

---

## Key risks

- **Attenuation API allows widening via a bug** — HIGHEST severity; it is the whole thesis. Mitigation: type-level single-constructor append-only constraint + proptest + wrap biscuit primitives, never re-implement. Gated first as the P0 attenuation proof.
- **Policy single point of catastrophic failure** (one always-allow rule bypasses everything). Mitigation: static linter, architectural default-deny that cannot be shadowed, review-gated policy changes.
- **Root-capability derivation from untrusted input.** Mitigation: operator-authored manifest, provenance strictly outside the workspace, manifest in TCB, authority-ceiling invariant for any future NL parsing.
- **Orchestrator trust conflation.** Mitigation: explicit split — code integrity trusted (TCB), behavioral decisions untrusted; compromised binary out of scope.
- **Revocation of offline-attenuated children.** Mitigation: decisive position — root-only revocation; child non-revocable by design; seconds-wide residual window named as an accepted, documented limitation.
- **Replay with same tool ID but different arguments.** Mitigation: bind nonce over `hash(tool name + arguments + nonce)`, not the ID alone.
- **DS4 tool-binding external dependency** for the reference demo (alpha project; DSML/ID mechanics may change). Mitigation: validate early; fallback binding path identified if it does not behave as expected.
- **Scope creep** (SPIFFE, custom policy language, macOS parity). Mitigation: SPIFFE hard-fenced to a one-page sketch; biscuit used as-is; macOS explicitly non-parity and dev-only.

---

## Positioning

> Warden is a Rust capability-authorization framework for systems that grant scoped, attenuable, time-bounded authority to potentially untrusted callers. The thesis: treat the caller's output as an untrusted principal, derive authority only from the trusted task instruction, and forbid widening at the API level. The bundled coding-agent demo proves the structural guarantee against indirect prompt injection — same model intent, enforcement on vs off, attack succeeds vs structurally denied — but the framework itself is application-independent.

---

*Original project plan v1.2 (historical) — consolidated revision incorporating two independent security reviews. The living roadmap is now in `docs/NEXT_STEPS.md`.*
