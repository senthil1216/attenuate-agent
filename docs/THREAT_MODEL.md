# Threat Model

**Warden** is a capability-based authorization framework whose core claim is *structural*: given an intact runtime, no sequence of outputs from an untrusted principal (LLM, plugin, external command, etc.) can cause a tool action outside the bounds of the original task-granted capability, because the operation that would permit widening authority does not exist in the capability algebra.

This document makes the security claims, trusted computing base, and limitations explicit.

## Trusted Computing Base (TCB)

- The operator and their task instruction.
- The task manifest (operator-authored, provenance outside the runtime workspace; lives in the TCB).
- The capability authority (holds the root signing key; runs under operator control).
- The code integrity of:
  - The orchestrator (trusted code, even when behaviorally driven by an untrusted principal).
  - `capability`, `pep`, `pdp`, `audit`, `tools`, and `manifest` crates.
  - The sandbox (planned defense-in-depth, Linux-only; not yet implemented).

**Important distinction:** The orchestrator's *code* is trusted. The orchestrator being tricked by its untrusted driver (model output, etc.) into requesting a bad action is exactly what the framework is designed to bound.

## In Scope (Defended)

- Out-of-scope filesystem reads/writes, command execution, or network egress caused by manipulation of the untrusted principal (indirect prompt injection, malicious plugin input, etc.).
- Ambient-authority over-reach within a single task/session.
- Replay or token confusion at the tool-dispatch boundary (including same tool ID with different arguments, thanks to nonce + argument hash binding).

## Out of Scope (Explicitly Not Claimed)

- A genuinely malicious principal that only ever issues *in-scope* tool calls to cause harm.
- Compromise of any TCB component's code integrity (supply-chain attack on the binary, kernel exploit, etc.).
- Child-capability revocation. By design, child capabilities are offline-attenuated and **not** centrally revocable. Revocation applies only to root capabilities. Residual risk: a leaked child capability remains valid for its short TTL (seconds).
- Side channels (timing, cache, legitimate in-scope reads of secrets, etc.).
- Permitted-binary misuse. The exec allowlist bounds *which* binaries may run, not *what* they do once running. A permitted `python` or `pip` can still be a vector for dependency confusion, mutation, or other in-scope harm. This is a named, documented limitation.
- Inference-time safety / refusal. Warden deliberately does not depend on the principal behaving safely or refusing bad requests.

## Residual Risks (Named and Accepted)

1. **Child capability TTL window**  
   A leaked child capability is valid until its short TTL expires. We accept a seconds-wide window as the price of offline attenuation.

2. **Permitted binary behavior**  
   Once a binary is on the allowlist, Warden cannot see what it does with the granted resources. This is out of scope for the current design.

3. **Compromised runtime binary**  
   If the orchestrator/PEP/PDP binary itself is malicious or backdoored, all bets are off.

4. **Manifest provenance**  
   The manifest is the root of authority. If an attacker can substitute a malicious manifest before it reaches the authority, they can mint overly broad capabilities. Operators must protect manifest provenance (outside the workspace, reviewed, etc.).

## How the Structural Guarantee Works

- Root capability is minted *only* from a trusted manifest.
- Every child capability can only be created by *appending* restricting caveats (type-level single-constructor API in `capability` + runtime checks).
- Widening is not expressible: attempting to request broader scope returns a typed error before any biscuit token is even constructed.
- Every tool dispatch goes through PEP (signature chain, expiry, request binding) + PDP (policy decision on the current permission set).
- The bypassed (`AUTHZ=off`) path is deliberately isolated and only exists for the vulnerable baseline in the demo.

The same principal output (identical tool call trace) produces opposite security outcomes solely because of the enforcement toggle. The defense does not inspect or depend on the cleverness of the principal.

## Relationship to Other Mitigations

Warden is an *authorization architecture* defense. It is complementary to (and does not replace):

- Prompt hardening / input sanitization
- Model refusal training
- Sandboxing at the OS level (Landlock + seccomp — planned defense-in-depth, not yet implemented)
- Code review of permitted binaries
- Supply-chain security for the runtime itself

## Versioning & Updates

This threat model is tied to the current implementation. Significant changes to the capability model, revocation story, or TCB will require an update to this document.

See also:
- `docs/NEXT_STEPS.md` (internal plan and historical status)
- `README.md` (high-level positioning)
- The `agent/tests/enforcement.rs` test (the executable specification of the core contrast)