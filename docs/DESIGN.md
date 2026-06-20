# Design Notes

## Why Biscuit + Rust-side Validation (not pure Datalog in the token for decisions)

Biscuit provides offline-attenuable, verifiable tokens with a built-in Datalog-like fact system. We use it for:

- Root minting from the trusted manifest.
- Append-only child creation (the attenuation algebra itself is provided by biscuit; we wrap it with a type-level single-constructor API so that "widen" is literally not expressible in the public Rust API).
- Cryptographic binding of request-specific facts (tool name + blake3(arg hash) + nonce) so that a child token is single-use and bound to one exact invocation.

However, the actual *policy decision* (is this ToolRequest allowed under the current permission set?) is performed in Rust (`pdp::decide`) over the `PermissionSet` that was extracted from the latest biscuit block.

Reasons:
- Architectural default-deny is easier to guarantee in ordinary Rust control flow than in a set of Datalog rules that could be shadowed or accidentally made permissive.
- The static linter (`pdp::linter`) can reject obviously dangerous policy at manifest load time (e.g. readable root = `/`).
- Property-based tests over the decision function are straightforward.
- We still get the benefits of biscuit for the token layer (attenuation, signature chain, offline use, tamper-evident facts).

### Enforcement reads the token, not the struct

The security of the previous paragraph hinges on one rule: the `PermissionSet` fed to `pdp::decide` must be **derived from the cryptographically verified token**, never from a plaintext struct field that an attacker could edit independently of the signature.

A `ChildCapability` carries a convenience mirror of its permissions as an ordinary `serde`-(de)serializable struct field. That mirror is *not* covered by the signature on its own. If enforcement decided over the struct, an attacker could take any legitimately-narrowed, validly-signed capability, deserialize it, widen the struct's `permissions`/`expires_at`/`request_binding` back toward root authority, and re-serialize: the signature still verifies (the token bytes are untouched) while the PDP reads the widened struct — a silent privilege escalation across the very serde boundary the token format is designed to support ("offline-attenuable").

To close this, the PEP (`pep::verify`) consumes a `VerifiedState` produced by `ChildCapability::verify_and_decode`, which:

1. recovers the authoritative `PermissionSet`, `expires_at`, and request binding by decoding the latest signed biscuit block (`biscuit_codec::decode_state`); and
2. rejects (`CapabilityError::TokenStateMismatch` → `VerificationError::StateTampered`) any capability whose struct mirror disagrees with the decoded token.

`VerifiedCapability` then exposes *only* the token-derived state, so the struct mirror is physically unreachable on the decision path. Honestly-constructed capabilities build the struct and the token block from the same `PermissionSet`, so the mismatch check only ever fires on tampering. Regression coverage: `pep::tests::verify_rejects_struct_permissions_widened_after_signing`, which asserts that the signature-chain-only check still passes the tampered capability (the old, vulnerable behavior) while `verify` rejects it.

If in the future we decide that embedding more of the policy logic inside biscuit authorizers adds value (e.g. for external reviewers who want to run the exact same Datalog), the current design keeps the door open; the facts we already emit (`read_root`, `write_root`, `exec_binary`, `network`, `expires_at`, binding facts) are the ones a biscuit authorizer would need.

## Request Binding Design

Every child capability carries (in its latest biscuit block):

- `binding_tool`
- `binding_arg_hash` (blake3 of canonical ToolRequest)
- `binding_nonce` (fresh UUID per attenuation)

On dispatch:
1. The orchestrator creates the binding *before* attenuation (so the hash covers the exact arguments the principal asked for).
2. The child token is minted with that binding.
3. PEP verifies that the *actual* request presented at execution time produces the same hash + nonce that is inside the token.
4. A replay with the same tool name but different args (or a different nonce) fails the binding check.

This prevents the classic "same ID, different arguments" replay that would otherwise be possible with many capability systems.

The nonce also makes every child token unique even if the rest of the attenuation is identical, which helps with audit correlation.

## Why Architectural Default-Deny + Linter

In the PDP we deliberately do *not* have a "deny" rule that could be shadowed by a later "allow" rule. `decide` returns `Allow` only if an explicit `allows_*` predicate matches; otherwise it is `Deny` with a human-readable reason.

The linter currently only catches the most egregious case (readable root = `/`). It is intended to grow (world-writable roots, overly broad exec allowlists, `network: allow_all` when the manifest author probably meant `deny_all`, etc.).

Policy changes are expected to be review-gated; the linter is a fast feedback loop, not a complete verifier.

## Audit Chain

Every mint, attenuation, allow, and deny is recorded via `audit::chain_entry`. The chain binds:

- Previous entry hash
- Event (including the exact failing caveat name + request context on denies)
- Timestamp, UUID, etc.

`audit::verify_chain` can be run after a demo (or in production) to detect tampering with either the log or the tokens that were referenced.

The current implementation is intentionally simple (in-memory `Vec<AuditEntry>` for the orchestrator, blake3 hashes). A production version could stream to a file or remote store while still offering the same `verify_chain` API.

## Sandbox (Defense in Depth)

Landlock + seccomp are deliberately *defense in depth*, not the primary mechanism. Even if a child capability is somehow widened (via a future bug), the OS sandbox should still confine the executed binary to the declared filesystem roots and syscall set.

On macOS we explicitly do *not* claim containment (Seatbelt is weaker for this use case). The demo works on macOS for development, but the security claims require Linux.

## Non-Goals (kept out of scope)

- Revocation of offline children (by design; short TTL is the mitigation).
- Distributed/federated roots (SPIFFE-style is mentioned only as a one-page design sketch).
- Inference engine or model safety (we treat the model output as an untrusted principal by definition).
- Multi-tenant isolation (single-operator runtime for now).

These decisions keep the TCB small and the thesis crisp.