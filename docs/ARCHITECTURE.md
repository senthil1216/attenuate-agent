# Architecture — a Python developer's guide to the Warden codebase

This doc maps the project's Rust structure onto concepts a Python programmer
already knows, then walks every crate and how they interact. It is reading
material, not a spec — for the *why* behind the design see [DESIGN.md](DESIGN.md)
and [THREAT_MODEL.md](THREAT_MODEL.md).

## The one-paragraph mental model

Warden mints a cryptographically signed **capability** from a trusted
operator-authored **manifest**, then forces every tool call an (untrusted) agent
wants to make through a verify → decide → execute pipeline. A prompt-injected
model can *ask* for anything; it can only *do* what the capability allows, and a
capability can only ever be **narrowed** (attenuated), never widened.

## Python → Rust cheat sheet

Keep this table next to you while reading the code. Once these five rows click,
the layout stops feeling foreign.

| Python concept | Rust concept in this repo | Example |
|---|---|---|
| A package (folder of related modules) | A **crate** | `capability/`, `pdp/`, `pep/` … |
| `__init__.py` / module entry point | `src/lib.rs` | every crate has one |
| The app entry (`__main__.py`) | `src/main.rs` | only `agent/` has one (the binary) |
| A class | a `struct` + its `impl` block | `struct TaskManifest` + `impl TaskManifest` |
| A method | `fn` taking `&self` inside `impl` | `fn validate(&self)` |
| A `@staticmethod` / free function | a bare `pub fn` | `pdp::decide(perms, req)` |
| An `Enum` / tagged union | `enum` (can carry data per variant) | `enum Decision { Allow, Deny { reason } }` |
| `from x import Y` | `use warden_x::Y;` | `use warden_pdp::decide;` |
| `raise SomeError()` | `return Err(SomeError)` | error is a *return value*, not a throw |
| catching/propagating an exception | the `?` operator | `verify(...)?` |
| `pip` dependency list | `[dependencies]` in `Cargo.toml` | — |
| `requirements.txt` + monorepo | the **workspace** `Cargo.toml` | top-level `Cargo.toml` |

### Two differences worth internalizing

1. **Errors are values, not exceptions.** A function that can fail returns
   `Result<T, E>` — either `Ok(value)` or `Err(error)`. The compiler *forces*
   the caller to handle it. The `?` operator is "if this is an `Err`, return it
   from my function too" — i.e. propagate-up, the way an uncaught Python
   exception bubbles, but explicit and visible at every call site.

2. **Where tests live.** Rust has two test locations and this repo uses both:
   - **Unit tests live in the *same file* as the code**, inside a
     `#[cfg(test)] mod tests { ... }` block. `#[cfg(test)]` means "only compile
     this when testing", so it adds nothing to release builds. They can reach
     the crate's *private* internals — that's why they're co-located.
     (See `capability/src/lib.rs`, `pdp/src/lib.rs`.)
   - **Integration tests live in a separate `tests/` directory** and may only
     touch the crate's *public* API — exactly like an outside user. This is the
     Python-style "tests in their own files" you're used to.
     (See `agent/tests/enforcement.rs`.)

## The crate map

The project is a Cargo **workspace** (one repo, many crates) declared in the
top-level `Cargo.toml`. Dependencies flow in **one direction only** — that
acyclic shape is the design: trust radiates outward from a tiny core.

```
                      ┌─────────────┐
                      │  manifest   │  root of trust, zero internal deps
                      └──────┬──────┘
                      ┌──────▼──────┐
                      │ capability  │  signed biscuit tokens + attenuation
                      └──────┬──────┘
                ┌────────────┼────────────┐
          ┌─────▼────┐  ┌────▼────┐        │
          │   pdp    │  │   pep   │        │
          │ (decide) │  │(verify) │        │
          └─────┬────┘  └────┬────┘        │
                └─────┬──────┘             │
                ┌─────▼─────┐              │
                │   tools   │  dispatch = verify + decide + execute
                └─────┬─────┘              │
                ┌─────▼──────┐   ┌─────────▼┐   ┌──────────┐
                │   agent    │──▶│  audit   │   │ sandbox  │ (OS-level,
                │(Orchestr.) │   └──────────┘   └──────────┘  later milestone)
                └─────┬──────┘
                ┌─────▼────┐
                │   demo   │  example manifests + call feeds (fixtures)
                └──────────┘
```

`spikes/` is deliberately excluded from the workspace — throwaway de-risk
experiments, not part of the build or CI.

## Crate-by-crate (in dependency order)

### `manifest` — the root of trust
*Python analogy: a tiny pure-data module with one validating dataclass.*

- **`TaskManifest`** (`struct`): the operator-authored declaration of what a task
  may do — `repo_root`, `ttl_seconds`, readable/writable roots, an exec
  allowlist, and a network policy.
- **`validate(&self)`**: a guard-clause method. Rejects zero TTLs, non-absolute
  or `..`-containing paths (path-traversal defense), and a manifest whose repo
  root isn't even readable.
- Has **no internal dependencies** on purpose — it's the trusted seed everything
  else is derived from.

### `capability` — the security heart
*Python analogy: a class hierarchy wrapping a signed token, where the only
"setter" makes permissions strictly smaller.*

- **`RootCapability::mint(manifest, now)`**: validates the manifest and signs its
  permissions into a **biscuit** token (a cryptographic, attenuable token
  format). Think "JWT, but you can hand someone a *narrower* version without the
  signing key."
- **`ChildCapability`** + **`RootCapability::attenuate(...)`**: produce a
  narrowed child by appending a caveat. Every field must be *equal to or smaller
  than* the parent; any attempt to widen returns an error
  (`ReadScopeWidened`, `TtlWidened`, …).
- **`PermissionSet`**: the readable/writable roots, exec allowlist, and network
  policy, with `allows_read` / `allows_write` / `allows_exec` predicates.
- **`VerifiedState`**: the authoritative state recovered *from the signed token
  bytes* — not from the plaintext struct fields. This distinction is load-bearing
  (see PEP below).

### `pep` — Policy **Enforcement** Point ("is this capability authentic?")
*Python analogy: a function that validates a signed token and returns a trusted
view object, raising on tampering/expiry.*

- **`verify(capability, now, actual_binding) -> VerifiedCapability`**: checks the
  biscuit signature chain, expiry, and request-binding, and **recovers the
  permissions from the signed token** via `verify_and_decode`. It returns a
  `VerifiedCapability` whose only accessor is the *token-derived* `permissions()`.
- Why this matters: a `ChildCapability` carries a plaintext `permissions` field
  for convenience. If enforcement trusted that field, a valid signature could
  "launder" a tampered/widened struct past the decision step. The PEP closes
  that by deciding only over token-derived state.

### `pdp` — Policy **Decision** Point ("does this verified scope allow this request?")
*Python analogy: a pure function — input in, Allow/Deny out, no I/O.*

- **`decide(permissions, request) -> Decision`**: a pattern match. Read/write
  allowed if the path is under an allowed root; exec allowed if the binary is on
  the list; network always denied. Returns `Decision::Allow` or
  `Decision::Deny { reason }`.
- It has **no crypto and no side effects** — it can't even be *called* without a
  `PermissionSet`. In the enforcement path, the only way to obtain one is from a
  `VerifiedCapability` (whose permissions are token-derived, via the PEP).
  Together with `dispatch` being the sole authorized entry point, this makes
  *verify-before-decide* an architectural invariant — not a convention to remember.

### `tools` — the tool layer and the single guarded gate
*Python analogy: the module with the actual `read_file` / `exec` implementations,
plus one wrapper that checks authorization before calling them.*

- **`ToolCall`** vs **`ToolRequest`** — two views of one action:
  - `ToolCall` is the *execution* view; it carries the payload (file contents,
    exec args, bytes to send).
  - `ToolRequest` (via `call.to_request()`) is the *authorization* view — just
    the shape the policy needs ("a write to path X"), no payload. The PDP never
    sees the bytes.
- **`dispatch(capability, call, nonce)`**: the **only** authorized entry point —
  `authorize_only` (verify at PEP, decide at PDP), and `execute` only if allowed.
  A denial returns *before any side effect*.
- **`execute(call)`**: performs the raw side effect with **no** check. It's
  `pub` solely so the deliberately-vulnerable `AUTHZ=off` baseline can reach it.

### `agent` — the Orchestrator (trusted code, untrusted driver)
*Python analogy: the main app loop — owns the session, drives a possibly-hostile
model, enforces every action it requests.*

- **`Orchestrator`**: mints the root capability from the manifest, then for each
  tool call the principal emits, attenuates a **single-use, ~5s-TTL,
  request-bound** child and runs it through `dispatch`. Records every mint,
  attenuation, and decision to the audit log.
- **`Principal`** (trait — Python's "interface"/Protocol): an untrusted source of
  tool calls. Two implementations:
  - `ScriptedPrincipal` — replays a fixed list (for tests + the scripted demo).
  - `OpenAiPrincipalClient` — a live model over HTTP.
  Both run through the *same* `run_principal` loop, so tests exercise the exact
  path a live model hits.
- **`AuthzMode`**: `Enforced` (the framework) vs `Bypassed` (ambient authority,
  no checks). The principal's *intent* is identical across both — enforcement is
  the only variable. That's the demo's whole punchline.
- `src/main.rs` is the CLI, with two modes:
  - **Scripted (M1):** `AUTHZ=on|off warden-agent <manifest.json> <calls.json>`
    — replays a fixed tool-call feed. This is the deterministic demo path.
  - **Live (M3):** `BASE_URL=… MODEL=… [API_KEY=…] AUTHZ=on|off warden-agent <manifest.json>`
    — drives a real model via an OpenAI-compatible HTTP endpoint through the
    multi-turn agentic loop. An explicit `calls.json` argument always selects
    scripted mode, even if `BASE_URL` is set, so a stray env var can't silently
    turn a scripted demo into a live run.

### `audit` — tamper-evident log
*Python analogy: an append-only log where each entry hashes the previous one.*

- **`chain_entry`** / **`verify_chain`**: a hash chain (blake3) so any edit to a
  past entry invalidates everything after it. `AuditEvent` enumerates what's
  recorded (root minted, capability attenuated, tool allowed/denied).

### `sandbox` — OS-level containment (later milestone)
*Python analogy: an optional C-extension that's a no-op unless a build flag is on.*

- **`install_linux_containment()`**: gated behind the `linux-containment` Cargo
  **feature** (compile-time flag). Off by default; a defense-in-depth layer
  distinct from the capability logic.

### `demo` — fixtures
- Example manifests and scripted call feeds under `demo/examples/*.json`
  (e.g. `basic-manifest.json`, `clean-calls.json`, `injected-calls.json`).

## End-to-end: one enforced tool call

Trace `Orchestrator::step_enforced` (in `agent/src/lib.rs`) to see every crate
cooperate:

```
Orchestrator::new(manifest)                          [agent]
  └─ RootCapability::mint(manifest, now)             [capability]  validate + sign
  └─ record(RootMinted)                              [audit]

for each tool call from the (untrusted) Principal:
  step_enforced(call):                               [agent]
    1. nonce       = new uuid
    2. request     = call.to_request()               [tools]   strip payload
    3. binding     = request_binding_for(req, nonce) [tools]   hash(tool,args,nonce)
    4. attenuation = { root scope, TTL=5s, binding } narrow only — never widen
    5. child       = root.attenuate(attenuation)     [capability]  append caveat, re-sign
       └─ record(CapabilityAttenuated)               [audit]
    6. dispatch(child, call, nonce):                 [tools]
         ├─ verify(child, now, binding)              [pep]   signature/expiry/binding
         ├─ decide(perms, request)                   [pdp]   scope check → Allow/Deny
         └─ if Allow: execute(call)                  [tools] the real side effect
       └─ record(ToolAllowed | ToolDenied)           [audit]
```

The invariant that makes it safe: **a denial returns before `execute` runs**, so
an out-of-scope action never has any effect — it is structurally impossible, not
merely discouraged.

## Where to start reading

1. `manifest/src/lib.rs` — small, no dependencies, defines the vocabulary.
2. `pdp/src/lib.rs` — `decide` is a pure function; easiest to grok.
3. `tools/src/lib.rs` — see `ToolCall` vs `ToolRequest` and `dispatch`.
4. `agent/src/lib.rs` — `step_enforced` ties everything together.
5. `capability/src/lib.rs` — the deepest crate (crypto + attenuation); read last.
