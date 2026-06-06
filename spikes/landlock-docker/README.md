# Spike B — Landlock + seccomp containment in Docker (M0)

**Question this answers:** do Landlock (filesystem) and seccomp (syscall)
actually deny a disallowed `open()` / `socket()` *inside our container*, before
we invest in the Phase 4 `sandbox` crate?

**Why it matters:** the README promises OS-level containment as defense in depth
on Linux. You're developing on macOS, so the real enforcement only exists inside
a Linux container. This proves the mechanism bites there.

## Run

```sh
./run.sh
```

Requires Docker. On macOS, Docker Desktop's LinuxKit VM provides a recent
kernel; Landlock needs **kernel ≥ 5.13**.

What the program asserts, after applying the rulesets to itself:
- in-scope read of `/allowed/ok.txt` → allowed
- out-of-scope read of `/etc/hostname` → **EACCES** (Landlock)
- `TcpStream::connect` → **refused** (seccomp blocks `socket()`)

## The gotcha to expect

Docker's **default** seccomp profile can block the `seccomp()` syscall itself —
so the app may not even be able to *install* its own filter. `run.sh` handles
this: it first tries the default profile, and if that fails, re-runs with
`--security-opt seccomp=unconfined`.

Important nuance: `seccomp=unconfined` only relaxes Docker's **outer** profile.
The app still applies **its own** Landlock ruleset and seccomp filter — that
inner containment is exactly what we're validating. The production `sandbox`
crate will ship a tailored seccomp profile so this relaxation isn't needed.

## Outcomes

- **SPIKE PASS** → Landlock + seccomp contain inside the container. Phase 4 has a
  real foundation; build the `sandbox` crate against this same mechanism.
- **SPIKE FAIL** at Landlock → kernel too old / Landlock disabled in the VM;
  check `docker run --rm rust:1.88-slim grep -i landlock /boot/config-* || true`
  and the Docker Desktop kernel version.
- **SPIKE FAIL** at seccomp only → almost always the outer-profile gotcha above;
  re-run with the unconfined outer profile.

## Crate-version note

Pinned to `landlock = 0.4`, `seccompiler = 0.4`, `libc = 0.2`. If a minor API
drift breaks the build, that's expected for a throwaway spike — adjust the two
ruleset-builder calls and move on; the point is the kernel behaviour, not the
bindings.
