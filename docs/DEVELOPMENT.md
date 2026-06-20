# Development

## Prerequisites

- Rust 1.88. The repository includes `rust-toolchain.toml`.
- macOS or Linux. The capability-layer enforcement (the structural guarantee) is pure Rust and runs on both. The planned OS-level sandbox (Landlock + seccomp, defense-in-depth) is Linux-only and **not yet implemented** (`sandbox` is a stub).

## Common commands

```sh
cargo fmt --all
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo check --locked -p warden-sandbox --features linux-containment
```

### Demo harness

```sh
make demo-contrast          # one-command: clean + injected under off/on + listener + logs + KEY DIFFERENCES
make demo-clean             # baseline (no injection)
make demo-vuln              # injected + AUTHZ=off (leaks)
make demo-protected         # injected + AUTHZ=on (denies malicious, keeps utility)
make demo-listener          # standalone canary sink on 127.0.0.1:9999 -> sink.log
```

Artifacts go to cwd (or `demo/artifacts/` via helper). See `Makefile`, `demo/src/main.rs`, and `demo/artifacts/demo-results.md` (post-ready excerpt using your run outputs).

## Commit signing

The `main` branch requires signed commits. SSH commit signing is the simplest setup for most contributors:

```sh
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
```

Add the matching public SSH key to GitHub under **Settings > SSH and GPG keys > New SSH signing key**. GitHub web commits and squash merges are signed by GitHub.

## Repository rulesets

Protections for the `main` branch (and future additional rules for tags or other branches) are defined as **repository rulesets** and stored in source control.

- Rule definitions: `.github/rulesets/main.json` (and additional `*.json` files as needed)
- Apply / sync script: `.github/scripts/apply-rulesets.sh`

To update rules after editing a JSON definition:

```sh
./.github/scripts/apply-rulesets.sh
```

The "main" ruleset currently enforces (matching and extending the previous branch protection intent):

- Require signed commits (`required_signatures`)
- Require linear history (no merge commits; forces squash or rebase merges)
- Require a pull request before merging to `main`
- Allowed merge methods on PRs: squash, rebase (no direct merge commits)
- Require all conversations on the PR to be resolved before merge
- Require status checks to pass (the "Rust" job from CI, with strict "up-to-date" policy)
- Block force pushes (`non_fast_forward`)
- Block deletions of the protected ref

Bypass is not granted to admins by default (enforced for everyone).

**Live configuration:** https://github.com/senthil1216/attenuate-agent/settings/rules

**Note:** Classic branch protection is not used; rulesets are the source of truth for these policies.

## Current state (summary)

See the status line at the top of `README.md` and `docs/NEXT_STEPS.md` for the latest milestone status.

High-level:
- Capability engine (P0–P2), multi-turn `Principal` + `Orchestrator::run_principal` loop (P3.5), and demo harness are complete.
- `sandbox` crate remains a no-op stub (Linux Landlock + seccomp containment is planned as defense-in-depth only).
