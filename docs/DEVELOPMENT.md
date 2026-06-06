# Development

## Prerequisites

- Rust 1.88. The repository includes `rust-toolchain.toml`.
- Linux for enforced sandbox containment. macOS is development-only and does not provide the final containment guarantee.

## Common commands

```sh
cargo fmt --all
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo check --locked -p warden-sandbox --features linux-containment
```

### Demo harness (P3 showcase)

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

## Current implementation milestone

The repository is scaffolded as a Rust workspace with crate boundaries matching the design in `README.md`.

The first implemented slice is the P0 capability boundary:

- `manifest` defines the trusted task manifest shape.
- `capability` defines root and child capabilities plus append-only attenuation.
- property tests reject read-scope widening and accept read-scope narrowing.

The capability crate currently uses an internal permission model to pin down the API and tests. The next milestone is to replace the internal token representation with `biscuit-auth` while preserving the same append-only public API.
