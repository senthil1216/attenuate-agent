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

## Commit signing

The `main` branch requires signed commits. SSH commit signing is the simplest setup for most contributors:

```sh
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
```

Add the matching public SSH key to GitHub under **Settings > SSH and GPG keys > New SSH signing key**. GitHub web commits and squash merges are signed by GitHub.

## Current implementation milestone

The repository is scaffolded as a Rust workspace with crate boundaries matching the design in `README.md`.

The first implemented slice is the P0 capability boundary:

- `manifest` defines the trusted task manifest shape.
- `capability` defines root and child capabilities plus append-only attenuation.
- property tests reject read-scope widening and accept read-scope narrowing.

The capability crate currently uses an internal permission model to pin down the API and tests. The next milestone is to replace the internal token representation with `biscuit-auth` while preserving the same append-only public API.
