# Repository Guidelines

## Project Structure & Module Organization

This Cargo workspace has three Rust crates. `crates/protocol-simulation` is the HTTP API for rules, instance state, PCAP records, and Agent integration. `crates/protocol-simulation-engine` runs simulations in workload containers. Put shared models in `crates/protocol-simulation-common`. The Vue 3 and TypeScript console lives in `frontend/src`; static files belong in `frontend/public`. Docker image helpers are in `scripts/`. Rust unit tests are colocated with code in `#[cfg(test)]` modules.

## Build, Test, and Development Commands

- `cargo run -p protocol-simulation` starts the API on port 8080 by default.
- `cargo run -p protocol-simulation-engine` starts the simulation engine.
- `cargo test --workspace` runs all Rust tests.
- `cargo fmt --all -- --check` checks Rust formatting; `cargo clippy --workspace --all-targets` runs lint checks.
- `pnpm -C frontend install` installs UI dependencies. Use `dev` for Vite development, `build` for a production build, and `type-check` for Vue/TypeScript validation: for example, `pnpm -C frontend dev`.
- `pnpm -C frontend lint` runs ESLint with fixes; `pnpm -C frontend format` applies Prettier to `src/`.
- `./scripts/build-image.sh [tag]` and `./scripts/build-engine-image.sh [tag]` build the API/UI and engine images. Without a tag, each script reads its crate version.

## Coding Style & Naming Conventions

Use standard `rustfmt` output and four-space indentation for Rust. Name modules, functions, and tests in `snake_case`; test names should describe observable behavior. Use PascalCase for Vue component filenames and camelCase for TypeScript symbols. Follow the configured ESLint and Prettier rules. Keep cross-service types in the common crate and preserve existing `camelCase` serialization contracts.

## Testing Guidelines

Add focused unit tests beside changed Rust code and run relevant crate tests plus `cargo test --workspace`. For frontend changes, run `pnpm -C frontend build` and `pnpm -C frontend type-check`. There is no frontend test runner or enforced coverage threshold; add regression coverage where supported.

## Commit & Pull Request Guidelines

Follow the repository's Conventional Commit pattern: `feat:`, `fix:`, `chore:`, or `refactor:`, optionally scoped, such as `fix(simulation): prevent duplicate deployment`. Pull requests should summarize behavior changes, link related issues when available, list validation commands, and include screenshots for visible UI changes.

## Security & Configuration

Configure services through environment variables; local API data defaults to `/data`. Runtime descriptors and instance credentials are injected by Veydeck and must not be committed. Keep tokens, SQLite files, `target/`, `frontend/node_modules/`, and generated `frontend/dist/` artifacts out of version control.

## Communication

- Please respond in chinese by default.
