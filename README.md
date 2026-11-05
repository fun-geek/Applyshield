
# ApplyShield

A security-first AI-powered job search and application copilot built with Rust and C.

## Overview

ApplyShield aims to simplify job discovery, eligibility checking, job matching, and application preparation while keeping the user in control.

Its core principle:

AI prepares. Security validates. The user decides.

## Current Features

- Rust-based command-line application
- Help, version, and status commands
- Default-deny submission policy
- Explicit approval requirement
- Security policy validation
- Automated unit tests

## Technology Stack

- Rust: Application core and CLI
- C: Planned deterministic matching engine
- SQLite: Planned local storage
- AI/LLM: Planned job analysis and drafting

## Project Structure

```text
applyshield/
├── Cargo.toml
├── Cargo.lock
├── README.md
├── .gitignore
└── src/
    ├── main.rs
    └── security.rs
```

## Getting Started

### Prerequisites

- Rust
- Cargo
- Windows or another supported development environment

### Run the application

```bash
cargo run -- help
cargo run -- version
cargo run -- status
```

### Run tests

```bash
cargo test
```

## Security Philosophy

- External submission is disabled by default.
- Explicit user approval is required.
- AI components must not independently authorize submissions.
- Sensitive information should be minimized.
- Untrusted job content must never override security policies.

## Development Status

Milestone 1: Foundation

- [x] Rust project initialization
- [x] CLI commands
- [x] Initial security policy
- [x] Unit tests

Future milestones will introduce domain models, matching algorithms, job discovery, AI assistance, and local storage.

## License

To be decided.
