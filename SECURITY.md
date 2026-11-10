# Security Policy

ApplyShield is a security-first project. Thank you for helping keep it safe.

## Supported versions

The project is in early development (Milestone 1). Only the latest commit on
`main` is supported.

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Use GitHub's private reporting instead:
**Security tab → "Report a vulnerability"** on this repository.

Include what you found, the steps to reproduce it, and the impact you expect.
You can expect an acknowledgement within a few days. This is a personal
project, so please be patient.

## What counts as a security issue here

- Any path that lets an external action happen without fresh, explicit user
  approval.
- Any way for untrusted content (job listings, web pages, LLM output) to change
  permissions or policy.
- Any leak of personal data or secrets (logs, database, network, repo).
- Any bypass of the default-deny policy.

See [`docs/security-model.md`](docs/security-model.md) for the full threat
model and invariants.

## Please don't commit secrets

Never commit API keys, passwords, tokens, or personal data. If you think a
secret was committed by mistake, report it as above and rotate the secret.
