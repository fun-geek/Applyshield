# ApplyShield Security Model

> **AI prepares. Security validates. The user decides.**

This document says what ApplyShield protects, what it defends against, how each
defence works, and where each one stops. Every claim below points at code and
tests. Where something is **not** built, it says so.

Status legend: **Implemented** (code and tests exist) · **Partly** · **Not built**.

---

## 1. What the program does, and what it never does

ApplyShield helps a job seeker find suitable listings, rejects unsafe or
unsuitable ones, drafts a cover letter, and prepares an application package.

**It never submits anything to an employer.** It makes no network requests at
all (enforced by a test). The final step, `approve`, writes a package to a local
`outbox/` folder and prints the apply link. The user opens the employer's site
and submits it themselves. This removes the largest risk in this kind of tool
(automation acting on the user's behalf against a hostile website) instead of
trying to manage it.

## 2. Assets

| Asset | Why it matters |
| --- | --- |
| Personal data (name, email, phone, education) | Privacy; spam and identity-theft risk |
| The user's decision authority | Nothing is prepared for sending without a deliberate human act |
| The audit log | Integrity of the record of what happened |
| The user's machine | The tool must not become a way into it |

## 3. Trust boundaries

```
 UNTRUSTED                    VERIFIED                      TRUSTED
 ---------                    --------                      -------
 Job listing text, links  --> sanitised + scanned   -->     Evaluation result
 Job feed file                parsed with strict limits
 Edited draft text        --> verify_text()          -->     Approval screen
                                                            User typing the job ID
```

1. Everything in a job listing is **untrusted data**, never instructions.
2. Draft text, whether generated or hand-edited, is verified before use.
3. Only a person typing the job ID at a terminal can authorise an export.

## 4. Threats and defences

| # | Threat | Defence | Where | Status |
| --- | --- | --- | --- | --- |
| T1 | **Prompt / terminal injection.** A listing tells an AI to "ignore previous instructions", or contains ANSI/bidi characters that rewrite the screen | `Untrusted<T>` (no `Display`, hidden `Debug`); `sanitized()` strips escape codes, `\r`, zero-width and bidi-override characters; injection phrases **block drafting**; the drafter never receives the description at all | `domain/untrusted.rs`, `checks/injection.rs`, `drafting.rs` | **Implemented.** Phrase lists can be reworded around; the structural defence (drafter never sees listing text) is the real one. No LLM is wired in yet |
| T2 | **Scam and look-alike listings** | Strict HTTPS-only URL parser (rejects `user@host`, IPs, punycode, local names, odd ports, backslashes, control chars); trust tiers; payment/guarantee phrases **block drafting**; free-email and chat-app contact warns | `checks/url.rs`, `checks/scam.rs` | **Implemented** for the *text* of a listing. It cannot tell whether a page is genuine; "trusted" means "a real platform", not "a real employer" |
| T3 | **Approval bypass.** An AI, script or bug exports without the user, or content changes after approval | `UserConfirmation` only from the exact job ID typed; `ApprovalToken` bound to the SHA-256 of the exact content **and** the destination, expires (max 10 min), consumed by move so it is single-use; export needs an `Authorization` only the gateway can create; `approve` and `purge` refuse unless stdin **and stdout** are a **real terminal** | `approval.rs`, `handoff.rs`, `cli.rs` | **Implemented.** See limits below |
| T4 | **Default-deny regression** | `SecurityPolicy` fields are private; the only public constructor denies; `ExternalSubmit` has no code path | `security.rs`, tests | **Implemented** |
| T5 | **PII leakage** | `Redacted<T>` prints `[REDACTED]`; drafter input has no field for name/email/phone; audit log holds no personal data (tested); phone included only with `--include-phone`; the review screen lists exactly which personal fields are in the package | `domain/sensitive.rs`, `drafting.rs`, `handoff.rs` | **Implemented.** Data at rest is **not encrypted** (file permissions only) |
| T6 | **Memory-unsafe C code** | No `malloc`, no globals, no I/O; explicit lengths; hard size limits; compiled `-Werror` with stack protector and `_FORTIFY_SOURCE`; ASan + UBSan test binary; a pure-Rust reference implementation compared against it on 30,000 random inputs | `c/`, `matching/` | **Implemented.** No continuous fuzzing yet |
| T7 | **Malicious dependency** | **Zero runtime dependencies.** One build-time crate (`cc`, plus its 2 helpers). `cargo audit`, `cargo deny`, Dependabot, committed `Cargo.lock` | `Cargo.toml`, CI | **Implemented** |
| T8 | **Secrets in the repo** | Nothing in the program uses secrets (no API keys exist). `.gitignore` covers keys, `.env`, databases, data directories | `.gitignore` | **Implemented** |
| T9 | **SSRF / unsafe fetching** | The program makes no network requests; a test fails if network code appears | `tests/architecture_tests.rs` | **Not applicable today.** Becomes real if discovery is added |
| T10 | **Audit tampering** | Each entry embeds the SHA-256 of the previous one, numbers must be written canonically; `audit` verifies; the program **refuses to continue** on a broken chain; details are sanitised and length-capped | `audit.rs` | **Implemented.** Someone who can rewrite the *whole* file can rebuild the chain; note the printed head hash to catch that and tail truncation |
| T11 | **Fabricated application content** | `verify_text` rejects technologies not in the profile, "N years of experience" claims, links, email addresses and stray placeholders. It runs on generated **and hand-edited** drafts, at review and approval | `drafting.rs` | **Implemented.** Vocabulary-based: it cannot catch every false claim in free text |
| T12 | **Switch-after-approval** | Approval is bound to the destination; nothing is auto-submitted; `NEXT_STEPS.txt` tells the user to check the address bar | `approval.rs`, `handoff.rs` | **Implemented by design** (no automation to hijack) |

### Limits of T3, stated plainly

- Module privacy is **not** a process boundary. Code inside this crate could
  call the approval functions. Tests check that the drafting module cannot
  reference them, and that `unsafe` exists only in one file, but a future
  contributor could still wire things badly. Review matters.
- "Interactive terminal" is a defence in depth, not a proof of a human. A
  program that allocates a pseudo-terminal can type into it. The stronger
  property is that no code path sends anything anywhere.
- The user is the final control. A user who approves a bad package without
  reading it has defeated the tool. The review screen is designed to make that
  hard: it shows the exact destination, the trust level, every warning, and the
  exact content.

## 5. Security invariants

| | Invariant | Enforced by |
| --- | --- | --- |
| I1 | Nothing is exported without a fresh, explicit approval for that exact content and destination | `approval.rs` unit tests; `tests/security_tests.rs`; e2e `anything_other_than_the_job_id_cancels` |
| I2 | The default policy denies all external actions | `security.rs`, `tests/security_tests.rs` |
| I3 | The drafting layer cannot approve, export, store, or touch the network | `tests/architecture_tests.rs` |
| I4 | Untrusted listing content cannot change permissions or policy | Types (`Untrusted`), `pipeline.rs`, e2e hostile-listing tests |
| I5 | Personal data is minimised and never logged | `Redacted`, `DraftInput`, audit test |
| I6 | No secrets are stored or handled | No secret-handling code exists |
| I7 | CAPTCHAs, MFA and site controls are never touched | The program never contacts a site |
| I8 | Important actions are recorded; a broken log stops the program | `audit.rs`, e2e tamper test |
| I9 | Documentation separates what exists from what is planned | This document |

## 6. Fail-closed rule

When something is unknown, missing, malformed or ambiguous, the answer is
**deny**. Examples in the code: an invalid link blocks drafting; an unreadable
status counts as "new"; a draft that cannot be verified is refused; a damaged
audit log stops approvals; a purge refuses a directory without the marker file;
an unexpected value from the C engine is an error.

## 7. How the pieces fit

```
 jobs file --parse--> Job (all text Untrusted)
                        |
                        v
   pipeline::evaluate:  URL check -> scam scan -> injection scan
                        -> eligibility -> C skill matcher -> score
                        |
              blocked? --+--> cannot draft (reasons shown)
                        |
                        v
   draft: TemplateDrafter(DraftInput only) -> verify -> drafts/<id>.txt
                        |   (user may edit; re-verified every time)
                        v
   review/approve: verify -> build exact package -> show it
                        -> user types job ID -> ApprovalToken
                        -> Gateway::authorize -> Authorization
                        -> audit(Approved) -> export to outbox -> audit(Exported)
```

## 8. Not built (so you are not misled)

- **Automatic job discovery** from job boards or APIs. Jobs come from a file you
  import. Fetching listings needs network code, rate limits, per-site terms of
  service and the SSRF defences in T9.
- **LLM-written drafts.** The `DraftProvider` trait and the verification layer
  are ready for one; only the local template drafter exists.
- **Automatic submission or browser automation.** Deliberately absent.
- **SQLite.** Storage is plain private files: the data is small and this keeps
  the dependency tree empty.
- **Encryption at rest, and OS-keychain integration.**
- **Continuous fuzzing** of the C engine (it has differential and sanitizer tests).
- **Windows file permissions.** On Unix, files are `0600` and directories
  `0700`. On Windows the program relies on the user's profile directory.
- **Homoglyph (look-alike letter) detection** in scam and injection scans. They
  normalise case, spacing, punctuation, invisible characters and fullwidth
  letters, but do not map look-alikes such as Cyrillic `а`.
- **Job title and company text** from a listing is allowed to contain technology
  words in a draft (they are facts about the job, not claims). A hostile company
  name could therefore hide a word from the skill check. The review screen shows
  the whole letter, which is the control.
- **Concurrent runs.** Two `ApplyShield` processes writing the audit log at once
  could fork the chain. This stops the program; it does not let anything through.

## 9. Reporting a vulnerability

See [`SECURITY.md`](../SECURITY.md).
