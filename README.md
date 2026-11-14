# ApplyShield
AI prepares. Security validates. The user decides.
A security-first job search and application copilot, written in Rust with a C matching engine.

> **AI prepares. Security validates. The user decides.**

ApplyShield ranks job listings against your profile, **rejects unsafe or unsuitable ones with reasons**, drafts a cover letter, checks that draft is truthful, and prepares an application package. You review it, type the job ID to approve, and **you submit it yourself**. ApplyShield never sends anything to an employer and makes no network requests.

## What it does

| Step | Command | What happens |
| --- | --- | --- |
| Set up | `init`, `import-profile`, `import-jobs` | Strictly validated input, stored privately |
| Rank | `jobs` | Score out of 100; unsafe/ineligible jobs are marked `BLOCKED` |
| Understand | `show <id>` | Eligibility, score breakdown, safety flags, and exactly why a job is blocked |
| Draft | `draft <id>` | A cover letter built only from facts in your profile |
| Check | `review <id>` | The exact package that would be exported; nothing is exported |
| Approve | `approve <id>` | You type the job ID; the package goes to your local outbox |
| Verify | `audit` | Checks the tamper-evident log |
| Erase | `purge` | Deletes your profile, jobs, drafts and outbox |

## Quick start

You need Rust (stable) and a C compiler (on Windows, the MSVC build tools that Rust already requires).

```bash
cargo build --release

# Copy the examples and edit them. Name them my-*.txt so git ignores them.
cp examples/profile.example.txt my-profile.txt
cp examples/jobs.example.txt   my-jobs.txt

cargo run --release -- init
cargo run --release -- import-profile my-profile.txt
cargo run --release -- import-jobs my-jobs.txt
cargo run --release -- jobs
cargo run --release -- show demo-good
cargo run --release -- draft demo-good
cargo run --release -- review demo-good
cargo run --release -- approve demo-good     # run this one in a real terminal
```

Data is kept in `~/.applyshield` (`%USERPROFILE%\.applyshield` on Windows). Override with `--data-dir <DIR>` or the `APPLYSHIELD_HOME` environment variable.

The example jobs file contains seven **fictional** listings that demonstrate the checks: one good match, one with an unfamiliar domain and a free-email recruiter, and five that are blocked (needs 5+ years, asks for a deposit, tries to prompt-inject an AI, has a link that hides its real host, wrong graduation batch).

### File formats

Profile (`key = value`):

```text
full_name = Asha Verma
email = asha.verma@example.org
phone = +91 98765 43210          # optional
degree = B.Tech
field = CSE (AI & ML)
graduation_year = 2028
skills = rust, c, sql, python    # only list skills you really have
target_roles = Software Developer, AI Engineer
locations = Remote, Bengaluru
```

Jobs (separated by a line containing only `---`):

```text
id: job-1
title: Software Developer Intern
company: Acme
location: Remote
url: https://boards.greenhouse.io/acme/jobs/1
description: Everything after this line, including more lines, is the description.
```

Optional: put extra trusted job-site domains, one per line, in `<data dir>/trusted_domains.txt`.

## How safety works

- **Listings are untrusted data.** Text is sanitised before it reaches your screen (no terminal escape codes, no invisible or direction-flipping characters). Text aimed at AI tools blocks the job.
- **Links are validated.** HTTPS only; no `user@host` tricks, raw IPs, look-alike (punycode) domains or local names. Unknown domains are flagged.
- **Scam signals are caught.** Fee and deposit requests, "no interview" promises and similar block drafting; off-platform contact and free email addresses warn.
- **Eligibility is explicit.** Experience requirements, graduation batch, experience-certificate requirements and location, each with a readable reason.
- **Drafts are verified, including your edits.** A draft that claims a skill not in your profile, invents years of experience, or contains a link or email address is refused.
- **Approval can't be faked.** It needs the exact job ID typed, is bound to the exact content and destination, expires, and is refused unless input and output are both a real terminal. A script piping `yes` does nothing.
- **Everything is logged** in a hash-chained audit log that holds no personal data. A broken chain stops the program.
- **Least data.** The cover-letter writer never sees your name, email, phone, the job description, or the link. Your phone number is included only with `--include-phone`.

The full threat model, with the limits of each defence, is in [`docs/security-model.md`](docs/security-model.md).

## Project structure

```text
applyshield/
├── Cargo.toml, build.rs, deny.toml
├── c/                         C matching engine + sanitizer test
│   ├── matcher.c, matcher.h
│   └── test_matcher.c
├── src/
│   ├── main.rs                thin binary
│   ├── cli.rs                 commands
│   ├── approval.rs            approval token + gateway
│   ├── security.rs            default-deny policy
│   ├── audit.rs               hash-chained audit log
│   ├── pipeline.rs            runs every check on a job
│   ├── checks/                url, scam, injection, eligibility, text
│   ├── matching/              safe wrapper, FFI (only `unsafe`), Rust reference
│   ├── domain/                Untrusted, Redacted, models
│   ├── drafting.rs            drafter + truthfulness check
│   ├── inputs.rs              strict parsers
│   ├── store.rs, handoff.rs   private storage, outbox export
│   └── hash.rs                SHA-256
├── tests/                     security, domain, architecture, end-to-end
├── examples/                  fictional profile and jobs
├── docs/security-model.md
└── .github/                   CI and Dependabot
```

## Testing

```bash
cargo test                       # unit, integration, architecture and end-to-end tests
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check

# C engine under AddressSanitizer + UBSan
cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined \
   -fno-sanitize-recover=all c/matcher.c c/test_matcher.c -o test_matcher && ./test_matcher

cargo install --locked cargo-audit cargo-deny
cargo audit && cargo deny check
```

CI runs all of these. There are 255 tests, including regression tests for issues found in an independent security review.

## Limitations (read these)

- **Jobs come from a file you import.** There is no automatic discovery from job boards.
- **Drafts come from a local template.** No LLM is connected yet. The verification layer is ready for one.
- **It does not submit applications.** By design.
- **Your data is not encrypted at rest.** It is stored in files only you can read (Unix) or in your user profile (Windows).
- **Link checks look at the text of a link,** not the page behind it. "Known job platform" means the site is real, not that the employer is.
- **Scam and injection checks are phrase-based.** They handle case, spacing, punctuation, invisible characters and fullwidth letters, but not look-alike letters from other alphabets, and not every clever rewording. Read what you approve.
- **Eligibility rules are heuristics** over free text. When unsure they say "needs review".

## Status

- [x] Milestone 1: foundation
- [x] Milestone 2: domain models
- [x] Milestone 3: C matching engine, differential and sanitizer tests
- [x] Milestone 4: link validation, scam and injection checks, eligibility, scoring
- [x] Milestone 5: drafting with truthfulness verification
- [x] Milestone 6: approval gateway, audit log
- [x] Milestone 7: private local storage, outbox hand-off
- [ ] Live job discovery · LLM-assisted drafting · encryption at rest · fuzzing

## Security

Report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

## License

To be decided.
