//! End-to-end tests: the whole workflow through the real CLI code, using the
//! shipped example files. Includes a test that runs the compiled binary.

use applyshield::cli::{self, Ctx, Io};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

const PROFILE: &str = include_str!("../examples/profile.example.txt");
const JOBS: &str = include_str!("../examples/jobs.example.txt");
const NOW: u64 = 1_800_000_000;

struct Env {
    dir: PathBuf,
}

struct Out {
    code: i32,
    out: String,
    err: String,
}

impl Env {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("applyshield-e2e-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        Self { dir }
    }

    fn data(&self) -> PathBuf {
        self.dir.join("data")
    }

    fn file(&self, name: &str, content: &str) -> String {
        fs::create_dir_all(&self.dir).unwrap();
        let p = self.dir.join(name);
        fs::write(&p, content).unwrap();
        p.to_string_lossy().into_owned()
    }

    fn run_with(&self, args: &[&str], interactive: bool, stdin: &str) -> Out {
        let ctx = Ctx {
            data_dir: self.data(),
            interactive,
            now: NOW,
        };
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let mut input = Cursor::new(stdin.as_bytes().to_vec());
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = cli::run(
            &args,
            &ctx,
            &mut Io {
                stdin: &mut input,
                out: &mut out,
                err: &mut err,
            },
        );
        Out {
            code,
            out: String::from_utf8(out).unwrap(),
            err: String::from_utf8(err).unwrap(),
        }
    }

    fn run(&self, args: &[&str]) -> Out {
        self.run_with(args, true, "")
    }

    /// init + import the example profile and jobs.
    fn setup(&self) {
        assert_eq!(self.run(&["init"]).code, 0);
        let p = self.file("profile.txt", PROFILE);
        let j = self.file("jobs.txt", JOBS);
        assert_eq!(self.run(&["import-profile", &p]).code, 0);
        assert_eq!(self.run(&["import-jobs", &j]).code, 0);
    }

    fn outbox(&self, id: &str) -> PathBuf {
        self.data()
            .join("outbox")
            .join(format!("job-{}", id.to_ascii_lowercase()))
    }

    fn draft_path(&self, id: &str) -> PathBuf {
        self.data()
            .join("drafts")
            .join(format!("job-{}.txt", id.to_ascii_lowercase()))
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn exists(p: &Path) -> bool {
    p.exists()
}

// ---------------------------------------------------------------- happy path

#[test]
fn full_workflow_from_import_to_approved_package() {
    let env = Env::new("happy");
    env.setup();

    let jobs = env.run(&["jobs"]);
    assert_eq!(jobs.code, 0);
    let line = |id: &str| {
        jobs.out
            .lines()
            .find(|l| l.starts_with(id))
            .unwrap_or_else(|| panic!("no row for {id}"))
            .to_string()
    };
    assert!(
        line("demo-good").contains("eligible"),
        "{}",
        line("demo-good")
    );
    assert!(!line("demo-good").contains("BLOCKED"));
    for blocked in [
        "demo-senior",
        "demo-fee-scam",
        "demo-injection",
        "demo-bad-link",
        "demo-wrong-batch",
    ] {
        assert!(
            line(blocked).contains("BLOCKED"),
            "{blocked}: {}",
            line(blocked)
        );
    }
    // The good job is ranked above the unknown-domain one, and blocked ones come last.
    let pos = |id: &str| jobs.out.find(id).unwrap();
    assert!(pos("demo-good") < pos("demo-ai-intern"));
    assert!(pos("demo-ai-intern") < pos("demo-senior"));
    assert!(
        line("demo-ai-intern").contains('!'),
        "unknown domain + free email should be flagged"
    );

    let show = env.run(&["show", "demo-good"]);
    assert_eq!(show.code, 0);
    assert!(
        show.out
            .contains("Matched skills: rust, c, sql, linux, git"),
        "{}",
        show.out
    );
    assert!(show.out.contains("Can be drafted: yes"));

    let draft = env.run(&["draft", "demo-good"]);
    assert_eq!(draft.code, 0, "{}{}", draft.out, draft.err);
    assert!(exists(&env.draft_path("demo-good")));

    let review = env.run(&["review", "demo-good"]);
    assert_eq!(review.code, 0, "{}{}", review.out, review.err);
    assert!(
        review
            .out
            .contains("https://boards.greenhouse.io/northwind/jobs/1001")
    );
    assert!(
        review
            .out
            .contains("Personal data in this package: full name, email address")
    );
    assert!(review.out.contains("Asha Verma"));
    assert!(
        !review.out.contains("98765"),
        "phone must not be included by default"
    );
    assert!(!exists(&env.outbox("demo-good")), "review must not export");

    let approve = env.run_with(&["approve", "demo-good"], true, "demo-good\n");
    assert_eq!(approve.code, 0, "{}{}", approve.out, approve.err);
    assert!(approve.out.contains("Nothing was sent"));

    let package = fs::read_to_string(env.outbox("demo-good").join("application.txt")).unwrap();
    assert!(package.contains("Apply at: https://boards.greenhouse.io/northwind/jobs/1001"));
    assert!(package.contains("Dear Hiring Team,"));
    assert!(package.contains("rust, c, sql, linux, and git"));
    assert!(!package.contains("98765"));
    assert!(exists(&env.outbox("demo-good").join("NEXT_STEPS.txt")));

    // The jobs list now shows the status.
    assert!(
        env.run(&["jobs"])
            .out
            .lines()
            .find(|l| l.starts_with("demo-good"))
            .unwrap()
            .contains("exported")
    );

    // The audit log recorded the whole story and its chain is intact.
    let audit = env.run(&["audit", "--show"]);
    assert_eq!(audit.code, 0, "{}", audit.err);
    for event in [
        "profile_imported",
        "jobs_imported",
        "drafted",
        "approved",
        "exported",
    ] {
        assert!(
            audit.out.contains(event),
            "audit missing {event}:\n{}",
            audit.out
        );
    }
    // No personal data in the audit log.
    let raw = fs::read_to_string(env.data().join("audit.log")).unwrap();
    assert!(!raw.contains("Asha") && !raw.contains("example.org") && !raw.contains("98765"));
}

#[test]
fn include_phone_adds_the_phone_only_when_asked() {
    let env = Env::new("phone");
    env.setup();
    assert_eq!(env.run(&["draft", "demo-good"]).code, 0);
    let r = env.run(&["review", "demo-good", "--include-phone"]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(r.out.contains("Phone: +91 98765 43210"));
    assert!(r.out.contains("full name, email address, phone number"));
    assert!(!env.run(&["review", "demo-good"]).out.contains("98765"));
}

#[test]
fn include_phone_without_a_phone_in_the_profile_is_an_error() {
    let env = Env::new("nophone");
    assert_eq!(env.run(&["init"]).code, 0);
    let p = env.file("p.txt", &PROFILE.replace("phone = +91 98765 43210\n", ""));
    let j = env.file("j.txt", JOBS);
    assert_eq!(env.run(&["import-profile", &p]).code, 0);
    assert_eq!(env.run(&["import-jobs", &j]).code, 0);
    assert_eq!(env.run(&["draft", "demo-good"]).code, 0);
    let r = env.run(&["review", "demo-good", "--include-phone"]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("no phone number"));
}

// ------------------------------------------------------ approval cannot be faked

#[test]
fn approval_is_refused_when_input_is_not_a_terminal() {
    let env = Env::new("noninteractive");
    env.setup();
    assert_eq!(env.run(&["draft", "demo-good"]).code, 0);
    // Even the exactly-right answer on piped input does nothing.
    let r = env.run_with(&["approve", "demo-good"], false, "demo-good\n");
    assert_eq!(r.code, 3);
    assert!(r.err.contains("interactive terminal"));
    assert!(!exists(&env.outbox("demo-good")));
    assert!(
        env.run(&["audit", "--show"])
            .out
            .contains("approval_denied")
    );
}

#[test]
fn anything_other_than_the_job_id_cancels() {
    for answer in [
        "y\n",
        "yes\n",
        "\n",
        "",
        "DEMO-GOOD\n",
        "demo-ai-intern\n",
        "demo-good extra\n",
    ] {
        let env = Env::new("cancel");
        env.setup();
        assert_eq!(env.run(&["draft", "demo-good"]).code, 0);
        let r = env.run_with(&["approve", "demo-good"], true, answer);
        assert_eq!(r.code, 1, "answer {answer:?}: {}{}", r.out, r.err);
        assert!(r.out.contains("Cancelled"));
        assert!(
            !exists(&env.outbox("demo-good")),
            "exported on answer {answer:?}"
        );
        assert!(
            env.run(&["audit", "--show"])
                .out
                .contains("approval_declined")
        );
    }
}

#[test]
fn approving_without_a_draft_is_refused() {
    let env = Env::new("nodraft");
    env.setup();
    let r = env.run_with(&["approve", "demo-good"], true, "demo-good\n");
    assert_eq!(r.code, 1);
    assert!(r.err.contains("no draft"));
    assert!(!exists(&env.outbox("demo-good")));
}

// ------------------------------------------------------------ blocked listings

#[test]
fn blocked_jobs_cannot_be_drafted_reviewed_or_approved() {
    let env = Env::new("blocked");
    env.setup();
    for id in [
        "demo-senior",
        "demo-fee-scam",
        "demo-injection",
        "demo-bad-link",
        "demo-wrong-batch",
    ] {
        let d = env.run(&["draft", id]);
        assert_eq!(d.code, 1, "{id} was drafted: {}", d.out);
        assert!(d.err.contains("Refusing to draft"), "{id}: {}", d.err);
        assert!(!exists(&env.draft_path(id)));
        assert_eq!(env.run(&["review", id]).code, 1, "{id} reviewed");
        let a = env.run_with(&["approve", id], true, &format!("{id}\n"));
        assert_ne!(a.code, 0, "{id} approved");
        assert!(!exists(&env.outbox(id)));
    }
}

#[test]
fn show_explains_why_a_job_is_blocked() {
    let env = Env::new("why");
    env.setup();
    let s = env.run(&["show", "demo-fee-scam"]).out;
    assert!(s.contains("Can be drafted: NO"));
    assert!(s.contains("possible scam"));
    let s = env.run(&["show", "demo-injection"]).out;
    assert!(s.contains("prompt injection"));
    let s = env.run(&["show", "demo-bad-link"]).out;
    assert!(s.contains("UNSAFE LINK") && s.contains("hides its real host"));
    let s = env.run(&["show", "demo-senior"]).out;
    assert!(s.contains("Requires prior work experience"));
    let s = env.run(&["show", "demo-wrong-batch"]).out;
    assert!(s.contains("Graduation year does not match"));
}

#[test]
fn a_job_that_turns_bad_after_drafting_cannot_be_approved() {
    let env = Env::new("turnsbad");
    env.setup();
    assert_eq!(env.run(&["draft", "demo-good"]).code, 0);
    // The feed is re-imported and the same job now asks for a fee.
    let tainted = JOBS.replace(
        "Open to the 2028 batch.",
        "Pay a refundable security deposit to confirm.",
    );
    let j = env.file("tainted.txt", &tainted);
    assert_eq!(env.run(&["import-jobs", &j]).code, 0);
    let r = env.run_with(&["approve", "demo-good"], true, "demo-good\n");
    assert_eq!(r.code, 1);
    assert!(r.err.contains("blocked"));
    assert!(!exists(&env.outbox("demo-good")));
}

// ---------------------------------------------------------- edited drafts

fn edited_draft_is_rejected(name: &str, extra: &str, expect: &str) {
    let env = Env::new(name);
    env.setup();
    assert_eq!(env.run(&["draft", "demo-good"]).code, 0);
    let path = env.draft_path("demo-good");
    let text = fs::read_to_string(&path).unwrap();
    fs::write(&path, format!("{text}\n{extra}\n")).unwrap();

    let review = env.run(&["review", "demo-good"]);
    assert_eq!(review.code, 1, "review accepted a bad edit: {}", review.out);
    assert!(
        review.err.contains(expect),
        "expected {expect:?} in: {}",
        review.err
    );

    let approve = env.run_with(&["approve", "demo-good"], true, "demo-good\n");
    assert_eq!(approve.code, 1);
    assert!(!exists(&env.outbox("demo-good")));
}

#[test]
fn an_edit_that_claims_an_unlisted_skill_is_rejected() {
    edited_draft_is_rejected(
        "edit-skill",
        "I am an expert in Kubernetes and Haskell.",
        "kubernetes",
    );
}

#[test]
fn an_edit_that_invents_experience_is_rejected() {
    edited_draft_is_rejected(
        "edit-exp",
        "I have 4 years of experience.",
        "years of experience",
    );
}

#[test]
fn an_edit_that_adds_a_link_is_rejected() {
    edited_draft_is_rejected("edit-link", "Portfolio: https://evil.example.org/x", "link");
}

#[test]
fn an_edit_that_adds_an_email_address_is_rejected() {
    edited_draft_is_rejected("edit-mail", "Reply to attacker@evil.org", "email address");
}

#[test]
fn an_edit_with_terminal_escape_codes_is_rejected() {
    edited_draft_is_rejected("edit-esc", "hello \u{1b}[2J", "control characters");
}

#[test]
fn an_edit_that_adds_a_skill_the_user_really_has_is_accepted() {
    let env = Env::new("edit-ok");
    env.setup();
    assert_eq!(env.run(&["draft", "demo-good"]).code, 0);
    let path = env.draft_path("demo-good");
    let text = fs::read_to_string(&path).unwrap();
    fs::write(
        &path,
        format!("{text}\nI also enjoy working with Python.\n"),
    )
    .unwrap();
    assert_eq!(env.run(&["review", "demo-good"]).code, 0);
}

#[test]
fn redrafting_needs_force_so_edits_are_not_lost() {
    let env = Env::new("force");
    env.setup();
    assert_eq!(env.run(&["draft", "demo-good"]).code, 0);
    let again = env.run(&["draft", "demo-good"]);
    assert_eq!(again.code, 1);
    assert!(again.err.contains("--force"));
    assert_eq!(env.run(&["draft", "demo-good", "--force"]).code, 0);
}

// ---------------------------------------------------------- audit integrity

#[test]
fn a_tampered_audit_log_is_detected_and_blocks_further_actions() {
    let env = Env::new("tamper");
    env.setup();
    assert_eq!(env.run(&["draft", "demo-good"]).code, 0);
    let log = env.data().join("audit.log");
    let text = fs::read_to_string(&log).unwrap();
    fs::write(&log, text.replacen("drafted", "exported", 1)).unwrap();

    let a = env.run(&["audit"]);
    assert_eq!(a.code, 1);
    assert!(a.err.contains("AUDIT LOG PROBLEM"));
    assert!(env.run(&["status"]).out.contains("PROBLEM"));

    // Fail closed: with a broken log, approval cannot proceed.
    let r = env.run_with(&["approve", "demo-good"], true, "demo-good\n");
    assert_ne!(r.code, 0);
    assert!(!exists(&env.outbox("demo-good")));
}

// ------------------------------------------------------------------- purge

#[test]
fn purge_requires_a_terminal_and_the_word_delete() {
    let env = Env::new("purge");
    env.setup();
    assert_eq!(env.run(&["draft", "demo-good"]).code, 0);

    let r = env.run_with(&["purge"], false, "DELETE\n");
    assert_eq!(r.code, 3);
    assert!(exists(&env.data().join("profile.txt")));

    let r = env.run_with(&["purge"], true, "delete\n");
    assert_eq!(r.code, 1);
    assert!(exists(&env.data().join("profile.txt")));

    let r = env.run_with(&["purge"], true, "DELETE\n");
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert!(!exists(&env.data().join("profile.txt")));
    assert!(!exists(&env.data().join("jobs.txt")));
    assert!(!exists(&env.draft_path("demo-good")));
    // The audit log survives, intact, and records the purge.
    let a = env.run(&["audit", "--show"]);
    assert_eq!(a.code, 0);
    assert!(a.out.contains("purged"));
}

// ------------------------------------------------------- hostile input

#[test]
fn hostile_listing_text_never_reaches_the_terminal_raw() {
    let env = Env::new("hostile");
    assert_eq!(env.run(&["init"]).code, 0);
    let p = env.file("p.txt", PROFILE);
    let hostile = "id: evil\n\
        title: Dev\u{1b}[2J\u{1b}[H FAKE: all clear\u{202E}\n\
        company: Acme\u{1b}]0;pwned\u{7}\n\
        location: Remote\r\n\
        url: https://boards.greenhouse.io/acme/jobs/1\n\
        description: Rust job\u{1b}[31m\u{8}\u{8}\u{8}\r overwrite\u{9b}0m\n";
    let j = env.file("j.txt", hostile);
    assert_eq!(env.run(&["import-profile", &p]).code, 0);
    assert_eq!(env.run(&["import-jobs", &j]).code, 0);
    for args in [vec!["jobs"], vec!["show", "evil"]] {
        let r = env.run(&args);
        for out in [&r.out, &r.err] {
            for bad in ['\u{1b}', '\u{7}', '\u{8}', '\r', '\u{9b}', '\u{202E}'] {
                assert!(!out.contains(bad), "{args:?} leaked {bad:?}");
            }
        }
    }
}

#[test]
fn dangerous_arguments_are_rejected_cleanly() {
    let env = Env::new("args");
    env.setup();
    for id in ["../x", "a b", "a;b", "", "..", "a/b", "\u{1b}[2J"] {
        let r = env.run(&["draft", id]);
        assert_ne!(r.code, 0, "accepted id {id:?}");
        assert!(!r.err.contains('\u{1b}'));
    }
    assert_eq!(env.run(&["draft"]).code, 1);
    assert_eq!(env.run(&["nonsense\u{1b}[2J"]).code, 2);
    assert!(!env.run(&["nonsense\u{1b}[2J"]).err.contains('\u{1b}'));
}

#[test]
fn invalid_imports_are_rejected_and_store_nothing() {
    let env = Env::new("badimport");
    assert_eq!(env.run(&["init"]).code, 0);
    let bad = env.file("bad.txt", "full_name = X\nemail = not-an-email\n");
    let r = env.run(&["import-profile", &bad]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("rejected"));
    assert!(!exists(&env.data().join("profile.txt")));

    let badjobs = env.file("badjobs.txt", "id: a\nsalary: 5\n");
    assert_eq!(env.run(&["import-jobs", &badjobs]).code, 1);
    assert!(!exists(&env.data().join("jobs.txt")));
    assert_eq!(
        env.run(&["import-profile", "/definitely/not/here.txt"])
            .code,
        1
    );
}

// --------------------------------------------------------------- basics

#[test]
fn commands_before_init_explain_what_to_do() {
    let env = Env::new("noinit");
    let r = env.run(&["jobs"]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("applyshield init"));
}

#[test]
fn status_reports_default_deny() {
    let env = Env::new("status");
    let r = env.run(&["status"]);
    assert_eq!(r.code, 0);
    assert!(r.out.contains("Submission enabled: false"));
    assert!(r.out.contains("Explicit approval required: true"));
    assert!(r.out.contains("Security: Default-deny"));
}

#[test]
fn help_version_and_unknown_commands() {
    let env = Env::new("help");
    assert!(env.run(&["help"]).out.contains("never submits"));
    assert_eq!(env.run(&[]).code, 0);
    assert!(env.run(&["version"]).out.starts_with("ApplyShield v"));
    let r = env.run(&["bogus"]);
    assert_eq!(r.code, 2);
    assert!(r.err.contains("Unknown command"));
}

#[test]
fn global_data_dir_argument_is_split_out() {
    let args: Vec<String> = ["--data-dir", "/x", "jobs"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let (dir, rest) = cli::split_global_args(&args).unwrap();
    assert_eq!(dir, Some(PathBuf::from("/x")));
    assert_eq!(rest, vec!["jobs"]);
    assert!(cli::split_global_args(&["--data-dir".to_string()]).is_err());
}

// -------------------------------------------- the real compiled binary

#[test]
fn the_real_binary_refuses_to_approve_from_piped_input() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let env = Env::new("binary");
    env.setup();
    assert_eq!(env.run(&["draft", "demo-good"]).code, 0);

    let mut child = Command::new(env!("CARGO_BIN_EXE_applyshield"))
        .args(["--data-dir"])
        .arg(env.data())
        .args(["approve", "demo-good"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // This is exactly what a script, or an AI tool with a shell, would try.
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"demo-good\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();

    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("interactive terminal"));
    assert!(
        !exists(&env.outbox("demo-good")),
        "package was exported from piped input"
    );
}

#[test]
fn the_real_binary_runs_the_read_only_commands() {
    use std::process::Command;
    let env = Env::new("binary2");
    env.setup();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_applyshield"))
            .arg("--data-dir")
            .arg(env.data())
            .args(args)
            .output()
            .unwrap()
    };
    let jobs = run(&["jobs"]);
    assert!(jobs.status.success());
    assert!(String::from_utf8_lossy(&jobs.stdout).contains("demo-good"));
    let status = run(&["status"]);
    assert!(String::from_utf8_lossy(&status.stdout).contains("Submission enabled: false"));
    assert_eq!(run(&["bogus"]).status.code(), Some(2));
}
