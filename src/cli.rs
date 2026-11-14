//! Command-line interface. Thin: every decision is made by the modules below it.
//!
//! `run` takes its input and output as parameters, so tests can drive the whole
//! program without a terminal.

use crate::approval::{ApprovalToken, Gateway, UserConfirmation};
use crate::audit::AuditEvent;
use crate::checks::scam::Severity;
use crate::checks::url::TrustTier;
use crate::domain::models::{CandidateProfile, Job, JobId, Verdict};
use crate::domain::untrusted::Untrusted;
use crate::drafting::{self, DraftInput, DraftProvider, TemplateDrafter};
use crate::handoff::{self, PackageParts};
use crate::inputs::{self, MAX_JOBS_BYTES, MAX_PROFILE_BYTES};
use crate::pipeline::{self, Evaluation};
use crate::security::Action;
use crate::store::{self, Status, Store};
use std::io::{BufRead, Write};
use std::path::PathBuf;

/// How long an approval lasts. It is used immediately, so this is generous.
const APPROVAL_TTL_SECS: u64 = 300;

pub struct Ctx {
    pub data_dir: PathBuf,
    /// True only when stdin and stdout are both a real terminal. Approval and purge refuse to
    /// run otherwise, so a script or an AI tool cannot answer the prompt.
    pub interactive: bool,
    /// Seconds since the Unix epoch.
    pub now: u64,
}

pub struct Io<'a> {
    pub stdin: &'a mut dyn BufRead,
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
}

macro_rules! say {
    ($o:expr, $($arg:tt)*) => {{ let _ = writeln!($o, $($arg)*); }};
}

const HELP: &str = "
====================================
             APPLYSHIELD
      Security-First Job Copilot
====================================
AI prepares. Security validates. The user decides.

USAGE:
    applyshield [--data-dir <DIR>] <COMMAND> [ARGS]

SETUP:
    init                      Create the private data directory
    import-profile <FILE>     Validate and import your profile
    import-jobs <FILE>        Validate and import a jobs file

WORKFLOW:
    jobs                      Rank jobs; show which are safe and eligible
    show <JOB_ID>             Full safety and eligibility report for one job
    draft <JOB_ID> [--force]  Write a cover-letter draft you can edit
    review <JOB_ID> [--include-phone]
                              Show exactly what would be exported
    approve <JOB_ID> [--include-phone]
                              Approve (type the job ID) and export the package

OTHER:
    status                    Show security status
    audit [--show]            Verify the tamper-evident audit log
    purge                     Erase your profile, jobs, drafts and outbox
    version                   Show version
    help                      Show this help

ApplyShield never submits an application for you. 'approve' writes a package
to your outbox; you apply yourself on the employer's site.
";

/// Splits `--data-dir <DIR>` out of the arguments (program name excluded).
pub fn split_global_args(args: &[String]) -> Result<(Option<PathBuf>, Vec<String>), String> {
    let mut dir = None;
    let mut rest = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--data-dir" {
            match it.next() {
                Some(d) if !d.is_empty() => dir = Some(PathBuf::from(d)),
                _ => return Err("--data-dir needs a directory".to_string()),
            }
        } else {
            rest.push(a.clone());
        }
    }
    Ok((dir, rest))
}

pub fn run(args: &[String], ctx: &Ctx, io: &mut Io<'_>) -> i32 {
    let command = args.first().map(String::as_str).unwrap_or("help");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };

    let result = match command {
        "help" | "--help" | "-h" => {
            let _ = write!(io.out, "{HELP}");
            Ok(0)
        }
        "version" | "--version" | "-V" => {
            say!(io.out, "ApplyShield v{}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        "status" => cmd_status(ctx, io),
        "init" => cmd_init(ctx, io),
        "import-profile" => cmd_import_profile(ctx, io, rest),
        "import-jobs" => cmd_import_jobs(ctx, io, rest),
        "jobs" => cmd_jobs(ctx, io),
        "show" => cmd_show(ctx, io, rest),
        "draft" => cmd_draft(ctx, io, rest),
        "review" => cmd_review(ctx, io, rest),
        "approve" => cmd_approve(ctx, io, rest),
        "audit" => cmd_audit(ctx, io, rest),
        "purge" => cmd_purge(ctx, io),
        other => {
            say!(io.err, "Unknown command: {}", clip(other, 40));
            say!(io.err, "Run 'applyshield help' for available commands.");
            return 2;
        }
    };

    match result {
        Ok(code) => code,
        Err(msg) => {
            say!(io.err, "error: {msg}");
            1
        }
    }
}

// ------------------------------------------------------------------ helpers

type Res<T> = Result<T, String>;

fn clip(s: &str, max: usize) -> String {
    let safe = Untrusted::new(s.to_string()).sanitized(10_000);
    let text: String = safe
        .as_str()
        .chars()
        .map(|c| if c == '\n' || c == '\t' { ' ' } else { c })
        .collect();
    if text.chars().count() <= max {
        text
    } else {
        let mut t: String = text.chars().take(max.saturating_sub(3)).collect();
        t.push_str("...");
        t
    }
}

fn store(ctx: &Ctx) -> Res<Store> {
    let s = Store::new(&ctx.data_dir);
    if !s.is_initialized() {
        return Err("no data directory yet; run 'applyshield init' first".into());
    }
    Ok(s)
}

fn audit(ctx: &Ctx, st: &Store, event: AuditEvent, job: Option<&JobId>, detail: &str) -> Res<()> {
    st.audit_log()
        .append(event, job, detail, ctx.now)
        .map_err(|e| format!("could not write the audit log ({e}); refusing to continue"))
}

fn load_profile(st: &Store) -> Res<CandidateProfile> {
    let text = store::read_limited(&st.profile_path(), MAX_PROFILE_BYTES)
        .map_err(|_| "no profile yet; run 'applyshield import-profile <file>'".to_string())?;
    inputs::parse_profile(&text).map_err(|e| format!("stored profile is invalid: {e}"))
}

fn load_jobs(st: &Store) -> Res<Vec<Job>> {
    let text = store::read_limited(&st.jobs_path(), MAX_JOBS_BYTES)
        .map_err(|_| "no jobs yet; run 'applyshield import-jobs <file>'".to_string())?;
    inputs::parse_jobs(&text).map_err(|e| format!("stored jobs file is invalid: {e}"))
}

fn parse_id(arg: Option<&String>) -> Res<JobId> {
    let raw = arg.ok_or("missing <JOB_ID>; see 'applyshield help'")?;
    JobId::parse(raw).map_err(|_| "that is not a valid job id".to_string())
}

fn find<'a>(jobs: &'a [Job], id: &JobId) -> Res<&'a Job> {
    jobs.iter()
        .find(|j| &j.id == id)
        .ok_or_else(|| format!("no job with id '{id}'"))
}

fn eval(st: &Store, job: &Job, profile: &CandidateProfile) -> Res<Evaluation> {
    pipeline::evaluate(job, profile, &st.trusted_domains())
        .map_err(|e| format!("internal matching error: {e:?}"))
}

fn verdict_label(e: &Evaluation) -> &'static str {
    match e.eligibility.verdict() {
        Verdict::Eligible => "eligible",
        Verdict::NeedsReview => "needs review",
        Verdict::Ineligible => "not eligible",
    }
}

fn trust_label(t: Option<TrustTier>) -> &'static str {
    match t {
        Some(TrustTier::Trusted) => "known job platform",
        Some(TrustTier::Unknown) => "NOT on your trusted list - check it yourself",
        None => "link failed safety checks",
    }
}

// ----------------------------------------------------------------- commands

fn cmd_status(ctx: &Ctx, io: &mut Io<'_>) -> Res<i32> {
    let gateway = Gateway::new();
    let policy = gateway.policy();
    say!(io.out, "\n===== APPLYSHIELD STATUS =====");
    say!(
        io.out,
        "Application: ApplyShield v{}",
        env!("CARGO_PKG_VERSION")
    );
    say!(
        io.out,
        "Submission enabled: {}",
        policy.allows_external_submission()
    );
    say!(
        io.out,
        "Explicit approval required: {}",
        policy.requires_explicit_approval()
    );
    say!(io.out, "Security: Default-deny");
    say!(
        io.out,
        "Approval method: type the job ID in an interactive terminal"
    );
    say!(io.out, "Data directory: {}", ctx.data_dir.display());
    let st = Store::new(&ctx.data_dir);
    if !st.is_initialized() {
        say!(io.out, "Initialized: no (run 'applyshield init')");
    } else {
        say!(io.out, "Initialized: yes");
        say!(
            io.out,
            "Profile: {}",
            if load_profile(&st).is_ok() {
                "imported"
            } else {
                "not imported"
            }
        );
        match load_jobs(&st) {
            Ok(j) => say!(io.out, "Jobs: {}", j.len()),
            Err(_) => say!(io.out, "Jobs: none imported"),
        }
        match st.audit_log().verify() {
            Ok(r) => say!(io.out, "Audit log: {} entries, chain intact", r.entries),
            Err(_) => say!(io.out, "Audit log: PROBLEM - run 'applyshield audit'"),
        }
    }
    say!(io.out, "==============================\n");
    Ok(0)
}

fn cmd_init(ctx: &Ctx, io: &mut Io<'_>) -> Res<i32> {
    let st = Store::new(&ctx.data_dir);
    st.init()
        .map_err(|e| format!("could not create the data directory: {e}"))?;
    say!(io.out, "Data directory ready: {}", ctx.data_dir.display());
    say!(
        io.out,
        "Next: applyshield import-profile <your-profile-file>"
    );
    Ok(0)
}

fn cmd_import_profile(ctx: &Ctx, io: &mut Io<'_>, args: &[String]) -> Res<i32> {
    let st = store(ctx)?;
    let path = args
        .first()
        .ok_or("usage: applyshield import-profile <FILE>")?;
    let text = store::read_limited(std::path::Path::new(path), MAX_PROFILE_BYTES)
        .map_err(|e| format!("could not read that file: {e}"))?;
    let profile = inputs::parse_profile(&text).map_err(|e| format!("profile rejected: {e}"))?;
    store::write_private(&st.profile_path(), text.as_bytes())
        .map_err(|e| format!("could not store the profile: {e}"))?;
    audit(
        ctx,
        &st,
        AuditEvent::ProfileImported,
        None,
        "profile validated and stored",
    )?;
    say!(
        io.out,
        "Profile imported: {} skills, graduation year {}.",
        profile.skills.len(),
        profile.education.graduation_year()
    );
    Ok(0)
}

fn cmd_import_jobs(ctx: &Ctx, io: &mut Io<'_>, args: &[String]) -> Res<i32> {
    let st = store(ctx)?;
    let path = args
        .first()
        .ok_or("usage: applyshield import-jobs <FILE>")?;
    let text = store::read_limited(std::path::Path::new(path), MAX_JOBS_BYTES)
        .map_err(|e| format!("could not read that file: {e}"))?;
    let jobs = inputs::parse_jobs(&text).map_err(|e| format!("jobs file rejected: {e}"))?;
    store::write_private(&st.jobs_path(), text.as_bytes())
        .map_err(|e| format!("could not store the jobs: {e}"))?;
    audit(
        ctx,
        &st,
        AuditEvent::JobsImported,
        None,
        &format!("{} jobs validated and stored", jobs.len()),
    )?;
    say!(
        io.out,
        "Imported {} jobs. Run 'applyshield jobs' to see them ranked.",
        jobs.len()
    );
    Ok(0)
}

fn cmd_jobs(ctx: &Ctx, io: &mut Io<'_>) -> Res<i32> {
    let st = store(ctx)?;
    let profile = load_profile(&st)?;
    let jobs = load_jobs(&st)?;
    // IDs are typed back into other commands, so they are never shortened.
    let id_width = jobs
        .iter()
        .map(|j| j.id.as_str().len())
        .max()
        .unwrap_or(2)
        .max(2);
    let mut rows: Vec<(Option<u8>, String)> = Vec::new();
    for job in &jobs {
        let e = eval(&st, job, &profile)?;
        let blocked = !e.draftable();
        let warn = if e.scam_flags.iter().any(|f| f.severity == Severity::Medium)
            || e.trust == Some(TrustTier::Unknown)
        {
            "!"
        } else {
            " "
        };
        let result = if blocked {
            "BLOCKED"
        } else {
            verdict_label(&e)
        };
        let score = if blocked {
            "--".to_string()
        } else {
            format!("{:>3}", e.score.total())
        };
        let title = clip(job.title.sanitized(200).as_str(), 34);
        let company = clip(job.company.sanitized(200).as_str(), 20);
        let line = format!(
            "{:<id_width$} {} {:<12} {:<9}{} {} @ {}",
            job.id.as_str(),
            score,
            result,
            st.status(&job.id).as_str(),
            warn,
            title,
            company
        );
        rows.push((if blocked { None } else { Some(e.score.total()) }, line));
    }
    rows.sort_by_key(|r| std::cmp::Reverse(r.0));
    say!(
        io.out,
        "{:<id_width$} {:>3} {:<12} {:<10} TITLE @ COMPANY",
        "ID",
        "SCR",
        "RESULT",
        "STATUS"
    );
    for (_, line) in &rows {
        say!(io.out, "{line}");
    }
    say!(
        io.out,
        "\n'!' = check this one yourself.  BLOCKED = cannot be drafted; see 'applyshield show <ID>'."
    );
    Ok(0)
}

fn cmd_show(ctx: &Ctx, io: &mut Io<'_>, args: &[String]) -> Res<i32> {
    let id = parse_id(args.first())?;
    let st = store(ctx)?;
    let profile = load_profile(&st)?;
    let jobs = load_jobs(&st)?;
    let job = find(&jobs, &id)?;
    let e = eval(&st, job, &profile)?;

    say!(io.out, "\n===== JOB {id} =====");
    say!(
        io.out,
        "Title:    {}",
        clip(job.title.sanitized(200).as_str(), 120)
    );
    say!(
        io.out,
        "Company:  {}",
        clip(job.company.sanitized(200).as_str(), 120)
    );
    say!(
        io.out,
        "Location: {}",
        clip(job.location.sanitized(200).as_str(), 120)
    );
    match &e.url {
        Ok(u) => say!(
            io.out,
            "Apply at: {}  [{}]",
            u.as_str(),
            trust_label(e.trust)
        ),
        Err(err) => say!(io.out, "Apply at: UNSAFE LINK ({})", err.explanation()),
    }
    say!(io.out, "Status:   {}", st.status(&id).as_str());

    say!(io.out, "\nEligibility: {}", verdict_label(&e));
    for r in e.eligibility.reasons() {
        say!(io.out, "  - {}", r.explanation());
    }
    say!(io.out, "\nScore: {}/100", e.score.total());
    for c in e.score.components() {
        say!(io.out, "  {:<9} {}", c.name, c.points);
    }
    if e.matched_skills.is_empty() {
        say!(io.out, "Matched skills: none");
    } else {
        say!(io.out, "Matched skills: {}", e.matched_skills.join(", "));
    }

    if !e.scam_flags.is_empty() || !e.injection_findings.is_empty() {
        say!(io.out, "\nSafety flags:");
        for f in &e.scam_flags {
            let tag = if f.severity == Severity::High {
                "HIGH  "
            } else {
                "medium"
            };
            say!(io.out, "  [{tag}] {}", f.name);
        }
        if !e.injection_findings.is_empty() {
            say!(
                io.out,
                "  [HIGH  ] contains text aimed at AI tools (possible prompt injection)"
            );
        }
    }

    say!(
        io.out,
        "\nDescription (untrusted listing text, shown for your reading only):"
    );
    let desc = job.description.sanitized(600);
    for line in desc.as_str().lines().take(12) {
        say!(io.out, "  | {}", clip(line, 100));
    }

    if e.draftable() {
        say!(
            io.out,
            "\nCan be drafted: yes. Next: applyshield draft {id}"
        );
    } else {
        say!(io.out, "\nCan be drafted: NO");
        for r in &e.block_reasons {
            say!(io.out, "  - {r}");
        }
    }
    say!(io.out, "");
    Ok(0)
}

fn cmd_draft(ctx: &Ctx, io: &mut Io<'_>, args: &[String]) -> Res<i32> {
    let id = parse_id(args.first())?;
    let force = args.iter().skip(1).any(|a| a == "--force");
    let st = store(ctx)?;
    let profile = load_profile(&st)?;
    let jobs = load_jobs(&st)?;
    let job = find(&jobs, &id)?;
    let e = eval(&st, job, &profile)?;

    if !e.draftable() {
        say!(io.err, "Refusing to draft job '{id}':");
        for r in &e.block_reasons {
            say!(io.err, "  - {r}");
        }
        return Ok(1);
    }
    if !force && st.load_draft(&id).map_err(|e| e.to_string())?.is_some() {
        return Err(format!(
            "a draft for '{id}' already exists (it may contain your edits); use --force to replace it"
        ));
    }

    let title = job.title.sanitized(200);
    let company = job.company.sanitized(200);
    let input = DraftInput {
        job_title: title.as_str(),
        company: company.as_str(),
        matched_skills: &e.matched_skills,
        degree: profile.education.degree(),
        field: profile.education.field(),
        graduation_year: profile.education.graduation_year(),
    };
    let draft = TemplateDrafter.draft(&input);
    let ctxs = [title.as_str(), company.as_str(), input.degree, input.field];
    let mut issues = drafting::verify_draft(&draft, &profile, &ctxs);
    let text = drafting::fill_name(&draft.body, profile.full_name.expose_secret());
    issues.extend(drafting::verify_text(&text, &profile, &ctxs));
    if !issues.is_empty() {
        say!(
            io.err,
            "The generated draft failed verification, so it was not saved:"
        );
        for i in &issues {
            say!(io.err, "  - {}", i.explanation());
        }
        return Ok(1);
    }

    st.save_draft(&id, &text)
        .map_err(|e| format!("could not save the draft: {e}"))?;
    st.set_status(&id, Status::Drafted)
        .map_err(|e| e.to_string())?;
    audit(
        ctx,
        &st,
        AuditEvent::Drafted,
        Some(&id),
        "draft created and verified",
    )?;
    say!(io.out, "Draft saved: {}", st.draft_path(&id).display());
    say!(
        io.out,
        "You can edit that file. Edits are re-verified when you review or approve."
    );
    say!(io.out, "Next: applyshield review {id}");
    Ok(0)
}

struct Prepared {
    destination: String,
    trust: Option<TrustTier>,
    package: String,
    shared: Vec<&'static str>,
    warnings: Vec<String>,
}

/// Everything `review` and `approve` need. Fails closed on any problem.
fn prepare(ctx: &Ctx, id: &JobId, include_phone: bool) -> Res<(Store, Prepared)> {
    let st = store(ctx)?;
    let profile = load_profile(&st)?;
    let jobs = load_jobs(&st)?;
    let job = find(&jobs, id)?;
    let e = eval(&st, job, &profile)?;
    if !e.draftable() {
        return Err(format!(
            "job '{id}' is blocked: {}",
            e.block_reasons.join("; ")
        ));
    }
    let draft = st
        .load_draft(id)
        .map_err(|e| format!("could not read the draft: {e}"))?
        .ok_or_else(|| format!("no draft yet; run 'applyshield draft {id}' first"))?;

    let title = job.title.sanitized(200);
    let company = job.company.sanitized(200);
    let letter = drafting::fill_name(&draft, profile.full_name.expose_secret());
    let ctxs = [
        title.as_str(),
        company.as_str(),
        profile.education.degree(),
        profile.education.field(),
    ];
    let issues = drafting::verify_text(&letter, &profile, &ctxs);
    if !issues.is_empty() {
        let list: Vec<String> = issues.iter().map(|i| i.explanation()).collect();
        return Err(format!(
            "the draft did not pass verification: {}",
            list.join("; ")
        ));
    }

    let phone = if include_phone {
        Some(
            profile
                .phone
                .as_ref()
                .ok_or("--include-phone given, but your profile has no phone number")?
                .expose_secret()
                .as_str(),
        )
    } else {
        None
    };
    let destination = e
        .url
        .as_ref()
        .map_err(|x| x.explanation().to_string())?
        .as_str()
        .to_string();
    let package = handoff::build_package(&PackageParts {
        job_title: title.as_str(),
        company: company.as_str(),
        destination: &destination,
        name: profile.full_name.expose_secret(),
        email: profile.email.expose_secret(),
        phone,
        cover_letter: &letter,
    });

    let mut warnings = Vec::new();
    if e.trust == Some(TrustTier::Unknown) {
        warnings.push(
            "the apply link is not on your trusted list; check the site is genuine".to_string(),
        );
    }
    for f in &e.scam_flags {
        warnings.push(format!("listing {}", f.name));
    }
    if e.eligibility.verdict() == Verdict::NeedsReview {
        for r in e.eligibility.reasons() {
            warnings.push(r.explanation().to_string());
        }
    }

    Ok((
        st,
        Prepared {
            destination,
            trust: e.trust,
            package,
            shared: handoff::shared_fields(include_phone),
            warnings,
        },
    ))
}

fn print_review(io: &mut Io<'_>, id: &JobId, p: &Prepared) {
    say!(io.out, "\n===== REVIEW: {id} =====");
    say!(
        io.out,
        "Destination: {}  [{}]",
        p.destination,
        trust_label(p.trust)
    );
    if !p.warnings.is_empty() {
        say!(io.out, "Warnings:");
        for w in &p.warnings {
            say!(io.out, "  ! {w}");
        }
    }
    say!(
        io.out,
        "Personal data in this package: {}",
        p.shared.join(", ")
    );
    say!(io.out, "----- exact content that would be exported -----");
    let _ = write!(io.out, "{}", p.package);
    say!(io.out, "------------------------------------------------");
}

fn cmd_review(ctx: &Ctx, io: &mut Io<'_>, args: &[String]) -> Res<i32> {
    let id = parse_id(args.first())?;
    let include_phone = args.iter().skip(1).any(|a| a == "--include-phone");
    let (_, p) = prepare(ctx, &id, include_phone)?;
    print_review(io, &id, &p);
    say!(
        io.out,
        "Nothing has been exported. To approve: applyshield approve {id}"
    );
    Ok(0)
}

fn cmd_approve(ctx: &Ctx, io: &mut Io<'_>, args: &[String]) -> Res<i32> {
    let id = parse_id(args.first())?;
    let include_phone = args.iter().skip(1).any(|a| a == "--include-phone");

    if !ctx.interactive {
        if let Ok(st) = store(ctx) {
            let _ = audit(
                ctx,
                &st,
                AuditEvent::ApprovalDenied,
                Some(&id),
                "refused: not an interactive terminal",
            );
        }
        say!(
            io.err,
            "Approval needs a person at an interactive terminal (input and output must both be a terminal); nothing was done."
        );
        return Ok(3);
    }

    let (st, p) = prepare(ctx, &id, include_phone)?;
    print_review(io, &id, &p);

    let _ = write!(
        io.out,
        "Type the job ID ({id}) and press Enter to approve, anything else cancels: "
    );
    let _ = io.out.flush();
    let mut line = String::new();
    let read = io.stdin.read_line(&mut line).unwrap_or(0);
    let typed = if read == 0 || line.len() > 256 {
        ""
    } else {
        line.as_str()
    };

    let Some(confirmation) = UserConfirmation::from_typed(typed, &id) else {
        audit(
            ctx,
            &st,
            AuditEvent::ApprovalDeclined,
            Some(&id),
            "user did not type the job id",
        )?;
        say!(io.out, "Cancelled. Nothing was exported.");
        return Ok(1);
    };

    let token = ApprovalToken::issue(
        confirmation,
        p.package.as_bytes(),
        &p.destination,
        ctx.now,
        APPROVAL_TTL_SECS,
    );
    let auth = match Gateway::new().authorize(
        token,
        Action::ExportForManualSubmission,
        &id,
        p.package.as_bytes(),
        &p.destination,
        ctx.now,
    ) {
        Ok(a) => a,
        Err(d) => {
            audit(
                ctx,
                &st,
                AuditEvent::ApprovalDenied,
                Some(&id),
                d.explanation(),
            )?;
            say!(io.err, "Denied: {}.", d.explanation());
            return Ok(1);
        }
    };

    // Record the approval before acting on it; if the log cannot be written, stop.
    audit(
        ctx,
        &st,
        AuditEvent::Approved,
        Some(&id),
        &format!("typed job id; shared: {}", p.shared.join(", ")),
    )?;
    let dir = handoff::export_package(&st, &auth, &p.package, &p.destination)
        .map_err(|e| format!("could not write the package: {e}"))?;
    st.set_status(&id, Status::Exported)
        .map_err(|e| e.to_string())?;
    audit(
        ctx,
        &st,
        AuditEvent::Exported,
        Some(&id),
        "package written to outbox for manual submission",
    )?;

    say!(io.out, "\nApproved. Package written to: {}", dir.display());
    say!(
        io.out,
        "Nothing was sent. To apply, open this link yourself and paste the details:"
    );
    say!(io.out, "  {}", p.destination);
    Ok(0)
}

fn cmd_audit(ctx: &Ctx, io: &mut Io<'_>, args: &[String]) -> Res<i32> {
    let st = store(ctx)?;
    let log = st.audit_log();
    match log.verify() {
        Ok(r) => {
            say!(io.out, "Audit log OK: {} entries, chain intact.", r.entries);
            say!(
                io.out,
                "Head hash (note this somewhere safe to detect truncation): {}",
                r.head
            );
        }
        Err(e) => {
            say!(
                io.err,
                "AUDIT LOG PROBLEM: {e:?}. The log was edited, damaged or truncated."
            );
            return Ok(1);
        }
    }
    if args.iter().any(|a| a == "--show") {
        for e in log.read_entries().map_err(|e| format!("{e:?}"))? {
            say!(
                io.out,
                "{:>4}  {}  {:<18} {:<14} {}",
                e.seq,
                e.timestamp,
                clip(&e.event, 24),
                clip(&e.job, 64),
                clip(&e.detail, 200)
            );
        }
    }
    Ok(0)
}

fn cmd_purge(ctx: &Ctx, io: &mut Io<'_>) -> Res<i32> {
    let st = store(ctx)?;
    if !ctx.interactive {
        say!(
            io.err,
            "Purge needs a person at an interactive terminal (input and output must both be a terminal); nothing was deleted."
        );
        return Ok(3);
    }
    say!(
        io.out,
        "This permanently deletes your profile, jobs, drafts and outbox in:"
    );
    say!(io.out, "  {}", ctx.data_dir.display());
    say!(
        io.out,
        "The audit log is kept (it contains no personal data)."
    );
    let _ = write!(io.out, "Type DELETE to confirm: ");
    let _ = io.out.flush();
    let mut line = String::new();
    let read = io.stdin.read_line(&mut line).unwrap_or(0);
    if read == 0 || line.trim() != "DELETE" {
        say!(io.out, "Cancelled. Nothing was deleted.");
        return Ok(1);
    }
    st.purge().map_err(|e| format!("purge failed: {e}"))?;
    audit(
        ctx,
        &st,
        AuditEvent::Purged,
        None,
        "profile, jobs, drafts and outbox erased",
    )?;
    say!(io.out, "Done. Your personal data has been erased.");
    Ok(0)
}
