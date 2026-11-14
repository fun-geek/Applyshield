//! Application drafting and the truthfulness check.
//!
//! Two rules shape this module (threats T1, T5, T11):
//!
//! 1. **Minimal input.** A drafter only ever receives [`DraftInput`]: the job
//!    title and company, the skills the user already has that the job mentions,
//!    and education facts. It never sees the job description, the apply link,
//!    or the user's name, email or phone. So a hostile listing cannot reach it,
//!    and a future LLM-backed drafter cannot leak personal data.
//! 2. **Verify before use.** Whatever a drafter (or the user, by editing)
//!    produces is checked by [`verify_text`] before it can be approved: no
//!    skills the user hasn't listed, no invented years of experience, no links
//!    or email addresses, no stray placeholders.
//!
//! This module deliberately knows nothing about approval or submission;
//! `tests/architecture_tests.rs` enforces that.

use crate::checks::eligibility::min_years_required;
use crate::checks::text::normalize_for_scan;
use crate::domain::models::CandidateProfile;
use crate::domain::untrusted::Untrusted;
use crate::matching;

pub const NAME_PLACEHOLDER: &str = "{{NAME}}";
pub const MAX_DRAFT_CHARS: usize = 3000;

/// Everything a drafter is allowed to know.
#[derive(Clone, Debug)]
pub struct DraftInput<'a> {
    pub job_title: &'a str,
    pub company: &'a str,
    pub matched_skills: &'a [String],
    pub degree: &'a str,
    pub field: &'a str,
    pub graduation_year: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Draft {
    /// The letter, with `{{NAME}}` where the user's name goes.
    pub body: String,
    /// Skills the draft claims. Must all be in the user's profile.
    pub claimed_skills: Vec<String>,
}

/// Anything that can write a draft: a local template today, possibly an LLM
/// later. Its output is always verified before use.
pub trait DraftProvider {
    fn draft(&self, input: &DraftInput<'_>) -> Draft;
}

/// Deterministic, local, no network. Claims only the skills it is given.
pub struct TemplateDrafter;

impl DraftProvider for TemplateDrafter {
    fn draft(&self, input: &DraftInput<'_>) -> Draft {
        let skills_sentence = match input.matched_skills {
            [] => "I am keen to learn quickly and contribute to your team.".to_string(),
            skills => format!(
                "My relevant skills include {}, and I would be glad to apply them in this role.",
                join_natural(skills)
            ),
        };
        let body = format!(
            "Dear Hiring Team,\n\n\
             I am writing to apply for the {title} position at {company}. \
             I am a {degree} student in {field}, graduating in {year}.\n\n\
             {skills_sentence}\n\n\
             Thank you for your time and consideration. I would welcome the \
             opportunity to discuss my application.\n\n\
             Sincerely,\n{NAME_PLACEHOLDER}\n",
            title = input.job_title,
            company = input.company,
            degree = input.degree,
            field = input.field,
            year = input.graduation_year,
        );
        Draft {
            body,
            claimed_skills: input.matched_skills.to_vec(),
        }
    }
}

fn join_natural(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [a] => a.clone(),
        [a, b] => format!("{a} and {b}"),
        [rest @ .., last] => format!("{}, and {last}", rest.join(", ")),
    }
}

/// Replaces the name placeholder. Done locally, after the drafter has run.
pub fn fill_name(text: &str, name: &str) -> String {
    text.replace(NAME_PLACEHOLDER, name)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DraftIssue {
    Empty,
    TooLong,
    ControlCharacters,
    ContainsLink,
    ContainsEmailAddress,
    UnknownPlaceholder,
    /// Claims years of experience.
    ExperienceClaim,
    /// Mentions a technology that is not in the user's profile.
    UnverifiedSkill(String),
}

impl DraftIssue {
    pub fn explanation(&self) -> String {
        match self {
            Self::Empty => "the draft is empty".into(),
            Self::TooLong => format!("the draft is longer than {MAX_DRAFT_CHARS} characters"),
            Self::ControlCharacters => "the draft contains control characters".into(),
            Self::ContainsLink => "the draft contains a link".into(),
            Self::ContainsEmailAddress => "the draft contains an email address".into(),
            Self::UnknownPlaceholder => "the draft contains an unfilled placeholder".into(),
            Self::ExperienceClaim => "the draft claims years of experience".into(),
            Self::UnverifiedSkill(s) => format!(
                "the draft mentions '{s}', which is not in your profile skills \
                 (add it to your profile if it is true, otherwise remove it)"
            ),
        }
    }
}

/// Technologies a letter might claim. Words that are also ordinary English
/// ("go", "excel", "swift", "spring", "rest", "unity") are left out on purpose
/// to avoid false alarms.
const VOCABULARY: &[&str] = &[
    "python",
    "java",
    "javascript",
    "typescript",
    "c++",
    "c#",
    "golang",
    "rust",
    "kotlin",
    "scala",
    "ruby",
    "php",
    "perl",
    "matlab",
    "sql",
    "mysql",
    "postgresql",
    "mongodb",
    "redis",
    "sqlite",
    "oracle",
    "html",
    "css",
    "react",
    "angular",
    "vue",
    "nodejs",
    "django",
    "flask",
    "docker",
    "kubernetes",
    "aws",
    "azure",
    "gcp",
    "linux",
    "git",
    "tensorflow",
    "pytorch",
    "keras",
    "scikit-learn",
    "pandas",
    "numpy",
    "opencv",
    "nlp",
    "machine learning",
    "deep learning",
    "data science",
    "hadoop",
    "spark",
    "kafka",
    "tableau",
    "power bi",
    "jenkins",
    "terraform",
    "ansible",
    "firebase",
    "flutter",
    "android",
    "ios",
    "solidity",
    "blockchain",
    "graphql",
    "assembly",
    "verilog",
    "embedded",
];

/// Checks letter text. `context` lists strings that are allowed to appear even
/// if they look like skills, because they are facts about the job or the user,
/// not claims (the job title, company, degree and field).
pub fn verify_text(text: &str, profile: &CandidateProfile, context: &[&str]) -> Vec<DraftIssue> {
    let mut issues = Vec::new();

    if text.trim().is_empty() {
        return vec![DraftIssue::Empty];
    }
    if text.chars().count() > MAX_DRAFT_CHARS {
        issues.push(DraftIssue::TooLong);
    }
    let clean = Untrusted::new(text.to_string()).sanitized(usize::MAX);
    if clean.as_str() != text {
        issues.push(DraftIssue::ControlCharacters);
    }

    let norm = normalize_for_scan(text);
    if norm.contains("http://") || norm.contains("https://") || norm.contains("www.") {
        issues.push(DraftIssue::ContainsLink);
    }
    if text.contains('@') {
        issues.push(DraftIssue::ContainsEmailAddress);
    }
    if text.matches("{{").count() != text.matches(NAME_PLACEHOLDER).count()
        || text.matches("}}").count() != text.matches(NAME_PLACEHOLDER).count()
    {
        issues.push(DraftIssue::UnknownPlaceholder);
    }
    if min_years_required(&norm).is_some() || norm.contains("years of experience") {
        issues.push(DraftIssue::ExperienceClaim);
    }

    // Skill vocabulary: remove allowed context, then look for technology words.
    let mut scrubbed = norm;
    for c in context {
        let c = normalize_for_scan(c);
        if !c.is_empty() {
            scrubbed = scrubbed.replace(&c, " ");
        }
    }
    let known: Vec<String> = profile
        .skills
        .iter()
        .map(|s| normalize_for_scan(s))
        .collect();
    let vocab: Vec<String> = VOCABULARY
        .iter()
        .filter(|v| !known.iter().any(|k| k == *v))
        .map(|v| v.to_string())
        .collect();
    for chunk in vocab.chunks(matching::MAX_SKILLS) {
        if let Ok(hits) = matching::skill_hits(&scrubbed, chunk) {
            for (term, hit) in chunk.iter().zip(hits) {
                if hit {
                    issues.push(DraftIssue::UnverifiedSkill(term.clone()));
                }
            }
        } else {
            // Fail closed: if matching cannot run, the draft is not verified.
            issues.push(DraftIssue::UnverifiedSkill(
                "(could not verify skills)".into(),
            ));
        }
    }

    issues
}

/// Checks a provider's draft: its declared claims *and* its text.
pub fn verify_draft(
    draft: &Draft,
    profile: &CandidateProfile,
    context: &[&str],
) -> Vec<DraftIssue> {
    let mut issues = verify_text(&draft.body, profile, context);
    for claim in &draft.claimed_skills {
        let c = normalize_for_scan(claim);
        if !profile.skills.iter().any(|s| normalize_for_scan(s) == c) {
            issues.push(DraftIssue::UnverifiedSkill(claim.clone()));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::Education;
    use crate::domain::sensitive::Redacted;

    fn profile() -> CandidateProfile {
        CandidateProfile {
            full_name: Redacted::new("Test Person".into()),
            email: Redacted::new("t@example.org".into()),
            phone: None,
            education: Education::new("B.Tech", "CSE (AI & ML)", 2028).unwrap(),
            target_roles: vec![],
            skills: vec!["rust".into(), "c".into(), "sql".into()],
            location_preferences: vec![],
        }
    }

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|x| x.to_string()).collect()
    }

    fn input<'a>(skills: &'a [String]) -> DraftInput<'a> {
        DraftInput {
            job_title: "Software Developer Intern",
            company: "Acme",
            matched_skills: skills,
            degree: "B.Tech",
            field: "CSE (AI & ML)",
            graduation_year: 2028,
        }
    }

    const CTX: &[&str] = &[
        "Software Developer Intern",
        "Acme",
        "B.Tech",
        "CSE (AI & ML)",
    ];

    #[test]
    fn template_draft_mentions_the_role_company_and_skills() {
        let sk = s(&["rust", "sql"]);
        let d = TemplateDrafter.draft(&input(&sk));
        assert!(d.body.contains("Software Developer Intern"));
        assert!(d.body.contains("Acme"));
        assert!(d.body.contains("rust and sql"));
        assert!(d.body.contains(NAME_PLACEHOLDER));
        assert_eq!(d.claimed_skills, sk);
    }

    #[test]
    fn template_draft_without_skills_makes_no_skill_claim() {
        let d = TemplateDrafter.draft(&input(&[]));
        assert!(d.claimed_skills.is_empty());
        assert!(d.body.contains("keen to learn"));
    }

    #[test]
    fn three_skills_use_an_oxford_comma_list() {
        assert_eq!(join_natural(&s(&["a", "b", "c"])), "a, b, and c");
        assert_eq!(join_natural(&s(&["a", "b"])), "a and b");
        assert_eq!(join_natural(&s(&["a"])), "a");
    }

    #[test]
    fn template_draft_passes_verification() {
        let sk = s(&["rust", "c", "sql"]);
        let d = TemplateDrafter.draft(&input(&sk));
        assert_eq!(verify_draft(&d, &profile(), CTX), vec![]);
    }

    #[test]
    fn name_is_filled_locally_and_verifies_after_filling() {
        let sk = s(&["rust"]);
        let d = TemplateDrafter.draft(&input(&sk));
        let text = fill_name(&d.body, "Test Person");
        assert!(!text.contains("{{"));
        assert!(text.contains("Test Person"));
        assert_eq!(verify_text(&text, &profile(), CTX), vec![]);
    }

    #[test]
    fn drafter_input_contains_no_personal_data_or_description() {
        // DraftInput has no field for them; this documents and pins that.
        let dbg = format!("{:?}", input(&s(&["rust"])));
        for forbidden in ["email", "phone", "description", "url", "full_name"] {
            assert!(
                !dbg.contains(forbidden),
                "{forbidden} leaked into DraftInput"
            );
        }
    }

    #[test]
    fn unlisted_skills_are_caught_in_text() {
        let issues = verify_text("I am an expert in Python and Kubernetes.", &profile(), CTX);
        assert!(issues.contains(&DraftIssue::UnverifiedSkill("python".into())));
        assert!(issues.contains(&DraftIssue::UnverifiedSkill("kubernetes".into())));
    }

    #[test]
    fn listed_skills_are_fine_in_any_case() {
        assert_eq!(verify_text("I know RUST and Sql.", &profile(), CTX), vec![]);
    }

    #[test]
    fn a_provider_claiming_an_unlisted_skill_is_caught() {
        let d = Draft {
            body: "Dear Hiring Team,\nI am keen.\n{{NAME}}".into(),
            claimed_skills: s(&["rust", "haskell"]),
        };
        let issues = verify_draft(&d, &profile(), CTX);
        assert_eq!(issues, vec![DraftIssue::UnverifiedSkill("haskell".into())]);
    }

    #[test]
    fn skill_words_in_the_job_title_or_company_are_not_claims() {
        let ctx = ["Python Developer Intern", "Java Labs"];
        let text = "I am applying for the Python Developer Intern position at Java Labs.";
        assert_eq!(verify_text(text, &profile(), &ctx), vec![]);
        // ...but claiming the skill outside that context is still caught.
        let sneaky = format!("{text} I have strong Python skills.");
        assert!(!verify_text(&sneaky, &profile(), &ctx).is_empty());
    }

    #[test]
    fn invented_experience_is_caught() {
        for t in [
            "I have 3 years of experience in software.",
            "With 2+ years experience I can contribute.",
            "I bring years of experience.",
        ] {
            assert!(
                verify_text(t, &profile(), CTX).contains(&DraftIssue::ExperienceClaim),
                "{t}"
            );
        }
    }

    #[test]
    fn links_and_email_addresses_are_caught() {
        let i = verify_text("See https://evil.com and mail me@evil.com", &profile(), CTX);
        assert!(i.contains(&DraftIssue::ContainsLink));
        assert!(i.contains(&DraftIssue::ContainsEmailAddress));
        assert!(
            verify_text("visit www.evil.com", &profile(), CTX).contains(&DraftIssue::ContainsLink)
        );
    }

    #[test]
    fn stray_placeholders_are_caught_but_the_name_placeholder_is_fine() {
        assert!(
            verify_text("Hello {{PHONE}}", &profile(), CTX)
                .contains(&DraftIssue::UnknownPlaceholder)
        );
        assert!(
            verify_text("Hello {{ NAME }}", &profile(), CTX)
                .contains(&DraftIssue::UnknownPlaceholder)
        );
        assert!(verify_text("Hello {{", &profile(), CTX).contains(&DraftIssue::UnknownPlaceholder));
        assert_eq!(verify_text("Hello {{NAME}}", &profile(), CTX), vec![]);
    }

    #[test]
    fn empty_oversized_and_control_character_drafts_are_caught() {
        assert_eq!(
            verify_text("   \n", &profile(), CTX),
            vec![DraftIssue::Empty]
        );
        assert!(verify_text(&"a ".repeat(2000), &profile(), CTX).contains(&DraftIssue::TooLong));
        assert!(
            verify_text("hello\u{1b}[31m", &profile(), CTX)
                .contains(&DraftIssue::ControlCharacters)
        );
        assert!(
            verify_text("hello\u{202E}", &profile(), CTX).contains(&DraftIssue::ControlCharacters)
        );
    }

    #[test]
    fn newlines_and_tabs_are_allowed() {
        assert_eq!(verify_text("Dear\tTeam,\n\nHello", &profile(), CTX), vec![]);
    }

    #[test]
    fn explanations_are_non_empty() {
        for i in [
            DraftIssue::Empty,
            DraftIssue::TooLong,
            DraftIssue::ControlCharacters,
            DraftIssue::ContainsLink,
            DraftIssue::ContainsEmailAddress,
            DraftIssue::UnknownPlaceholder,
            DraftIssue::ExperienceClaim,
            DraftIssue::UnverifiedSkill("x".into()),
        ] {
            assert!(!i.explanation().is_empty());
        }
    }
}
