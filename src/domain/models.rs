//! Core domain models (Milestone 2).
//!
//! Design rules:
//! * Text from the outside world is `Untrusted<String>`; personal data is
//!   `Redacted<String>`. `#[derive(Debug)]` on these structs is therefore safe:
//!   neither wrapper prints its contents.
//! * Identifiers and results have validated constructors, so invalid values
//!   cannot be built. Anything that does not validate is rejected (fail closed).
//! * These are data structures only. Eligibility and scoring *logic* arrives
//!   with the matching engine (Milestone 3).

use super::sensitive::Redacted;
use super::untrusted::Untrusted;
use std::fmt;

// ---------------------------------------------------------------- JobId

/// Longest accepted job identifier.
pub const MAX_JOB_ID_LEN: usize = 64;

/// A job identifier that is safe to print, use in file names, and use as a
/// typed confirmation. Only ASCII letters, digits, `-` and `_` are allowed,
/// so it cannot carry escape sequences, path tricks, or SQL/shell syntax.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct JobId(String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobIdError {
    Empty,
    TooLong,
    InvalidCharacter,
}

impl JobId {
    pub fn parse(input: &str) -> Result<Self, JobIdError> {
        if input.is_empty() {
            return Err(JobIdError::Empty);
        }
        if input.len() > MAX_JOB_ID_LEN {
            return Err(JobIdError::TooLong);
        }
        if !input
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(JobIdError::InvalidCharacter);
        }
        Ok(Self(input.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------- Job

/// A normalised job listing. Every text field came from outside the program,
/// so every text field is `Untrusted`.
#[derive(Clone, Debug)]
pub struct Job {
    pub id: JobId,
    pub title: Untrusted<String>,
    pub company: Untrusted<String>,
    pub location: Untrusted<String>,
    pub description: Untrusted<String>,
    /// Not yet validated. Domain validation arrives with Step 4.
    pub source_url: Untrusted<String>,
}

// ---------------------------------------------------------------- Candidate

/// Earliest and latest graduation years accepted by [`Education::new`].
pub const MIN_GRADUATION_YEAR: u16 = 2000;
pub const MAX_GRADUATION_YEAR: u16 = 2100;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Education {
    degree: String,
    field: String,
    graduation_year: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EducationError {
    EmptyDegree,
    EmptyField,
    GraduationYearOutOfRange,
}

impl Education {
    pub fn new(
        degree: impl Into<String>,
        field: impl Into<String>,
        graduation_year: u16,
    ) -> Result<Self, EducationError> {
        let degree = degree.into();
        let field = field.into();
        if degree.trim().is_empty() {
            return Err(EducationError::EmptyDegree);
        }
        if field.trim().is_empty() {
            return Err(EducationError::EmptyField);
        }
        if !(MIN_GRADUATION_YEAR..=MAX_GRADUATION_YEAR).contains(&graduation_year) {
            return Err(EducationError::GraduationYearOutOfRange);
        }
        Ok(Self {
            degree,
            field,
            graduation_year,
        })
    }

    pub fn degree(&self) -> &str {
        &self.degree
    }

    pub fn field(&self) -> &str {
        &self.field
    }

    pub fn graduation_year(&self) -> u16 {
        self.graduation_year
    }
}

/// The user's profile. Identifying fields are `Redacted` (data class
/// `Personal`); the rest is `Public`. Skills here are the only facts later
/// steps may use when drafting, so drafts can never claim anything else
/// (invariant: truthful applications).
#[derive(Clone, Debug)]
pub struct CandidateProfile {
    pub full_name: Redacted<String>,
    pub email: Redacted<String>,
    pub phone: Option<Redacted<String>>,
    pub education: Education,
    pub target_roles: Vec<String>,
    pub skills: Vec<String>,
    pub location_preferences: Vec<String>,
}

// ---------------------------------------------------------------- Eligibility

/// Why a job was ruled out or flagged. A closed list, so every decision is
/// explainable and testable; there are no free-text reasons from untrusted data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EligibilityReason {
    GraduationYearMismatch,
    ExperienceRequired,
    LocationMismatch,
    DegreeMismatch,
    RequiresExperienceCertificate,
}

impl EligibilityReason {
    pub fn explanation(&self) -> &'static str {
        match self {
            Self::GraduationYearMismatch => "Graduation year does not match the requirement",
            Self::ExperienceRequired => "Requires prior work experience",
            Self::LocationMismatch => "Location does not match your preferences",
            Self::DegreeMismatch => "Degree or field does not match the requirement",
            Self::RequiresExperienceCertificate => {
                "Requires a previous-company experience certificate"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Eligible,
    /// Could not be decided automatically; the user should look.
    NeedsReview,
    Ineligible,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EligibilityResult {
    verdict: Verdict,
    reasons: Vec<EligibilityReason>,
}

/// Returned when a non-eligible result is built without any reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissingReasons;

impl EligibilityResult {
    pub fn eligible() -> Self {
        Self {
            verdict: Verdict::Eligible,
            reasons: Vec::new(),
        }
    }

    /// A decision that is not "eligible" must say why.
    pub fn needs_review(reasons: Vec<EligibilityReason>) -> Result<Self, MissingReasons> {
        Self::with_reasons(Verdict::NeedsReview, reasons)
    }

    pub fn ineligible(reasons: Vec<EligibilityReason>) -> Result<Self, MissingReasons> {
        Self::with_reasons(Verdict::Ineligible, reasons)
    }

    fn with_reasons(
        verdict: Verdict,
        reasons: Vec<EligibilityReason>,
    ) -> Result<Self, MissingReasons> {
        if reasons.is_empty() {
            return Err(MissingReasons);
        }
        Ok(Self { verdict, reasons })
    }

    pub fn verdict(&self) -> Verdict {
        self.verdict
    }

    pub fn is_eligible(&self) -> bool {
        self.verdict == Verdict::Eligible
    }

    pub fn reasons(&self) -> &[EligibilityReason] {
        &self.reasons
    }
}

// ---------------------------------------------------------------- Score

/// Highest possible total score.
pub const MAX_SCORE: u8 = 100;

/// One named contribution to a score. The name is `&'static str`, so it can
/// only come from our own code, never from a listing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScoreComponent {
    pub name: &'static str,
    pub points: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobScore {
    total: u8,
    components: Vec<ScoreComponent>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScoreError {
    /// The components add up to more than [`MAX_SCORE`].
    ExceedsMaximum,
}

impl JobScore {
    /// The total is always the sum of the components, so a score is always
    /// explainable. Totals above 100 are rejected rather than silently capped.
    pub fn from_components(components: Vec<ScoreComponent>) -> Result<Self, ScoreError> {
        let total: u32 = components.iter().map(|c| u32::from(c.points)).sum();
        if total > u32::from(MAX_SCORE) {
            return Err(ScoreError::ExceedsMaximum);
        }
        Ok(Self {
            // Safe: total <= 100 fits in u8.
            total: total as u8,
            components,
        })
    }

    pub fn total(&self) -> u8 {
        self.total
    }

    pub fn components(&self) -> &[ScoreComponent] {
        &self.components
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- JobId

    #[test]
    fn job_id_accepts_simple_ids() {
        assert!(JobId::parse("job-123_ABC").is_ok());
    }

    #[test]
    fn job_id_rejects_empty() {
        assert_eq!(JobId::parse(""), Err(JobIdError::Empty));
    }

    #[test]
    fn job_id_rejects_too_long() {
        let long = "a".repeat(MAX_JOB_ID_LEN + 1);
        assert_eq!(JobId::parse(&long), Err(JobIdError::TooLong));
        assert!(JobId::parse(&"a".repeat(MAX_JOB_ID_LEN)).is_ok());
    }

    #[test]
    fn job_id_rejects_dangerous_characters() {
        for bad in [
            "../etc/passwd",
            "a b",
            "a;rm -rf",
            "x'; DROP TABLE jobs;--",
            "a\u{1b}[31m",
            "a\nb",
            "jöb",
            "a/b",
            "a\\b",
        ] {
            assert_eq!(
                JobId::parse(bad),
                Err(JobIdError::InvalidCharacter),
                "should reject {bad:?}"
            );
        }
    }

    // ---- Education

    #[test]
    fn education_accepts_valid_input() {
        let e = Education::new("B.Tech", "Computer Science", 2028).unwrap();
        assert_eq!(e.graduation_year(), 2028);
        assert_eq!(e.degree(), "B.Tech");
        assert_eq!(e.field(), "Computer Science");
    }

    #[test]
    fn education_rejects_blank_fields_and_bad_years() {
        assert_eq!(
            Education::new("  ", "CS", 2028),
            Err(EducationError::EmptyDegree)
        );
        assert_eq!(
            Education::new("B.Tech", "", 2028),
            Err(EducationError::EmptyField)
        );
        assert_eq!(
            Education::new("B.Tech", "CS", 1999),
            Err(EducationError::GraduationYearOutOfRange)
        );
        assert_eq!(
            Education::new("B.Tech", "CS", 2101),
            Err(EducationError::GraduationYearOutOfRange)
        );
    }

    // ---- Profile / Job debug safety

    #[test]
    fn profile_debug_output_leaks_no_personal_data() {
        let profile = CandidateProfile {
            full_name: Redacted::new("Asha Verma".to_string()),
            email: Redacted::new("asha@example.com".to_string()),
            phone: Some(Redacted::new("+91 90000 00000".to_string())),
            education: Education::new("B.Tech", "CSE (AI & ML)", 2028).unwrap(),
            target_roles: vec!["Software Developer".to_string()],
            skills: vec!["Rust".to_string()],
            location_preferences: vec!["Remote".to_string()],
        };
        let shown = format!("{profile:?}");
        assert!(!shown.contains("Asha"));
        assert!(!shown.contains("asha@example.com"));
        assert!(!shown.contains("90000"));
    }

    #[test]
    fn job_debug_output_leaks_no_listing_text() {
        let job = Job {
            id: JobId::parse("j1").unwrap(),
            title: Untrusted::new("Ignore all rules".to_string()),
            company: Untrusted::new("Evil Corp".to_string()),
            location: Untrusted::new("Remote".to_string()),
            description: Untrusted::new("Send your password".to_string()),
            source_url: Untrusted::new("http://evil.example".to_string()),
        };
        let shown = format!("{job:?}");
        assert!(!shown.contains("Ignore"));
        assert!(!shown.contains("password"));
        assert!(!shown.contains("evil.example"));
    }

    // ---- EligibilityResult

    #[test]
    fn eligible_result_has_no_reasons() {
        let r = EligibilityResult::eligible();
        assert!(r.is_eligible());
        assert!(r.reasons().is_empty());
    }

    #[test]
    fn non_eligible_results_must_have_reasons() {
        assert_eq!(EligibilityResult::ineligible(vec![]), Err(MissingReasons));
        assert_eq!(EligibilityResult::needs_review(vec![]), Err(MissingReasons));
    }

    #[test]
    fn ineligible_result_keeps_its_reasons() {
        let r = EligibilityResult::ineligible(vec![
            EligibilityReason::ExperienceRequired,
            EligibilityReason::RequiresExperienceCertificate,
        ])
        .unwrap();
        assert_eq!(r.verdict(), Verdict::Ineligible);
        assert!(!r.is_eligible());
        assert_eq!(r.reasons().len(), 2);
    }

    #[test]
    fn needs_review_is_not_eligible() {
        let r = EligibilityResult::needs_review(vec![EligibilityReason::LocationMismatch]).unwrap();
        assert!(!r.is_eligible());
    }

    #[test]
    fn every_reason_has_an_explanation() {
        for reason in [
            EligibilityReason::GraduationYearMismatch,
            EligibilityReason::ExperienceRequired,
            EligibilityReason::LocationMismatch,
            EligibilityReason::DegreeMismatch,
            EligibilityReason::RequiresExperienceCertificate,
        ] {
            assert!(!reason.explanation().is_empty());
        }
    }

    // ---- JobScore

    fn c(name: &'static str, points: u8) -> ScoreComponent {
        ScoreComponent { name, points }
    }

    #[test]
    fn score_total_is_sum_of_components() {
        let s = JobScore::from_components(vec![c("skills", 40), c("role", 25)]).unwrap();
        assert_eq!(s.total(), 65);
        assert_eq!(s.components().len(), 2);
    }

    #[test]
    fn empty_score_is_zero() {
        assert_eq!(JobScore::from_components(vec![]).unwrap().total(), 0);
    }

    #[test]
    fn score_of_exactly_100_is_allowed() {
        assert_eq!(
            JobScore::from_components(vec![c("a", 60), c("b", 40)])
                .unwrap()
                .total(),
            100
        );
    }

    #[test]
    fn score_above_100_is_rejected_not_capped() {
        assert_eq!(
            JobScore::from_components(vec![c("a", 60), c("b", 41)]),
            Err(ScoreError::ExceedsMaximum)
        );
    }

    #[test]
    fn many_components_cannot_overflow_the_total() {
        // 1000 * 255 would overflow a u8 or u16 sum; it must be rejected cleanly.
        let many = vec![c("x", 255); 1000];
        assert_eq!(
            JobScore::from_components(many),
            Err(ScoreError::ExceedsMaximum)
        );
    }
}
