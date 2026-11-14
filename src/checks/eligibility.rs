//! Eligibility rules for a fresher / early-career applicant.
//!
//! All inputs must come from [`crate::checks::text::normalize_for_scan`], which
//! guarantees pure ASCII, so slicing by byte index is safe.
//!
//! These are heuristics over free text. They decide *ineligible*, *needs
//! review* or *eligible*, with a closed list of reasons the user can read.
//! When the text is ambiguous the result is "needs review", never "eligible".

use crate::domain::models::{CandidateProfile, EligibilityReason, EligibilityResult};

const NUMBER_WORDS: &[(&str, u32)] = &[
    ("zero", 0),
    ("one", 1),
    ("two", 2),
    ("three", 3),
    ("four", 4),
    ("five", 5),
    ("six", 6),
    ("seven", 7),
    ("eight", 8),
    ("nine", 9),
    ("ten", 10),
    ("eleven", 11),
    ("twelve", 12),
    ("fifteen", 15),
];

/// A number written as 1 to 2 digits or as a word ("three").
fn number_of(token: &str) -> Option<u32> {
    if !token.is_empty() && token.len() <= 2 && token.bytes().all(|b| b.is_ascii_digit()) {
        return token.parse().ok();
    }
    NUMBER_WORDS
        .iter()
        .find(|(w, _)| *w == token)
        .map(|(_, n)| *n)
}

/// Splits off the last alphanumeric token of `s`: "... 3" -> ("... ", "3").
fn last_token(s: &str) -> (&str, &str) {
    let len = s
        .bytes()
        .rev()
        .take_while(|b| b.is_ascii_alphanumeric())
        .count();
    s.split_at(s.len() - len)
}

/// Trailing number of `s`, rejecting digit runs longer than two ("2024 year").
fn trailing_number(s: &str) -> Option<(u32, &str)> {
    let (rest, token) = last_token(s);
    Some((number_of(token)?, rest))
}

fn mentions_experience(window: &str) -> bool {
    window
        .split(|c: char| !c.is_ascii_alphabetic())
        .any(|w| matches!(w, "experience" | "experienced" | "exp"))
}

/// The largest "N years of experience" requirement mentioned, using the lower
/// end of ranges ("2-4 years" -> 2). `None` if nothing is mentioned.
///
/// Recognises "years", "yrs", "yr", digits and number words ("three"),
/// "3 (three) years", "5+yrs", and "exp". When experience is clearly being
/// discussed next to "years" but the number is not directly attached
/// ("at least 3 full-time years of experience"), the result is `Some(1)`, which
/// the caller treats as "needs review" rather than silently eligible.
pub fn min_years_required(t: &str) -> Option<u32> {
    let bytes = t.as_bytes();
    let mut best: Option<u32> = None;
    let mut note = |n: u32| best = Some(best.map_or(n, |b| b.max(n)));

    for at in 0..t.len() {
        let rest = &t[at..];
        if !(rest.starts_with("year") || rest.starts_with("yr")) {
            continue;
        }
        // Must start a word (a digit before is fine: "3years").
        if at > 0 && bytes[at - 1].is_ascii_alphabetic() {
            continue;
        }

        let lo = at.saturating_sub(60);
        let hi = (at + 60).min(t.len());
        if !mentions_experience(&t[lo..hi]) {
            continue;
        }

        let before = t[..at].trim_end_matches([' ', '+', ')', '(']);
        if let Some((right, prefix)) = trailing_number(before) {
            // Ranges: "2-4 years" or "2 to 4 years" -> use the left number.
            let p = prefix.trim_end();
            let left = if let Some(q) = p.strip_suffix('-') {
                trailing_number(q.trim_end()).map(|(n, _)| n)
            } else if let Some(q) = p.strip_suffix(" to") {
                trailing_number(q.trim_end()).map(|(n, _)| n)
            } else {
                None
            };
            note(left.unwrap_or(right));
        } else {
            // No number attached. If a number is close by, flag for review.
            let near = &t[at.saturating_sub(25)..at];
            if near
                .split(' ')
                .any(|w| number_of(w.trim_matches(|c: char| !c.is_ascii_alphanumeric())).is_some())
            {
                note(1);
            }
        }
    }
    best
}

/// Four-digit years (2020..=2035) mentioned next to words about batches or
/// graduation, e.g. "2025 and 2026 batch".
pub fn batch_years(t: &str) -> Vec<u16> {
    const KEYWORDS: &[&str] = &[
        "batch",
        "graduat",
        "pass out",
        "passout",
        "passing out",
        "pass-out",
        "class of",
    ];
    let mut years: Vec<u16> = Vec::new();
    for kw in KEYWORDS {
        let mut from = 0;
        while let Some(rel) = t[from..].find(kw) {
            let at = from + rel;
            from = at + kw.len();
            let lo = at.saturating_sub(40);
            let hi = (at + kw.len() + 40).min(t.len());
            let window = &t[lo..hi];
            let bytes = window.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i].is_ascii_digit() {
                    let start = i;
                    while i < bytes.len() && bytes[i].is_ascii_digit() {
                        i += 1;
                    }
                    if i - start == 4
                        && let Ok(y) = window[start..i].parse::<u16>()
                        && (2020..=2035).contains(&y)
                        && !years.contains(&y)
                    {
                        years.push(y);
                    }
                } else {
                    i += 1;
                }
            }
        }
    }
    years.sort_unstable();
    years
}

/// Whether the job's location suits the candidate's preferences.
/// Unknown or empty information is treated as acceptable: the rule only flags
/// a *clear* mismatch.
pub fn location_ok(job_location: &str, job_text: &str, preferences: &[String]) -> bool {
    if preferences.is_empty() || job_location.is_empty() {
        return true;
    }
    let remote =
        |s: &str| s.contains("remote") || s.contains("work from home") || s.contains("anywhere");
    if remote(job_location) || remote(job_text.get(..job_text.len().min(300)).unwrap_or("")) {
        return true;
    }
    preferences.iter().any(|p| {
        let p = p.trim().to_ascii_lowercase();
        !p.is_empty()
            && (matches!(p.as_str(), "remote" | "anywhere" | "any") || job_location.contains(&p))
    })
}

/// Combines the rules into one result.
///
/// * Ineligible: batch mismatch, 2+ years required, or an experience
///   certificate is required.
/// * Needs review: 1 year required, or the location does not match.
pub fn assess(job_text: &str, job_location: &str, profile: &CandidateProfile) -> EligibilityResult {
    let mut ineligible: Vec<EligibilityReason> = Vec::new();
    let mut review: Vec<EligibilityReason> = Vec::new();

    let batches = batch_years(job_text);
    if !batches.is_empty() && !batches.contains(&profile.education.graduation_year()) {
        ineligible.push(EligibilityReason::GraduationYearMismatch);
    }

    match min_years_required(job_text) {
        Some(n) if n >= 2 => ineligible.push(EligibilityReason::ExperienceRequired),
        Some(1) => review.push(EligibilityReason::ExperienceRequired),
        _ => {}
    }

    if [
        "experience certificate",
        "experience letter",
        "relieving letter",
    ]
    .iter()
    .any(|p| job_text.contains(p))
    {
        ineligible.push(EligibilityReason::RequiresExperienceCertificate);
    }

    if !location_ok(job_location, job_text, &profile.location_preferences) {
        review.push(EligibilityReason::LocationMismatch);
    }

    if !ineligible.is_empty() {
        ineligible.extend(review);
        return EligibilityResult::ineligible(ineligible).expect("non-empty reasons");
    }
    if !review.is_empty() {
        return EligibilityResult::needs_review(review).expect("non-empty reasons");
    }
    EligibilityResult::eligible()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::text::normalize_for_scan as n;
    use crate::domain::models::{Education, Verdict};
    use crate::domain::sensitive::Redacted;

    fn profile(year: u16, locations: &[&str]) -> CandidateProfile {
        CandidateProfile {
            full_name: Redacted::new("T".into()),
            email: Redacted::new("t@example.com".into()),
            phone: None,
            education: Education::new("B.Tech", "CSE", year).unwrap(),
            target_roles: vec![],
            skills: vec![],
            location_preferences: locations.iter().map(|s| s.to_string()).collect(),
        }
    }

    // ---- experience

    #[test]
    fn finds_simple_and_plus_forms() {
        assert_eq!(
            min_years_required(&n("3 years of experience in Java")),
            Some(3)
        );
        assert_eq!(
            min_years_required(&n("5+ years experience required")),
            Some(5)
        );
        assert_eq!(
            min_years_required(&n("Minimum 2 years' experience")),
            Some(2)
        );
        assert_eq!(min_years_required(&n("1 year experience")), Some(1));
    }

    #[test]
    fn ranges_use_the_lower_number() {
        assert_eq!(min_years_required(&n("2-4 years of experience")), Some(2));
        assert_eq!(min_years_required(&n("3 to 5 years experience")), Some(3));
        assert_eq!(min_years_required(&n("0-1 years of experience")), Some(0));
    }

    #[test]
    fn ignores_years_without_experience_context() {
        assert_eq!(
            min_years_required(&n("Founded 10 years ago, growing fast")),
            None
        );
        assert_eq!(
            min_years_required(&n("Internship for 2 years duration")),
            None
        );
    }

    #[test]
    fn four_digit_years_are_not_experience() {
        assert_eq!(
            min_years_required(&n("experience since the year 2024")),
            None
        );
    }

    #[test]
    fn takes_the_strictest_mention() {
        assert_eq!(
            min_years_required(&n(
                "1 year experience with C and 4 years of experience overall"
            )),
            Some(4)
        );
    }

    #[test]
    fn no_mention_is_none() {
        assert_eq!(
            min_years_required(&n("Freshers welcome. Rust and SQL.")),
            None
        );
        assert_eq!(min_years_required(""), None);
    }

    // ---- batch

    #[test]
    fn finds_batch_years() {
        assert_eq!(
            batch_years(&n("2025 and 2026 batch only")),
            vec![2025, 2026]
        );
        assert_eq!(batch_years(&n("Graduating in 2027")), vec![2027]);
        assert_eq!(batch_years(&n("Class of 2028")), vec![2028]);
    }

    #[test]
    fn ignores_years_far_from_batch_words() {
        let t = n(&format!(
            "We were founded in 2021. {} Apply for the batch.",
            "x ".repeat(60)
        ));
        assert!(batch_years(&t).is_empty());
    }

    #[test]
    fn ignores_out_of_range_and_non_year_numbers() {
        assert!(batch_years(&n("batch 1999 or 12345 or 20266")).is_empty());
    }

    // ---- location

    #[test]
    fn location_rules() {
        let prefs = vec!["bengaluru".to_string(), "remote".to_string()];
        assert!(location_ok("bengaluru, india", "", &prefs));
        assert!(location_ok("pune", "", &prefs)); // "remote" in prefs = anywhere
        let strict = vec!["bengaluru".to_string()];
        assert!(!location_ok("pune", "great team", &strict));
        assert!(location_ok("remote (india)", "", &strict));
        assert!(location_ok("", "", &strict));
        assert!(location_ok("pune", "", &[]));
    }

    // ---- assess

    #[test]
    fn fresher_friendly_job_is_eligible() {
        let r = assess(
            &n("software intern freshers welcome rust sql"),
            "remote",
            &profile(2028, &["remote"]),
        );
        assert_eq!(r.verdict(), Verdict::Eligible);
    }

    #[test]
    fn two_plus_years_is_ineligible() {
        let r = assess(
            &n("requires 3+ years of experience"),
            "",
            &profile(2028, &[]),
        );
        assert_eq!(r.verdict(), Verdict::Ineligible);
        assert!(r.reasons().contains(&EligibilityReason::ExperienceRequired));
    }

    #[test]
    fn one_year_needs_review() {
        let r = assess(
            &n("1 year of experience preferred"),
            "",
            &profile(2028, &[]),
        );
        assert_eq!(r.verdict(), Verdict::NeedsReview);
    }

    #[test]
    fn wrong_batch_is_ineligible_right_batch_is_not() {
        let t = n("open to 2025 and 2026 batch");
        assert_eq!(
            assess(&t, "", &profile(2028, &[])).verdict(),
            Verdict::Ineligible
        );
        assert_eq!(
            assess(&t, "", &profile(2026, &[])).verdict(),
            Verdict::Eligible
        );
    }

    #[test]
    fn experience_certificate_requirement_is_ineligible() {
        let r = assess(
            &n("must submit relieving letter from previous company"),
            "",
            &profile(2028, &[]),
        );
        assert_eq!(r.verdict(), Verdict::Ineligible);
        assert!(
            r.reasons()
                .contains(&EligibilityReason::RequiresExperienceCertificate)
        );
    }

    #[test]
    fn location_mismatch_needs_review_but_does_not_make_ineligible() {
        let r = assess(&n("great role"), "pune", &profile(2028, &["bengaluru"]));
        assert_eq!(r.verdict(), Verdict::NeedsReview);
        assert_eq!(r.reasons(), &[EligibilityReason::LocationMismatch]);
    }

    #[test]
    fn ineligible_result_also_lists_review_reasons() {
        let r = assess(
            &n("5 years of experience"),
            "pune",
            &profile(2028, &["bengaluru"]),
        );
        assert_eq!(r.verdict(), Verdict::Ineligible);
        assert_eq!(r.reasons().len(), 2);
    }
}
