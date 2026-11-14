//! Scam heuristics for job listings (threat T2).
//!
//! These are simple phrase checks, not a guarantee. They catch the common
//! patterns: asking the applicant to pay, "no interview" promises, and moving
//! the conversation to chat apps or free email addresses.
//!
//! A `High` flag blocks drafting. A `Medium` flag is shown as a warning.
//! Input is raw (already sanitised) text; both normal forms are checked.

use crate::checks::text::Scannable;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScamFlag {
    pub name: &'static str,
    pub severity: Severity,
}

const RULES: &[(&str, &str, Severity)] = &[
    // Applicant is asked to pay.
    (
        "registration fee",
        "asks for a registration fee",
        Severity::High,
    ),
    (
        "application fee",
        "asks for an application fee",
        Severity::High,
    ),
    (
        "processing fee",
        "asks for a processing fee",
        Severity::High,
    ),
    ("training fee", "asks for a training fee", Severity::High),
    (
        "security deposit",
        "asks for a security deposit",
        Severity::High,
    ),
    (
        "refundable deposit",
        "asks for a refundable deposit",
        Severity::High,
    ),
    ("pay a fee", "asks you to pay a fee", Severity::High),
    ("pay to apply", "asks you to pay to apply", Severity::High),
    (
        "pay for training",
        "asks you to pay for training",
        Severity::High,
    ),
    ("send money", "asks you to send money", Severity::High),
    ("gift card", "mentions gift cards", Severity::High),
    ("wire transfer", "mentions wire transfers", Severity::High),
    // Too-good-to-be-true promises.
    (
        "guaranteed job",
        "promises a guaranteed job",
        Severity::High,
    ),
    (
        "guaranteed placement",
        "promises guaranteed placement",
        Severity::High,
    ),
    ("no interview", "promises no interview", Severity::High),
    (
        "without interview",
        "promises hiring without an interview",
        Severity::High,
    ),
    (
        "direct joining",
        "promises direct joining",
        Severity::Medium,
    ),
    (
        "limited seats",
        "uses pressure tactics (limited seats)",
        Severity::Medium,
    ),
    // Off-platform or throwaway contact.
    ("whatsapp", "moves contact to WhatsApp", Severity::Medium),
    ("telegram", "moves contact to Telegram", Severity::Medium),
    (
        "@gmail.com",
        "recruiter uses a free email address",
        Severity::Medium,
    ),
    (
        "@yahoo.",
        "recruiter uses a free email address",
        Severity::Medium,
    ),
    (
        "@outlook.",
        "recruiter uses a free email address",
        Severity::Medium,
    ),
    (
        "@hotmail.",
        "recruiter uses a free email address",
        Severity::Medium,
    ),
    // Asks for sensitive documents up front.
    ("aadhaar", "asks for Aadhaar details", Severity::Medium),
    ("aadhar", "asks for Aadhaar details", Severity::Medium),
    ("pan card", "asks for PAN card details", Severity::Medium),
    (
        "bank account",
        "asks for bank account details",
        Severity::Medium,
    ),
    (
        "passport copy",
        "asks for a passport copy",
        Severity::Medium,
    ),
];

/// True when "pay" (or payment/paid) appears shortly before the word "fee",
/// which catches rewordings such as "pay a one-time fee of Rs 500".
fn pay_near_fee(loose_text: &str) -> bool {
    let b = loose_text.as_bytes();
    let alnum = |x: u8| x.is_ascii_alphanumeric();
    for (at, _) in loose_text.match_indices("fee") {
        let end = at + 3;
        let left_ok = at == 0 || !alnum(b[at - 1]);
        let right_ok = end == b.len()
            || !alnum(b[end])
            || (b[end] == b's' && (end + 1 == b.len() || !alnum(b[end + 1])));
        if !(left_ok && right_ok) {
            continue;
        }
        let window = &loose_text[at.saturating_sub(30)..at];
        if window
            .split(' ')
            .any(|w| w.starts_with("pay") || w == "paid")
        {
            return true;
        }
    }
    false
}

/// Scans raw (sanitised) listing text. Returns each distinct flag once,
/// highest severity first.
pub fn scan(raw: &str) -> Vec<ScamFlag> {
    let text = Scannable::new(raw);
    let mut flags: Vec<ScamFlag> = Vec::new();
    let mut add = |name: &'static str, severity: Severity| {
        if !flags.iter().any(|f| f.name == name) {
            flags.push(ScamFlag { name, severity });
        }
    };

    for (pattern, name, severity) in RULES {
        if text.contains(pattern) {
            add(name, *severity);
        }
    }
    if text.contains("earn") && text.contains("per day") {
        add("promises daily earnings", Severity::High);
    }
    if pay_near_fee(text.loose_text()) {
        add("asks you to pay a fee", Severity::High);
    }

    flags.sort_by_key(|f| std::cmp::Reverse(f.severity == Severity::High));
    flags
}

pub fn has_high(flags: &[ScamFlag]) -> bool {
    flags.iter().any(|f| f.severity == Severity::High)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_raw(s: &str) -> Vec<ScamFlag> {
        scan(s)
    }

    #[test]
    fn clean_listing_has_no_flags() {
        assert!(
            scan_raw("Software Developer Intern. Rust, C, SQL. Apply via our careers page.")
                .is_empty()
        );
    }

    #[test]
    fn payment_requests_are_high() {
        for t in [
            "A refundable Security Deposit of Rs 5000 is required",
            "Pay the REGISTRATION   FEE to confirm your seat",
            "training fee applies",
            "Please send money for the kit",
            "buy a gift card",
        ] {
            assert!(has_high(&scan_raw(t)), "{t}");
        }
    }

    #[test]
    fn too_good_to_be_true_promises_are_high() {
        assert!(has_high(&scan_raw("100% guaranteed job, no interview!")));
        assert!(has_high(&scan_raw("Earn Rs 2000 per day from home")));
    }

    #[test]
    fn off_platform_contact_is_medium_not_high() {
        let f = scan_raw("Send your CV on WhatsApp or hr.team@gmail.com");
        assert!(!f.is_empty());
        assert!(!has_high(&f));
    }

    #[test]
    fn sensitive_document_requests_are_medium() {
        let f = scan_raw("Share your Aadhaar and bank account number");
        assert_eq!(f.len(), 2);
        assert!(!has_high(&f));
    }

    #[test]
    fn spacing_and_case_tricks_do_not_hide_phrases() {
        assert!(has_high(&scan_raw("Registration\n\tFEE")));
        assert!(has_high(&scan_raw("rEgIsTrAtIoN fEe\u{200B}")));
    }

    #[test]
    fn each_flag_is_reported_once_and_high_comes_first() {
        let f = scan_raw("whatsapp whatsapp telegram registration fee registration fee");
        assert_eq!(
            f.iter()
                .filter(|x| x.name == "moves contact to WhatsApp")
                .count(),
            1
        );
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn plain_words_do_not_trigger_false_positives() {
        assert!(scan_raw("We offer a competitive salary and a gift of learning").is_empty());
        assert!(scan_raw("Interview process: two technical rounds").is_empty());
    }
}
