//! Text normalisation for scanning.
//!
//! Scans look for phrases in untrusted text, so the text is reduced to a plain
//! form first. Two forms are produced because attackers split phrases in two
//! different ways:
//!
//! * [`normalize_for_scan`]: non-ASCII characters become *spaces* (so
//!   `registration–fee` with an en dash still reads as two words). ASCII
//!   punctuation is kept.
//! * [`loose`]: invisible and other non-ASCII characters are *deleted* (so a
//!   soft hyphen inside `regis\u{ad}tration` vanishes), and all ASCII
//!   punctuation becomes a space (so `registration-fee` and `registration_fee`
//!   read as two words).
//!
//! Both fold fullwidth letters (`ｉｇｎｏｒｅ`) to ASCII. Look-alike letters from
//! other alphabets (for example Cyrillic `а`) are **not** mapped; that is a
//! documented limit.
//!
//! Both outputs are pure ASCII, so slicing by byte index cannot panic.

/// Fullwidth ASCII forms (U+FF01 to U+FF5E) map to their ASCII equivalents.
fn fold(c: char) -> char {
    if ('\u{FF01}'..='\u{FF5E}').contains(&c) {
        char::from_u32(c as u32 - 0xFEE0).unwrap_or(c)
    } else {
        c
    }
}

/// Lowercases, replaces everything that is not printable ASCII with a space,
/// and collapses runs of whitespace.
pub fn normalize_for_scan(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut last_space = true;
    for c in input.chars().map(fold) {
        let mapped = if c.is_ascii_graphic() {
            c.to_ascii_lowercase()
        } else {
            ' '
        };
        if mapped == ' ' {
            if !last_space {
                out.push(' ');
            }
            last_space = true;
        } else {
            out.push(mapped);
            last_space = false;
        }
    }
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

/// Keeps ASCII letters and digits (lowercased). ASCII punctuation, controls
/// and whitespace become single spaces. Other non-ASCII characters are removed.
pub fn loose(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut last_space = true;
    for c in input.chars().map(fold) {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            last_space = false;
        } else if (c.is_ascii() || c.is_whitespace()) && !last_space {
            out.push(' ');
            last_space = true;
        }
        // any other non-ASCII character is dropped
    }
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

/// Whether `pat` occurs in `hay` as a whole phrase.
///
/// An alphanumeric edge of the pattern must sit on a word boundary, so
/// `training fee` does not match `training feedback` and `no interview` does
/// not match `piano interview`. A plural `s` after the phrase is allowed
/// (`gift cards`, `deposits`). Both arguments must already be normalised
/// (ASCII).
pub fn contains_phrase(hay: &str, pat: &str) -> bool {
    if pat.is_empty() || !hay.is_ascii() || !pat.is_ascii() {
        return false;
    }
    let hb = hay.as_bytes();
    let pb = pat.as_bytes();
    let alnum = |b: u8| b.is_ascii_alphanumeric();
    let need_left = alnum(pb[0]);
    let need_right = alnum(pb[pb.len() - 1]);

    let mut from = 0;
    while let Some(rel) = hay[from..].find(pat) {
        let at = from + rel;
        let end = at + pat.len();
        let left_ok = !need_left || at == 0 || !alnum(hb[at - 1]);
        let right_ok = !need_right
            || end == hb.len()
            || !alnum(hb[end])
            || (hb[end] == b's' && (end + 1 == hb.len() || !alnum(hb[end + 1])));
        if left_ok && right_ok {
            return true;
        }
        from = at + 1;
    }
    false
}

/// Checks `pattern` against both normalised forms of the same text.
pub struct Scannable {
    normal: String,
    loose: String,
}

impl Scannable {
    pub fn new(raw: &str) -> Self {
        Self {
            normal: normalize_for_scan(raw),
            loose: loose(raw),
        }
    }

    pub fn contains(&self, pattern: &str) -> bool {
        contains_phrase(&self.normal, &normalize_for_scan(pattern))
            || contains_phrase(&self.loose, &loose(pattern))
    }

    /// The `loose` form, for rules that need more than a fixed phrase.
    pub fn loose_text(&self) -> &str {
        &self.loose
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowercases_and_collapses_whitespace() {
        assert_eq!(normalize_for_scan("  Hello \n\t WORLD  "), "hello world");
    }

    #[test]
    fn non_ascii_becomes_a_separator() {
        assert_eq!(normalize_for_scan("café\u{200B}x"), "caf x");
    }

    #[test]
    fn output_is_always_ascii() {
        assert!(normalize_for_scan("é\u{1b}[31m✓ok").is_ascii());
        assert!(loose("é\u{1b}[31m✓ok").is_ascii());
    }

    #[test]
    fn empty_input_gives_empty_output() {
        assert_eq!(normalize_for_scan(""), "");
        assert_eq!(normalize_for_scan("   "), "");
        assert_eq!(loose(""), "");
    }

    #[test]
    fn fullwidth_letters_are_folded() {
        assert_eq!(normalize_for_scan("ｉｇｎｏｒｅ"), "ignore");
        assert_eq!(loose("ＩＧＮＯＲＥ"), "ignore");
    }

    #[test]
    fn loose_deletes_invisible_characters_and_splits_on_punctuation() {
        assert_eq!(loose("regis\u{00AD}tration"), "registration");
        assert_eq!(loose("registration-fee"), "registration fee");
        assert_eq!(loose("REGISTRATION_FEE"), "registration fee");
        assert_eq!(loose("a\u{00A0}b"), "a b"); // non-breaking space is whitespace
        assert_eq!(loose("don't"), "don t");
    }

    #[test]
    fn phrases_need_word_boundaries() {
        assert!(contains_phrase("pay the training fee now", "training fee"));
        assert!(!contains_phrase(
            "training feedback sessions",
            "training fee"
        ));
        assert!(!contains_phrase("a piano interview club", "no interview"));
        assert!(contains_phrase("there is no interview", "no interview"));
    }

    #[test]
    fn plural_s_is_allowed_but_other_suffixes_are_not() {
        assert!(contains_phrase("buy gift cards today", "gift card"));
        assert!(contains_phrase("refundable deposits", "refundable deposit"));
        assert!(!contains_phrase("gift cardigan", "gift card"));
    }

    #[test]
    fn patterns_with_symbol_edges_match_without_boundary_rules() {
        assert!(contains_phrase("mail hr@gmail.com now", "@gmail.com"));
        assert!(contains_phrase("<|im_start|>", "<|"));
    }

    #[test]
    fn empty_or_non_ascii_inputs_never_match_or_panic() {
        assert!(!contains_phrase("abc", ""));
        assert!(!contains_phrase("é", "é"));
    }

    #[test]
    fn scannable_matches_either_form() {
        // soft hyphen inside a word: the loose form deletes it
        assert!(Scannable::new("regis\u{00AD}tration fee").contains("registration fee"));
        // en dash between words: the normal form reads it as a space
        assert!(Scannable::new("registration–fee").contains("registration fee"));
        let s = Scannable::new("registration-fee");
        assert!(s.contains("registration fee"));
        assert!(!Scannable::new("training feedback").contains("training fee"));
    }
}
