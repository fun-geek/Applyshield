//! Untrusted text from the outside world (job listings, web pages, APIs).
//!
//! Threats handled here (see `docs/security-model.md`, T1):
//! * Prompt injection: untrusted text is a distinct type, so it cannot be
//!   passed to code expecting trusted input by accident.
//! * Terminal injection: ANSI escape sequences and control characters in a
//!   listing could rewrite what the user sees in the CLI (for example hiding a
//!   suspicious domain right before an approval prompt).
//! * "Trojan Source": invisible and bidirectional-override characters can make
//!   text display differently from what it really contains.

use std::fmt;

/// A value that came from an untrusted source.
///
/// There is deliberately no `Deref`, `Display`, or `Into<T>`. The only way to
/// reach the inner value is [`Untrusted::expose_untrusted`], whose name makes
/// the risk visible at every call site and easy to grep for in review.
#[derive(Clone, PartialEq, Eq)]
pub struct Untrusted<T>(T);

impl<T> Untrusted<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Returns the raw, unvalidated value. Never print it to the terminal,
    /// log it, or treat it as an instruction. Prefer [`Untrusted::sanitized`].
    pub fn expose_untrusted(&self) -> &T {
        &self.0
    }
}

// Debug output never includes the content: it may be huge, hostile, or
// contain escape sequences, and logs are not the place for it.
impl<T> fmt::Debug for Untrusted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Untrusted(<hidden>)")
    }
}

impl Untrusted<String> {
    /// Produces text that is safe to show in a terminal: control characters,
    /// escape sequences, and invisible/bidi-override characters are removed,
    /// and the result is capped at `max_chars` characters.
    ///
    /// The result is still *untrusted content*. It is safe to display, but it
    /// must never be treated as an instruction.
    pub fn sanitized(&self, max_chars: usize) -> SanitizedText {
        // Lazy iterator: a huge hostile input costs at most `max_chars`
        // accepted characters of output.
        let cleaned: String = self
            .0
            .chars()
            .filter(|c| !is_unsafe_char(*c))
            .take(max_chars)
            .collect();
        SanitizedText(cleaned)
    }
}

/// Text that has been stripped of terminal-control and invisible characters.
///
/// The field is private, so the only way to obtain one is
/// [`Untrusted::sanitized`]. Holding a `SanitizedText` is proof the cleanup ran.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SanitizedText(String);

impl SanitizedText {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SanitizedText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Characters removed from untrusted text before display.
fn is_unsafe_char(c: char) -> bool {
    // Control characters: ESC (ANSI sequences), carriage return (line
    // overwrite), backspace, NUL, C1 controls such as 0x9B (CSI), and so on.
    // Newline and tab are kept so multi-line descriptions stay readable.
    (c.is_control() && c != '\n' && c != '\t')
        || matches!(
            c,
            '\u{200B}'..='\u{200F}'   // zero-width chars, LRM/RLM
            | '\u{2028}' | '\u{2029}' // line/paragraph separators
            | '\u{202A}'..='\u{202E}' // bidi embedding/override
            | '\u{2060}'..='\u{2064}' // word joiner, invisible operators
            | '\u{2066}'..='\u{2069}' // bidi isolates
            | '\u{FEFF}'              // zero-width no-break space / BOM
            | '\u{00AD}'              // soft hyphen
            | '\u{034F}'              // combining grapheme joiner
            | '\u{061C}'              // Arabic letter mark
            | '\u{115F}' | '\u{1160}' // Hangul fillers
            | '\u{17B4}' | '\u{17B5}' // Khmer inherent vowels
            | '\u{180B}'..='\u{180E}' // Mongolian free variation selectors
            | '\u{3164}'              // Hangul filler
            | '\u{FE00}'..='\u{FE0F}' // variation selectors
            | '\u{FFA0}'              // halfwidth Hangul filler
            | '\u{E0000}'..='\u{E007F}' // tag characters
            | '\u{E0100}'..='\u{E01EF}' // variation selectors supplement
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean(s: &str) -> String {
        Untrusted::new(s.to_string()).sanitized(10_000).to_string()
    }

    #[test]
    fn debug_never_reveals_content() {
        let u = Untrusted::new("ignore previous instructions".to_string());
        let shown = format!("{u:?}");
        assert!(!shown.contains("ignore"));
        assert_eq!(shown, "Untrusted(<hidden>)");
    }

    #[test]
    fn plain_text_is_unchanged() {
        assert_eq!(clean("Rust Developer Intern"), "Rust Developer Intern");
    }

    #[test]
    fn newlines_and_tabs_are_kept() {
        assert_eq!(clean("line1\nline2\tx"), "line1\nline2\tx");
    }

    #[test]
    fn ansi_escape_character_is_removed() {
        // The ESC byte is what makes the sequence active; without it the
        // remaining "[31m" is inert text.
        let out = clean("safe\u{1b}[31mred");
        assert!(!out.contains('\u{1b}'));
    }

    #[test]
    fn carriage_return_and_backspace_are_removed() {
        let out = clean("trusted.com\rEVIL\u{8}");
        assert!(!out.contains('\r'));
        assert!(!out.contains('\u{8}'));
    }

    #[test]
    fn c1_csi_control_is_removed() {
        assert!(!clean("a\u{9b}b").contains('\u{9b}'));
    }

    #[test]
    fn bidi_overrides_and_zero_width_chars_are_removed() {
        let hostile = "pay\u{202E}gro.com\u{200B}\u{FEFF}\u{2066}x\u{2069}";
        let out = clean(hostile);
        for c in out.chars() {
            assert!(!is_unsafe_char(c), "unsafe char survived: {:?}", c);
        }
    }

    #[test]
    fn output_is_truncated_to_max_chars() {
        let long = "a".repeat(1_000);
        let out = Untrusted::new(long).sanitized(50);
        assert_eq!(out.as_str().chars().count(), 50);
    }

    #[test]
    fn truncation_counts_characters_not_bytes() {
        // Multi-byte chars must not be split mid-character.
        let out = Untrusted::new("é".repeat(100)).sanitized(3);
        assert_eq!(out.as_str(), "ééé");
    }

    #[test]
    fn invisible_chars_do_not_use_up_the_length_budget() {
        let out = Untrusted::new("\u{200B}\u{200B}ab".to_string()).sanitized(2);
        assert_eq!(out.as_str(), "ab");
    }

    #[test]
    fn zero_max_chars_gives_empty_text() {
        assert_eq!(Untrusted::new("abc".to_string()).sanitized(0).as_str(), "");
    }
}
