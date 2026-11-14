//! Pure-safe-Rust reference implementation of the matcher's rules.
//! Must behave identically to `c/matcher.c`; see the differential test in
//! `matching/mod.rs`.

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'#' || b == b'_'
}

fn contains_word(text: &[u8], skill: &[u8]) -> bool {
    if skill.is_empty() || skill.len() > text.len() {
        return false;
    }
    for i in 0..=(text.len() - skill.len()) {
        if i > 0 && is_word(text[i - 1]) {
            continue;
        }
        let same = text[i..i + skill.len()]
            .iter()
            .zip(skill)
            .all(|(a, b)| a.eq_ignore_ascii_case(b));
        if same && (i + skill.len() == text.len() || !is_word(text[i + skill.len()])) {
            return true;
        }
    }
    false
}

/// `skills` is newline-separated; empty entries are skipped (as in C).
pub(super) fn run(text: &[u8], skills: &[u8]) -> Vec<bool> {
    skills
        .split(|b| *b == b'\n')
        .filter(|s| !s.is_empty())
        .map(|s| contains_word(text, s))
        .collect()
}
