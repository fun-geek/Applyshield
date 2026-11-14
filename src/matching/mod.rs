//! Skill matching: the safe Rust face of the C engine.
//!
//! [`skill_hits`] validates inputs, calls the C engine, and validates what comes
//! back. [`skill_hits_reference`] is an independent pure-Rust implementation of
//! the same rules; tests compare the two on large amounts of generated input
//! (differential testing), so a bug in either shows up as a disagreement.

mod ffi;
mod reference;

/// Mirrors the limits in `c/matcher.h`.
pub const MAX_TEXT_LEN: usize = 65_536;
pub const MAX_SKILLS: usize = 128;
pub const MAX_SKILL_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchError {
    TooManySkills,
    SkillTooLong,
    /// A skill was empty or contained a newline or NUL byte.
    InvalidSkill,
    /// The C engine returned an error code or an inconsistent result.
    Engine(i32),
}

struct Prepared<'a> {
    text: &'a [u8],
    joined: Vec<u8>,
    count: usize,
}

fn prepare<'a>(text: &'a str, skills: &[String]) -> Result<Prepared<'a>, MatchError> {
    if skills.len() > MAX_SKILLS {
        return Err(MatchError::TooManySkills);
    }
    let mut joined = Vec::new();
    for (i, s) in skills.iter().enumerate() {
        let b = s.as_bytes();
        if b.is_empty() || b.contains(&b'\n') || b.contains(&0) {
            return Err(MatchError::InvalidSkill);
        }
        if b.len() > MAX_SKILL_LEN {
            return Err(MatchError::SkillTooLong);
        }
        if i > 0 {
            joined.push(b'\n');
        }
        joined.extend_from_slice(b);
    }
    // Only the first MAX_TEXT_LEN bytes are scanned. Byte-wise is fine: the
    // matcher is byte-oriented and never interprets UTF-8.
    let bytes = text.as_bytes();
    let text = &bytes[..bytes.len().min(MAX_TEXT_LEN)];
    Ok(Prepared {
        text,
        joined,
        count: skills.len(),
    })
}

/// For each skill, whether it appears in `text` as a whole word
/// (ASCII case-insensitive). Uses the C engine.
pub fn skill_hits(text: &str, skills: &[String]) -> Result<Vec<bool>, MatchError> {
    let p = prepare(text, skills)?;
    ffi::call(p.text, &p.joined, p.count).map_err(MatchError::Engine)
}

/// Same contract as [`skill_hits`], implemented in safe Rust.
pub fn skill_hits_reference(text: &str, skills: &[String]) -> Result<Vec<bool>, MatchError> {
    let p = prepare(text, skills)?;
    Ok(reference::run(p.text, &p.joined))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|x| x.to_string()).collect()
    }

    fn both(text: &str, skills: &[&str]) -> Vec<bool> {
        let sk = s(skills);
        let c = skill_hits(text, &sk).unwrap();
        let r = skill_hits_reference(text, &sk).unwrap();
        assert_eq!(c, r, "C and reference disagree on {text:?} / {skills:?}");
        c
    }

    #[test]
    fn finds_whole_words_case_insensitively() {
        assert_eq!(
            both("We use RUST and Sql daily", &["rust", "sql", "go"]),
            vec![true, true, false]
        );
    }

    #[test]
    fn does_not_match_inside_other_words() {
        assert_eq!(both("javascript developer", &["java"]), vec![false]);
        assert_eq!(both("trust the process", &["rust"]), vec![false]);
        assert_eq!(both("c++ developer", &["c"]), vec![false]);
    }

    #[test]
    fn handles_symbol_skills() {
        assert_eq!(both("c++ developer", &["c++"]), vec![true]);
        assert_eq!(both("C#, .NET", &["c#"]), vec![true]);
        assert_eq!(both("C/C++ preferred", &["c"]), vec![true]);
    }

    #[test]
    fn no_skills_gives_empty_result() {
        assert_eq!(both("anything", &[]), Vec::<bool>::new());
    }

    #[test]
    fn empty_text_matches_nothing() {
        assert_eq!(both("", &["rust"]), vec![false]);
    }

    #[test]
    fn invalid_skills_are_rejected() {
        assert_eq!(skill_hits("x", &s(&[""])), Err(MatchError::InvalidSkill));
        assert_eq!(
            skill_hits("x", &s(&["a\nb"])),
            Err(MatchError::InvalidSkill)
        );
        assert_eq!(
            skill_hits("x", &s(&["a\0b"])),
            Err(MatchError::InvalidSkill)
        );
        assert_eq!(
            skill_hits("x", &["a".repeat(MAX_SKILL_LEN + 1)]),
            Err(MatchError::SkillTooLong)
        );
    }

    #[test]
    fn too_many_skills_is_rejected() {
        let many: Vec<String> = (0..=MAX_SKILLS).map(|i| format!("s{i}")).collect();
        assert_eq!(skill_hits("x", &many), Err(MatchError::TooManySkills));
        assert_eq!(
            skill_hits_reference("x", &many),
            Err(MatchError::TooManySkills)
        );
    }

    #[test]
    fn max_sized_inputs_are_accepted() {
        let many: Vec<String> = (0..MAX_SKILLS).map(|i| format!("s{i}")).collect();
        let text = "a".repeat(MAX_TEXT_LEN * 2); // longer than the cap: truncated
        let c = skill_hits(&text, &many).unwrap();
        assert_eq!(c.len(), MAX_SKILLS);
        assert_eq!(c, skill_hits_reference(&text, &many).unwrap());
    }

    #[test]
    fn text_past_the_cap_is_not_scanned() {
        let mut text = "x ".repeat(MAX_TEXT_LEN / 2);
        text.push_str(" rust");
        assert_eq!(both(&text, &["rust"]), vec![false]);
    }

    #[test]
    fn multibyte_text_is_safe() {
        assert_eq!(both("café rust ünï", &["rust"]), vec![true]);
        // Truncation may land mid-character; must not panic or misbehave.
        let text = "é".repeat(MAX_TEXT_LEN);
        assert_eq!(both(&text, &["rust"]), vec![false]);
    }

    /// Deterministic pseudo-random generator so failures are reproducible.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 33
        }
        fn pick(&mut self, items: &[u8]) -> u8 {
            items[(self.next() as usize) % items.len()]
        }
    }

    #[test]
    fn c_engine_agrees_with_reference_on_random_inputs() {
        // A small alphabet makes matches, near-misses and boundary cases common.
        let text_alphabet = b"abcABC+#_ .,/-\n\xc3\xa9";
        let skill_alphabet = b"abcABC+#.";
        let mut rng = Lcg(0x5eed);
        for iteration in 0..30_000u32 {
            let text_len = (rng.next() % 60) as usize;
            let text: Vec<u8> = (0..text_len).map(|_| rng.pick(text_alphabet)).collect();
            let n_skills = (rng.next() % 6) as usize;
            let skills: Vec<String> = (0..n_skills)
                .map(|_| {
                    let len = 1 + (rng.next() % 4) as usize;
                    (0..len).map(|_| rng.pick(skill_alphabet) as char).collect()
                })
                .collect();
            // Invalid UTF-8 can't be a &str; skip the rare cases it would be.
            let Ok(text) = String::from_utf8(text) else {
                continue;
            };
            let c = skill_hits(&text, &skills).unwrap();
            let r = skill_hits_reference(&text, &skills).unwrap();
            assert_eq!(
                c, r,
                "disagreement at iteration {iteration}: text={text:?} skills={skills:?}"
            );
        }
    }
}
