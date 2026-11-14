//! The only place in the crate that uses `unsafe`.
//!
//! `tests/architecture_tests.rs` fails if `unsafe` appears in any other file.
#![allow(unsafe_code)]

unsafe extern "C" {
    /// See `c/matcher.h`. Returns the number of skills processed, or a
    /// negative error code.
    fn as_skill_hits(
        text: *const u8,
        text_len: usize,
        skills: *const u8,
        skills_len: usize,
        hit_mask: *mut u8,
        mask_cap: usize,
    ) -> i32;
}

/// Calls the C engine. `expected` is the number of skills in `skills`; the
/// result is rejected if the engine reports anything else.
pub(super) fn call(text: &[u8], skills: &[u8], expected: usize) -> Result<Vec<bool>, i32> {
    // Caller-allocated output. At least one byte so the pointer is never null.
    let mut mask = vec![0u8; expected.max(1)];

    // SAFETY:
    // * `text`, `skills` and `mask` are live slices/Vecs; each pointer is
    //   non-null (even for empty slices) and valid for exactly the length
    //   passed alongside it.
    // * `mask` is writable for `mask.len()` bytes and the engine is told that
    //   length as `mask_cap`; it never writes past it.
    // * The engine does not retain any pointer after returning, performs no
    //   allocation and has no global state, so there is no aliasing or
    //   lifetime concern.
    let rc = unsafe {
        as_skill_hits(
            text.as_ptr(),
            text.len(),
            skills.as_ptr(),
            skills.len(),
            mask.as_mut_ptr(),
            mask.len(),
        )
    };

    if rc < 0 {
        return Err(rc);
    }
    if rc as usize != expected {
        // Inconsistent with what we sent: treat as an engine failure.
        return Err(-100);
    }
    mask.truncate(expected);
    let mut out = Vec::with_capacity(expected);
    for b in mask {
        match b {
            0 => out.push(false),
            1 => out.push(true),
            _ => return Err(-101),
        }
    }
    Ok(out)
}
