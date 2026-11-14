//! Architecture guards: rules about the *code*, checked by reading the source.
//!
//! These are cheap tripwires for the structural promises in
//! `docs/security-model.md`. They are not a substitute for review, but they
//! make an accidental break fail CI loudly.

use std::fs;
use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn src_files() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    files
}

/// Source with comments removed, so prose about a word does not trip a check.
fn code_only(text: &str) -> String {
    text.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// True if `text` uses the `unsafe` keyword (not an identifier such as
/// `is_unsafe_char` or the lint name `unsafe_code`).
fn uses_unsafe_keyword(text: &str) -> bool {
    let bytes = text.as_bytes();
    let word = b"unsafe";
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut i = 0;
    while i + word.len() <= bytes.len() {
        if &bytes[i..i + word.len()] == word {
            let before_ok = i == 0 || !is_ident(bytes[i - 1]);
            let after = i + word.len();
            let after_ok = after >= bytes.len() || !is_ident(bytes[after]);
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

#[test]
fn unsafe_code_exists_only_in_the_ffi_module() {
    for path in src_files() {
        if path.ends_with("matching/ffi.rs") {
            continue;
        }
        let text = code_only(&fs::read_to_string(&path).unwrap());
        // Test modules may mention the word in strings; shipped code may not use it.
        let shipped = text.split("#[cfg(test)]").next().unwrap();
        assert!(
            !uses_unsafe_keyword(shipped),
            "`unsafe` keyword found outside matching/ffi.rs: {}",
            path.display()
        );
    }
}

#[test]
fn the_unsafe_detector_itself_works() {
    assert!(uses_unsafe_keyword("let x = unsafe { f() };"));
    assert!(uses_unsafe_keyword("unsafe extern \"C\" {}"));
    assert!(uses_unsafe_keyword("pub unsafe fn f() {}"));
    assert!(!uses_unsafe_keyword("fn is_unsafe_char(c: char) {}"));
    assert!(!uses_unsafe_keyword("#![deny(unsafe_code)]"));
    assert!(!uses_unsafe_keyword("let safe = 1;"));
}

#[test]
fn the_ffi_module_is_the_only_place_that_allows_unsafe() {
    for path in src_files() {
        let text = fs::read_to_string(&path).unwrap();
        let allows = text.contains("allow(unsafe_code)");
        let is_ffi = path.ends_with("matching/ffi.rs");
        assert_eq!(
            allows,
            is_ffi,
            "unexpected unsafe_code allowance in {}",
            path.display()
        );
    }
}

#[test]
fn every_unsafe_block_has_a_safety_comment() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/matching/ffi.rs");
    let text = fs::read_to_string(path).unwrap();
    assert!(
        text.contains("// SAFETY:"),
        "unsafe block without SAFETY comment"
    );
}

#[test]
fn crate_root_denies_unsafe_and_binary_forbids_it() {
    let lib = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs")).unwrap();
    assert!(lib.contains("#![deny(unsafe_code)]"));
    let main =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs")).unwrap();
    assert!(main.contains("#![forbid(unsafe_code)]"));
}

/// The AI/drafting side must not be able to approve or export anything.
/// Invariant I3: the AI layer cannot disable, bypass or reconfigure the gateway.
#[test]
fn drafting_code_cannot_reach_approval_or_export() {
    let forbidden = [
        "approval",
        "ApprovalToken",
        "UserConfirmation",
        "Gateway",
        "Authorization",
        "handoff",
        "export_package",
        "store",
        "Store",
        "audit",
        "std::fs",
        "std::net",
        "std::process",
    ];
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/drafting.rs");
    let text = code_only(&fs::read_to_string(path).unwrap());
    // Ignore the test module at the bottom of the file.
    let body = text.split("#[cfg(test)]").next().unwrap();
    for word in forbidden {
        assert!(
            !body.contains(word),
            "src/drafting.rs must not reference `{word}`"
        );
    }
}

#[test]
fn drafting_input_has_no_field_for_personal_data_or_listing_text() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/drafting.rs");
    let text = fs::read_to_string(path).unwrap();
    let start = text
        .find("pub struct DraftInput")
        .expect("DraftInput exists");
    let block = &text[start..start + text[start..].find('}').unwrap()];
    for word in [
        "email",
        "phone",
        "name",
        "description",
        "url",
        "Redacted",
        "Untrusted",
    ] {
        assert!(
            !block.to_lowercase().contains(&word.to_lowercase()),
            "DraftInput must not contain a `{word}` field"
        );
    }
}

/// Checks and the C wrapper are pure: no files, network, or processes.
#[test]
fn pure_modules_do_no_io() {
    let forbidden = [
        "std::fs",
        "std::net",
        "std::process",
        "std::env",
        "File::open",
    ];
    let mut files: Vec<PathBuf> = Vec::new();
    rust_files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src/checks"),
        &mut files,
    );
    rust_files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src/matching"),
        &mut files,
    );
    for extra in [
        "src/pipeline.rs",
        "src/hash.rs",
        "src/approval.rs",
        "src/security.rs",
    ] {
        files.push(Path::new(env!("CARGO_MANIFEST_DIR")).join(extra));
    }
    for path in files {
        let text = code_only(&fs::read_to_string(&path).unwrap());
        let body = text.split("#[cfg(test)]").next().unwrap();
        for word in forbidden {
            assert!(
                !body.contains(word),
                "{} must stay free of I/O but references `{word}`",
                path.display()
            );
        }
    }
}

/// No code path may call a network API: ApplyShield never contacts an employer.
#[test]
fn no_network_code_anywhere() {
    for path in src_files() {
        let text = code_only(&fs::read_to_string(&path).unwrap());
        for word in [
            "std::net",
            "TcpStream",
            "UdpSocket",
            "reqwest",
            "hyper",
            "ureq",
        ] {
            assert!(
                !text.contains(word),
                "{} references `{word}`",
                path.display()
            );
        }
    }
}

/// `Command` (spawning programs) is not used anywhere in the shipped code.
#[test]
fn no_process_spawning_in_shipped_code() {
    for path in src_files() {
        let text = code_only(&fs::read_to_string(&path).unwrap());
        let body = text.split("#[cfg(test)]").next().unwrap();
        for word in ["std::process::Command", "Command::new"] {
            assert!(
                !body.contains(word),
                "{} references `{word}`",
                path.display()
            );
        }
    }
}

#[test]
fn the_only_runtime_dependency_set_is_empty() {
    let toml =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    let deps = toml
        .split("[dependencies]")
        .nth(1)
        .unwrap()
        .split("[build-dependencies]")
        .next()
        .unwrap();
    let entries: Vec<&str> = deps
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    assert!(
        entries.is_empty(),
        "runtime dependencies were added: {entries:?}"
    );
}
