//! Tamper-evident audit log.
//!
//! Each line stores the SHA-256 of the previous line, so editing, deleting, or
//! reordering an earlier entry breaks every later hash and `verify` reports the
//! first broken line.
//!
//! Limits, stated plainly:
//! * Someone who can write the file can rewrite the *whole* chain. Detection
//!   works against accidental damage and partial edits. To catch a full rewrite
//!   or tail truncation, note the head hash printed by `applyshield audit`.
//! * Only fixed event names, job ids (validated), and a sanitised detail string
//!   are stored. No personal data goes in the log.

use crate::domain::models::JobId;
use crate::hash::sha256_hex;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_DETAIL_CHARS: usize = 200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditEvent {
    ProfileImported,
    JobsImported,
    Drafted,
    ApprovalDeclined,
    ApprovalDenied,
    Approved,
    Exported,
    Purged,
}

impl AuditEvent {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ProfileImported => "profile_imported",
            Self::JobsImported => "jobs_imported",
            Self::Drafted => "drafted",
            Self::ApprovalDeclined => "approval_declined",
            Self::ApprovalDenied => "approval_denied",
            Self::Approved => "approved",
            Self::Exported => "exported",
            Self::Purged => "purged",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEntry {
    pub seq: u64,
    pub timestamp: u64,
    pub event: String,
    pub job: String,
    pub detail: String,
    pub prev: String,
    pub hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditError {
    /// The file could not be read.
    Unreadable,
    /// A line is not in the expected format (1-based line number).
    Malformed(usize),
    /// The chain is broken at this line (1-based): content or order changed.
    Broken(usize),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyReport {
    pub entries: usize,
    /// Hash of the last entry (or the genesis value for an empty log).
    pub head: String,
}

pub struct AuditLog {
    path: PathBuf,
}

fn clean_detail(detail: &str) -> String {
    detail
        .chars()
        .map(|c| {
            if c == '|' {
                '/'
            } else if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '_'
            }
        })
        .take(MAX_DETAIL_CHARS)
        .collect()
}

fn entry_hash(seq: u64, ts: u64, event: &str, job: &str, detail: &str, prev: &str) -> String {
    sha256_hex(format!("{seq}|{ts}|{event}|{job}|{detail}|{prev}").as_bytes())
}

fn parse_line(line: &str) -> Option<AuditEntry> {
    let parts: Vec<&str> = line.split('|').collect();
    if parts.len() != 7 {
        return None;
    }
    let seq: u64 = parts[0].parse().ok()?;
    let timestamp: u64 = parts[1].parse().ok()?;
    // The numbers must be written exactly as `append` writes them. Otherwise
    // "+0001" and "1" would hash the same and an entry could be rewritten
    // without breaking the chain.
    if seq.to_string() != parts[0] || timestamp.to_string() != parts[1] {
        return None;
    }
    Some(AuditEntry {
        seq,
        timestamp,
        event: parts[2].to_string(),
        job: parts[3].to_string(),
        detail: parts[4].to_string(),
        prev: parts[5].to_string(),
        hash: parts[6].to_string(),
    })
}

impl AuditLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn read_entries(&self) -> Result<Vec<AuditEntry>, AuditError> {
        let text = match fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(AuditError::Unreadable),
        };
        let mut entries = Vec::new();
        for (i, line) in text.lines().enumerate() {
            if line.is_empty() {
                continue;
            }
            entries.push(parse_line(line).ok_or(AuditError::Malformed(i + 1))?);
        }
        Ok(entries)
    }

    pub fn append(
        &self,
        event: AuditEvent,
        job: Option<&JobId>,
        detail: &str,
        now: u64,
    ) -> io::Result<()> {
        let entries = self
            .read_entries()
            .map_err(|_| io::Error::other("audit log is damaged; refusing to append"))?;
        // Refuse to extend a chain that is already broken.
        if self.verify().is_err() {
            return Err(io::Error::other(
                "audit chain is broken; refusing to append",
            ));
        }
        let (seq, prev) = match entries.last() {
            Some(last) => (last.seq + 1, last.hash.clone()),
            None => (1, GENESIS.to_string()),
        };
        let job = job.map(|j| j.as_str()).unwrap_or("-");
        let detail = clean_detail(detail);
        let hash = entry_hash(seq, now, event.as_str(), job, &detail, &prev);
        let line = format!(
            "{seq}|{now}|{}|{job}|{detail}|{prev}|{hash}\n",
            event.as_str()
        );

        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&self.path)?;
        file.write_all(line.as_bytes())?;
        file.sync_all()
    }

    pub fn verify(&self) -> Result<VerifyReport, AuditError> {
        let entries = self.read_entries()?;
        let mut prev = GENESIS.to_string();
        for (i, e) in entries.iter().enumerate() {
            let line_no = i + 1;
            if e.seq != (i as u64) + 1 || e.prev != prev {
                return Err(AuditError::Broken(line_no));
            }
            let expect = entry_hash(e.seq, e.timestamp, &e.event, &e.job, &e.detail, &e.prev);
            if expect != e.hash {
                return Err(AuditError::Broken(line_no));
            }
            prev = e.hash.clone();
        }
        Ok(VerifyReport {
            entries: entries.len(),
            head: prev,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_log(name: &str) -> (PathBuf, AuditLog) {
        let dir =
            std::env::temp_dir().join(format!("applyshield-audit-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.log");
        (dir, AuditLog::new(path))
    }

    fn id(s: &str) -> JobId {
        JobId::parse(s).unwrap()
    }

    #[test]
    fn empty_log_verifies_with_genesis_head() {
        let (dir, log) = temp_log("empty");
        let r = log.verify().unwrap();
        assert_eq!(r.entries, 0);
        assert_eq!(r.head, GENESIS);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn appended_entries_form_a_valid_chain() {
        let (dir, log) = temp_log("chain");
        log.append(AuditEvent::JobsImported, None, "3 jobs", 100)
            .unwrap();
        log.append(AuditEvent::Drafted, Some(&id("j1")), "ok", 101)
            .unwrap();
        log.append(AuditEvent::Approved, Some(&id("j1")), "typed id", 102)
            .unwrap();
        let r = log.verify().unwrap();
        assert_eq!(r.entries, 3);
        assert_ne!(r.head, GENESIS);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn editing_an_entry_is_detected() {
        let (dir, log) = temp_log("edit");
        log.append(AuditEvent::Drafted, Some(&id("j1")), "ok", 100)
            .unwrap();
        log.append(AuditEvent::Approved, Some(&id("j1")), "typed id", 101)
            .unwrap();
        let text = fs::read_to_string(log.path()).unwrap();
        fs::write(log.path(), text.replace("drafted", "exported")).unwrap();
        assert_eq!(log.verify().unwrap_err(), AuditError::Broken(1));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn deleting_an_early_entry_is_detected() {
        let (dir, log) = temp_log("delete");
        for i in 0..3 {
            log.append(AuditEvent::Drafted, Some(&id("j1")), "x", 100 + i)
                .unwrap();
        }
        let text = fs::read_to_string(log.path()).unwrap();
        let without_first: String = text.lines().skip(1).map(|l| format!("{l}\n")).collect();
        fs::write(log.path(), without_first).unwrap();
        assert!(matches!(log.verify().unwrap_err(), AuditError::Broken(_)));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn reordering_entries_is_detected() {
        let (dir, log) = temp_log("reorder");
        for i in 0..3 {
            log.append(AuditEvent::Drafted, Some(&id("j1")), "x", 100 + i)
                .unwrap();
        }
        let text = fs::read_to_string(log.path()).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        lines.swap(0, 1);
        let swapped: String = lines.iter().map(|l| format!("{l}\n")).collect();
        fs::write(log.path(), swapped).unwrap();
        assert!(log.verify().is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn non_canonical_numbers_are_rejected() {
        let (dir, log) = temp_log("canon");
        log.append(AuditEvent::Drafted, None, "x", 100).unwrap();
        let text = fs::read_to_string(log.path()).unwrap();
        // "1|100|" rewritten as "+0001|0000100|" has the same numeric value.
        let forged = text.replacen("1|100|", "+0001|0000100|", 1);
        assert_ne!(text, forged);
        fs::write(log.path(), forged).unwrap();
        assert!(log.verify().is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn malformed_line_is_reported() {
        let (dir, log) = temp_log("malformed");
        fs::write(log.path(), "not a log line\n").unwrap();
        assert_eq!(log.verify().unwrap_err(), AuditError::Malformed(1));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn refuses_to_append_to_a_broken_chain() {
        let (dir, log) = temp_log("refuse");
        log.append(AuditEvent::Drafted, Some(&id("j1")), "ok", 100)
            .unwrap();
        let text = fs::read_to_string(log.path()).unwrap();
        fs::write(log.path(), text.replace("ok", "no")).unwrap();
        assert!(log.append(AuditEvent::Drafted, None, "more", 101).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn detail_cannot_break_the_line_format() {
        let (dir, log) = temp_log("detail");
        log.append(AuditEvent::Drafted, None, "a|b\nc\u{1b}[31m\r d é", 100)
            .unwrap();
        let text = fs::read_to_string(log.path()).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(!text.contains('\u{1b}'));
        assert!(log.verify().is_ok());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn detail_is_length_capped() {
        let (dir, log) = temp_log("cap");
        log.append(AuditEvent::Drafted, None, &"a".repeat(5000), 100)
            .unwrap();
        let e = &log.read_entries().unwrap()[0];
        assert_eq!(e.detail.len(), MAX_DETAIL_CHARS);
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn log_file_is_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, log) = temp_log("perm");
        log.append(AuditEvent::Drafted, None, "x", 100).unwrap();
        let mode = fs::metadata(log.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_dir_all(dir);
    }
}
