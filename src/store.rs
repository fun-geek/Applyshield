//! Private on-disk storage under one data directory.
//!
//! Layout:
//! ```text
//! <data dir>/
//!   .applyshield-data        marker: proves this directory is ours
//!   profile.txt              validated profile (personal data)
//!   jobs.txt                 validated job feed
//!   trusted_domains.txt      optional extra trusted domains, one per line
//!   audit.log                hash-chained audit log (no personal data)
//!   drafts/<job id>.txt      cover-letter drafts the user may edit
//!   state/<job id>.status    new | drafted | exported
//!   outbox/<job id>/         approved application packages
//! ```
//! Files are created readable by the current user only (0600/0700) on Unix.
//! Windows relies on the user's profile directory permissions.
//! Writes are atomic (write a temp file, then rename).
//!
//! No SQL database is used: the data is small, and a plain-text store keeps the
//! dependency tree empty. Job ids are validated before they are used in paths.

use crate::audit::AuditLog;
use crate::domain::models::JobId;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub const MARKER: &str = ".applyshield-data";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    New,
    Drafted,
    Exported,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Drafted => "drafted",
            Self::Exported => "exported",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "new" => Some(Self::New),
            "drafted" => Some(Self::Drafted),
            "exported" => Some(Self::Exported),
            _ => None,
        }
    }
}

pub struct Store {
    root: PathBuf,
}

fn private_dir(path: &Path) -> io::Result<()> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(path)
}

/// Creates a directory (and parents) readable only by the current user.
pub fn write_private_dir(path: &Path) -> io::Result<()> {
    private_dir(path)
}

/// Atomically writes `bytes` to `path`, readable only by the current user.
pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path)
}

/// Reads a text file, refusing anything longer than `limit` bytes.
pub fn read_limited(path: &Path, limit: usize) -> io::Result<String> {
    let f = File::open(path)?;
    let mut buf = Vec::new();
    f.take(limit as u64 + 1).read_to_end(&mut buf)?;
    if buf.len() > limit {
        return Err(io::Error::other("file is too large"));
    }
    String::from_utf8(buf).map_err(|_| io::Error::other("file is not valid UTF-8 text"))
}

impl Store {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn is_initialized(&self) -> bool {
        self.root.join(MARKER).is_file()
    }

    pub fn init(&self) -> io::Result<()> {
        private_dir(&self.root)?;
        for sub in ["drafts", "state", "outbox"] {
            private_dir(&self.root.join(sub))?;
        }
        if !self.is_initialized() {
            write_private(
                &self.root.join(MARKER),
                b"ApplyShield data directory. Created by `applyshield init`.\n",
            )?;
        }
        Ok(())
    }

    pub fn profile_path(&self) -> PathBuf {
        self.root.join("profile.txt")
    }

    pub fn jobs_path(&self) -> PathBuf {
        self.root.join("jobs.txt")
    }

    pub fn audit_log(&self) -> AuditLog {
        AuditLog::new(self.root.join("audit.log"))
    }

    pub fn trusted_domains(&self) -> Vec<String> {
        read_limited(&self.root.join("trusted_domains.txt"), 16 * 1024)
            .map(|t| {
                t.lines()
                    .map(|l| l.trim().to_ascii_lowercase())
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .filter(|l| {
                        l.contains('.')
                            && l.bytes().all(|b| {
                                b.is_ascii_lowercase()
                                    || b.is_ascii_digit()
                                    || b == b'.'
                                    || b == b'-'
                            })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// File-system name for a job. The `job-` prefix avoids Windows reserved
    /// device names (`con`, `nul`, `aux` ...) and lower-casing stops `Job1`
    /// and `job1` from sharing a file on case-insensitive file systems.
    fn stem(id: &JobId) -> String {
        format!("job-{}", id.as_str().to_ascii_lowercase())
    }

    pub fn draft_path(&self, id: &JobId) -> PathBuf {
        self.root
            .join("drafts")
            .join(format!("{}.txt", Self::stem(id)))
    }

    pub fn save_draft(&self, id: &JobId, text: &str) -> io::Result<()> {
        write_private(&self.draft_path(id), text.as_bytes())
    }

    pub fn load_draft(&self, id: &JobId) -> io::Result<Option<String>> {
        match read_limited(&self.draft_path(id), 16 * 1024) {
            Ok(t) => Ok(Some(t)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn status_path(&self, id: &JobId) -> PathBuf {
        self.root
            .join("state")
            .join(format!("{}.status", Self::stem(id)))
    }

    pub fn set_status(&self, id: &JobId, status: Status) -> io::Result<()> {
        write_private(&self.status_path(id), status.as_str().as_bytes())
    }

    /// Unknown or unreadable status is treated as `New`.
    pub fn status(&self, id: &JobId) -> Status {
        read_limited(&self.status_path(id), 32)
            .ok()
            .and_then(|s| Status::parse(&s))
            .unwrap_or(Status::New)
    }

    pub fn outbox_dir(&self, id: &JobId) -> PathBuf {
        self.root.join("outbox").join(Self::stem(id))
    }

    /// Deletes personal data: profile, jobs, drafts, state and outbox.
    /// Keeps the audit log (it holds no personal data) and the marker.
    /// Refuses to touch a directory that does not carry our marker.
    pub fn purge(&self) -> io::Result<()> {
        if !self.is_initialized() {
            return Err(io::Error::other(
                "not an ApplyShield data directory; refusing to delete anything",
            ));
        }
        for file in ["profile.txt", "jobs.txt", "trusted_domains.txt"] {
            match fs::remove_file(self.root.join(file)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        for dir in ["drafts", "state", "outbox"] {
            let p = self.root.join(dir);
            match fs::remove_dir_all(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            private_dir(&p)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store(name: &str) -> (PathBuf, Store) {
        let dir =
            std::env::temp_dir().join(format!("applyshield-store-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = Store::new(&dir);
        (dir, store)
    }

    fn id(s: &str) -> JobId {
        JobId::parse(s).unwrap()
    }

    #[test]
    fn init_creates_the_layout_and_marker() {
        let (dir, st) = temp_store("init");
        assert!(!st.is_initialized());
        st.init().unwrap();
        assert!(st.is_initialized());
        for sub in ["drafts", "state", "outbox"] {
            assert!(dir.join(sub).is_dir());
        }
        st.init().unwrap(); // idempotent
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn drafts_round_trip_and_missing_draft_is_none() {
        let (dir, st) = temp_store("draft");
        st.init().unwrap();
        assert_eq!(st.load_draft(&id("j1")).unwrap(), None);
        st.save_draft(&id("j1"), "hello").unwrap();
        assert_eq!(st.load_draft(&id("j1")).unwrap().as_deref(), Some("hello"));
        st.save_draft(&id("j1"), "second").unwrap();
        assert_eq!(st.load_draft(&id("j1")).unwrap().as_deref(), Some("second"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn status_defaults_to_new_and_round_trips() {
        let (dir, st) = temp_store("status");
        st.init().unwrap();
        assert_eq!(st.status(&id("j1")), Status::New);
        st.set_status(&id("j1"), Status::Drafted).unwrap();
        assert_eq!(st.status(&id("j1")), Status::Drafted);
        st.set_status(&id("j1"), Status::Exported).unwrap();
        assert_eq!(st.status(&id("j1")), Status::Exported);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_corrupted_status_file_reads_as_new() {
        let (dir, st) = temp_store("badstatus");
        st.init().unwrap();
        fs::write(dir.join("state").join("job-j1.status"), "approved!!").unwrap();
        assert_eq!(st.status(&id("j1")), Status::New);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn reserved_windows_names_and_case_variants_get_safe_file_names() {
        let (_dir, st) = temp_store("reserved");
        for reserved in ["con", "nul", "aux", "prn", "com1", "lpt1"] {
            let p = st.draft_path(&id(reserved));
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            assert!(name.starts_with("job-"), "{name}");
        }
        // Case variants share a file name; the jobs parser rejects such
        // duplicate ids so two jobs can never share one.
        assert_eq!(st.draft_path(&id("Job1")), st.draft_path(&id("job1")));
    }

    #[test]
    fn paths_stay_inside_the_data_directory() {
        let (dir, st) = temp_store("paths");
        for p in [st.draft_path(&id("a-b_1")), st.outbox_dir(&id("a-b_1"))] {
            assert!(p.starts_with(&dir));
            assert!(!p.to_string_lossy().contains(".."));
        }
    }

    #[test]
    fn read_limited_rejects_oversized_files() {
        let (dir, st) = temp_store("limit");
        st.init().unwrap();
        let p = dir.join("big.txt");
        fs::write(&p, "a".repeat(100)).unwrap();
        assert!(read_limited(&p, 99).is_err());
        assert!(read_limited(&p, 100).is_ok());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn read_limited_rejects_non_utf8() {
        let (dir, st) = temp_store("utf8");
        st.init().unwrap();
        let p = dir.join("bin.txt");
        fs::write(&p, [0xff, 0xfe, 0x00]).unwrap();
        assert!(read_limited(&p, 100).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn trusted_domains_file_is_parsed_and_filtered() {
        let (dir, st) = temp_store("trusted");
        st.init().unwrap();
        fs::write(
            dir.join("trusted_domains.txt"),
            "# comment\nCareers.Acme.com\nnot a domain\n\nevil/../x.com\nbeta.io\n",
        )
        .unwrap();
        assert_eq!(st.trusted_domains(), vec!["careers.acme.com", "beta.io"]);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn purge_removes_personal_data_but_keeps_audit_log_and_marker() {
        let (dir, st) = temp_store("purge");
        st.init().unwrap();
        fs::write(st.profile_path(), "x").unwrap();
        fs::write(st.jobs_path(), "x").unwrap();
        st.save_draft(&id("j1"), "d").unwrap();
        st.set_status(&id("j1"), Status::Drafted).unwrap();
        fs::create_dir_all(st.outbox_dir(&id("j1"))).unwrap();
        fs::write(st.outbox_dir(&id("j1")).join("application.txt"), "p").unwrap();
        fs::write(dir.join("audit.log"), "keep").unwrap();

        st.purge().unwrap();

        assert!(!st.profile_path().exists());
        assert!(!st.jobs_path().exists());
        assert_eq!(st.load_draft(&id("j1")).unwrap(), None);
        assert_eq!(st.status(&id("j1")), Status::New);
        assert!(!st.outbox_dir(&id("j1")).exists());
        assert!(dir.join("outbox").is_dir()); // recreated empty
        assert!(dir.join("audit.log").exists());
        assert!(st.is_initialized());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn purge_refuses_a_directory_without_the_marker() {
        let (dir, st) = temp_store("nomarker");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("precious.txt"), "do not delete").unwrap();
        fs::create_dir_all(dir.join("drafts")).unwrap();
        fs::write(dir.join("drafts").join("mine.txt"), "mine").unwrap();
        assert!(st.purge().is_err());
        assert!(dir.join("precious.txt").exists());
        assert!(dir.join("drafts").join("mine.txt").exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn files_and_directories_are_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, st) = temp_store("perm");
        st.init().unwrap();
        st.save_draft(&id("j1"), "x").unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join("drafts")), 0o700);
        assert_eq!(mode(&st.draft_path(&id("j1"))), 0o600);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn writes_leave_no_temp_files_behind() {
        let (dir, st) = temp_store("tmp");
        st.init().unwrap();
        st.save_draft(&id("j1"), "x").unwrap();
        let leftovers: Vec<_> = fs::read_dir(dir.join("drafts"))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "tmp"))
            .collect();
        assert!(leftovers.is_empty());
        let _ = fs::remove_dir_all(dir);
    }
}
