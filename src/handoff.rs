//! Hand-off: turning an approved application into files the user submits
//! themselves.
//!
//! ApplyShield does **not** submit anything to an employer. [`export_package`]
//! writes the approved application to the local outbox and tells the user where
//! to apply. It requires an [`Authorization`] from the gateway, so it cannot be
//! called without a valid approval for exactly this content.

use crate::approval::Authorization;
use crate::hash::sha256;
use crate::security::Action;
use crate::store::{Store, write_private};
use std::io;
use std::path::PathBuf;

pub struct PackageParts<'a> {
    pub job_title: &'a str,
    pub company: &'a str,
    pub destination: &'a str,
    pub name: &'a str,
    pub email: &'a str,
    /// `None` unless the user chose to include a phone number.
    pub phone: Option<&'a str>,
    pub cover_letter: &'a str,
}

/// The exact text the user approves, and the exact text that is exported.
pub fn build_package(p: &PackageParts<'_>) -> String {
    let mut out = String::new();
    out.push_str("APPLICATION PACKAGE (prepared by ApplyShield, not yet submitted)\n");
    out.push_str(&format!("Role: {}\n", p.job_title));
    out.push_str(&format!("Company: {}\n", p.company));
    out.push_str(&format!("Apply at: {}\n\n", p.destination));
    out.push_str("--- Contact details ---\n");
    out.push_str(&format!("Name: {}\n", p.name));
    out.push_str(&format!("Email: {}\n", p.email));
    if let Some(phone) = p.phone {
        out.push_str(&format!("Phone: {phone}\n"));
    }
    out.push_str("\n--- Cover letter ---\n");
    out.push_str(p.cover_letter.trim_end());
    out.push('\n');
    out
}

/// Names of the personal fields a package contains, for the review screen.
pub fn shared_fields(include_phone: bool) -> Vec<&'static str> {
    let mut f = vec!["full name", "email address"];
    if include_phone {
        f.push("phone number");
    }
    f
}

/// Writes `application.txt` and `NEXT_STEPS.txt` into the job's outbox folder.
pub fn export_package(
    store: &Store,
    auth: &Authorization,
    package: &str,
    destination: &str,
) -> io::Result<PathBuf> {
    if auth.action() != Action::ExportForManualSubmission {
        return Err(io::Error::other("authorization is for a different action"));
    }
    if auth.content_hash() != &sha256(package.as_bytes()) {
        return Err(io::Error::other("package does not match the approval"));
    }
    let dir = store.outbox_dir(auth.job_id());
    crate::store::write_private_dir(&dir)?;
    write_private(&dir.join("application.txt"), package.as_bytes())?;
    let steps = format!(
        "NEXT STEPS (you submit this yourself)\n\n\
         1. Open the employer's apply page in your browser:\n   {destination}\n\
         2. Check the address bar matches the link above before typing anything.\n\
         3. Copy the cover letter and details from application.txt.\n\
         4. Review everything, then press Submit yourself.\n\n\
         ApplyShield never submits applications for you.\n"
    );
    write_private(&dir.join("NEXT_STEPS.txt"), steps.as_bytes())?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::{ApprovalToken, Gateway, UserConfirmation};
    use crate::domain::models::JobId;
    use std::fs;

    fn parts<'a>(phone: Option<&'a str>) -> PackageParts<'a> {
        PackageParts {
            job_title: "Dev Intern",
            company: "Acme",
            destination: "https://boards.greenhouse.io/acme/jobs/1",
            name: "Test Person",
            email: "t@example.org",
            phone,
            cover_letter: "Dear Team,\nHello.\n\n",
        }
    }

    #[test]
    fn package_contains_what_the_user_approves() {
        let p = build_package(&parts(None));
        assert!(p.contains("Role: Dev Intern"));
        assert!(p.contains("Apply at: https://boards.greenhouse.io/acme/jobs/1"));
        assert!(p.contains("Name: Test Person"));
        assert!(p.contains("Email: t@example.org"));
        assert!(p.contains("Dear Team,"));
        assert!(!p.contains("Phone:"));
        assert!(p.ends_with("Hello.\n"));
    }

    #[test]
    fn phone_is_included_only_when_given() {
        assert!(build_package(&parts(Some("+91 98765 43210"))).contains("Phone: +91 98765 43210"));
        assert_eq!(shared_fields(false), vec!["full name", "email address"]);
        assert_eq!(shared_fields(true).len(), 3);
    }

    fn authorized(package: &str, action: Action) -> Result<Authorization, crate::approval::Denied> {
        let id = JobId::parse("j1").unwrap();
        let conf = UserConfirmation::from_typed("j1", &id).unwrap();
        let dest = "https://boards.greenhouse.io/acme/jobs/1";
        let token = ApprovalToken::issue(conf, package.as_bytes(), dest, 100, 300);
        Gateway::new().authorize(token, action, &id, package.as_bytes(), dest, 101)
    }

    #[test]
    fn export_writes_files_for_a_valid_authorization() {
        let dir = std::env::temp_dir().join(format!("applyshield-handoff-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = Store::new(&dir);
        store.init().unwrap();
        let package = build_package(&parts(None));
        let auth = authorized(&package, Action::ExportForManualSubmission).unwrap();
        let out = export_package(
            &store,
            &auth,
            &package,
            "https://boards.greenhouse.io/acme/jobs/1",
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(out.join("application.txt")).unwrap(),
            package
        );
        let steps = fs::read_to_string(out.join("NEXT_STEPS.txt")).unwrap();
        assert!(steps.contains("never submits"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn export_refuses_a_package_that_differs_from_the_approved_one() {
        let dir = std::env::temp_dir().join(format!("applyshield-handoff2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = Store::new(&dir);
        store.init().unwrap();
        let package = build_package(&parts(None));
        let auth = authorized(&package, Action::ExportForManualSubmission).unwrap();
        let tampered = format!("{package}extra");
        assert!(export_package(&store, &auth, &tampered, "d").is_err());
        assert!(!store.outbox_dir(&JobId::parse("j1").unwrap()).exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn external_submit_cannot_be_authorized_so_nothing_can_be_exported_under_it() {
        let package = build_package(&parts(None));
        assert!(authorized(&package, Action::ExternalSubmit).is_err());
    }
}
