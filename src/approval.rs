//! Approval tokens and the gateway that checks them.
//!
//! The rule this module exists to enforce: **nothing leaves the program unless
//! a human typed the job id for that exact content, recently, for that exact
//! destination.**
//!
//! * [`UserConfirmation`] can only be built from text the user typed that
//!   equals the job id. Its field is private.
//! * [`ApprovalToken`] can only be issued from a `UserConfirmation`. It is
//!   bound to the SHA-256 of the exact content and to the destination, and it
//!   expires. It is not `Clone` or `Copy`, and [`Gateway::authorize`] takes it
//!   *by value*, so it can be used once.
//! * [`Authorization`] is the proof handed to code that performs an action.
//!   It can only be produced by the gateway.
//!
//! Limitation: this is module-level privacy inside one crate, not a process
//! boundary. A test (`tests/architecture_tests.rs`) checks that the AI/drafting
//! code never references these types.

use crate::domain::models::JobId;
use crate::hash::{Digest, sha256};
use crate::security::{Action, SecurityPolicy};

/// Longest a token may live, whatever the caller asks for.
pub const MAX_TOKEN_TTL_SECS: u64 = 600;

/// Proof that a human typed the job id.
#[derive(Debug)]
pub struct UserConfirmation {
    job_id: JobId,
}

impl UserConfirmation {
    /// `typed` must equal the job id exactly (case-sensitive) after trimming
    /// surrounding whitespace such as the newline from Enter. Anything else
    /// returns `None`: a bare "y" or an empty line is not an approval.
    pub fn from_typed(typed: &str, expected: &JobId) -> Option<Self> {
        if typed.trim() == expected.as_str() {
            Some(Self {
                job_id: expected.clone(),
            })
        } else {
            None
        }
    }
}

/// Permission to act on exactly one piece of content, once, until it expires.
#[derive(Debug)]
pub struct ApprovalToken {
    job_id: JobId,
    content_hash: Digest,
    destination: String,
    expires_at: u64,
}

impl ApprovalToken {
    pub fn issue(
        confirmation: UserConfirmation,
        content: &[u8],
        destination: &str,
        now: u64,
        ttl_secs: u64,
    ) -> Self {
        let ttl = ttl_secs.min(MAX_TOKEN_TTL_SECS);
        Self {
            job_id: confirmation.job_id,
            content_hash: sha256(content),
            destination: destination.to_string(),
            expires_at: now.saturating_add(ttl),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denied {
    /// The policy never permits this action.
    PolicyDisabled,
    /// The token was approved for a different job.
    JobMismatch,
    /// The token has expired.
    Expired,
    /// The content differs from what the user approved.
    ContentChanged,
    /// The destination differs from what the user approved.
    DestinationChanged,
}

impl Denied {
    pub fn explanation(&self) -> &'static str {
        match self {
            Self::PolicyDisabled => "the security policy does not permit this action",
            Self::JobMismatch => "the approval was for a different job",
            Self::Expired => "the approval expired; approve again",
            Self::ContentChanged => "the content changed after you approved it",
            Self::DestinationChanged => "the destination changed after you approved it",
        }
    }
}

/// Proof that the gateway allowed an action. Cannot be built outside this
/// module; functions that perform an action take `&Authorization`.
#[derive(Debug)]
pub struct Authorization {
    job_id: JobId,
    action: Action,
    content_hash: Digest,
}

impl Authorization {
    pub fn job_id(&self) -> &JobId {
        &self.job_id
    }

    pub fn action(&self) -> Action {
        self.action
    }

    pub fn content_hash(&self) -> &Digest {
        &self.content_hash
    }
}

#[derive(Debug, Default)]
pub struct Gateway {
    policy: SecurityPolicy,
}

impl Gateway {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn policy(&self) -> &SecurityPolicy {
        &self.policy
    }

    /// Fail closed. The token is consumed whether or not it is accepted.
    pub fn authorize(
        &self,
        token: ApprovalToken,
        action: Action,
        job_id: &JobId,
        content: &[u8],
        destination: &str,
        now: u64,
    ) -> Result<Authorization, Denied> {
        if !self.policy.permits(action) {
            return Err(Denied::PolicyDisabled);
        }
        if &token.job_id != job_id {
            return Err(Denied::JobMismatch);
        }
        if now >= token.expires_at {
            return Err(Denied::Expired);
        }
        let hash = sha256(content);
        if hash != token.content_hash {
            return Err(Denied::ContentChanged);
        }
        if token.destination != destination {
            return Err(Denied::DestinationChanged);
        }
        Ok(Authorization {
            job_id: token.job_id,
            action,
            content_hash: hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000_000;
    const DEST: &str = "https://boards.greenhouse.io/acme/jobs/1";

    fn id(s: &str) -> JobId {
        JobId::parse(s).unwrap()
    }

    fn token(job: &str, content: &[u8], dest: &str, ttl: u64) -> ApprovalToken {
        let conf = UserConfirmation::from_typed(job, &id(job)).unwrap();
        ApprovalToken::issue(conf, content, dest, NOW, ttl)
    }

    #[test]
    fn typing_the_exact_job_id_confirms() {
        assert!(UserConfirmation::from_typed("job-1\n", &id("job-1")).is_some());
        assert!(UserConfirmation::from_typed("  job-1  ", &id("job-1")).is_some());
    }

    #[test]
    fn anything_other_than_the_job_id_does_not_confirm() {
        for typed in [
            "",
            "y",
            "yes",
            "Y",
            "JOB-1",
            "job-2",
            "job-1 job-1",
            "job-1x",
        ] {
            assert!(
                UserConfirmation::from_typed(typed, &id("job-1")).is_none(),
                "accepted {typed:?}"
            );
        }
    }

    #[test]
    fn valid_token_authorizes_manual_export() {
        let g = Gateway::new();
        let t = token("job-1", b"content", DEST, 300);
        let auth = g
            .authorize(
                t,
                Action::ExportForManualSubmission,
                &id("job-1"),
                b"content",
                DEST,
                NOW + 10,
            )
            .unwrap();
        assert_eq!(auth.job_id(), &id("job-1"));
        assert_eq!(auth.action(), Action::ExportForManualSubmission);
    }

    #[test]
    fn external_submit_is_always_denied_even_with_a_valid_token() {
        let g = Gateway::new();
        let t = token("job-1", b"content", DEST, 300);
        let r = g.authorize(
            t,
            Action::ExternalSubmit,
            &id("job-1"),
            b"content",
            DEST,
            NOW + 1,
        );
        assert_eq!(r.unwrap_err(), Denied::PolicyDisabled);
    }

    #[test]
    fn changed_content_is_denied() {
        let g = Gateway::new();
        let t = token("job-1", b"content", DEST, 300);
        let r = g.authorize(
            t,
            Action::ExportForManualSubmission,
            &id("job-1"),
            b"content!",
            DEST,
            NOW + 1,
        );
        assert_eq!(r.unwrap_err(), Denied::ContentChanged);
    }

    #[test]
    fn changed_destination_is_denied() {
        let g = Gateway::new();
        let t = token("job-1", b"content", DEST, 300);
        let r = g.authorize(
            t,
            Action::ExportForManualSubmission,
            &id("job-1"),
            b"content",
            "https://evil.example/jobs/1",
            NOW + 1,
        );
        assert_eq!(r.unwrap_err(), Denied::DestinationChanged);
    }

    #[test]
    fn token_for_another_job_is_denied() {
        let g = Gateway::new();
        let t = token("job-1", b"content", DEST, 300);
        let r = g.authorize(
            t,
            Action::ExportForManualSubmission,
            &id("job-2"),
            b"content",
            DEST,
            NOW + 1,
        );
        assert_eq!(r.unwrap_err(), Denied::JobMismatch);
    }

    #[test]
    fn expired_token_is_denied_at_the_boundary() {
        let g = Gateway::new();
        // ttl 300 => expires_at = NOW + 300; at exactly that instant it is expired.
        let t = token("job-1", b"c", DEST, 300);
        let r = g.authorize(
            t,
            Action::ExportForManualSubmission,
            &id("job-1"),
            b"c",
            DEST,
            NOW + 300,
        );
        assert_eq!(r.unwrap_err(), Denied::Expired);
        let t = token("job-1", b"c", DEST, 300);
        assert!(
            g.authorize(
                t,
                Action::ExportForManualSubmission,
                &id("job-1"),
                b"c",
                DEST,
                NOW + 299
            )
            .is_ok()
        );
    }

    #[test]
    fn ttl_is_capped() {
        let g = Gateway::new();
        let t = token("job-1", b"c", DEST, u64::MAX);
        let r = g.authorize(
            t,
            Action::ExportForManualSubmission,
            &id("job-1"),
            b"c",
            DEST,
            NOW + MAX_TOKEN_TTL_SECS,
        );
        assert_eq!(r.unwrap_err(), Denied::Expired);
    }

    #[test]
    fn zero_ttl_token_is_immediately_expired() {
        let g = Gateway::new();
        let t = token("job-1", b"c", DEST, 0);
        let r = g.authorize(
            t,
            Action::ExportForManualSubmission,
            &id("job-1"),
            b"c",
            DEST,
            NOW,
        );
        assert_eq!(r.unwrap_err(), Denied::Expired);
    }

    #[test]
    fn huge_clock_values_do_not_overflow() {
        let conf = UserConfirmation::from_typed("job-1", &id("job-1")).unwrap();
        let t = ApprovalToken::issue(conf, b"c", DEST, u64::MAX, 300);
        let g = Gateway::new();
        let r = g.authorize(
            t,
            Action::ExportForManualSubmission,
            &id("job-1"),
            b"c",
            DEST,
            u64::MAX,
        );
        assert_eq!(r.unwrap_err(), Denied::Expired);
    }
}
