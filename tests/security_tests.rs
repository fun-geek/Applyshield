//! Integration tests: the security gate exactly as an outside caller sees it.
//!
//! These guard invariants I1 to I3 from `docs/security-model.md`.
//! If one of these fails after a refactor, treat it as a security regression.

use applyshield::approval::{ApprovalToken, Denied, Gateway, UserConfirmation};
use applyshield::domain::models::JobId;
use applyshield::security::{Action, SecurityPolicy};

const DEST: &str = "https://jobs.example.com/1";

fn job() -> JobId {
    JobId::parse("job-1").unwrap()
}

fn token(content: &[u8], now: u64) -> ApprovalToken {
    let c = UserConfirmation::from_typed("job-1", &job()).expect("typed id");
    ApprovalToken::issue(c, content, DEST, now, 300)
}

#[test]
fn i2_default_policy_denies_external_submission() {
    let policy = SecurityPolicy::default();
    assert!(!policy.allows_external_submission());
    assert!(!policy.permits(Action::ExternalSubmit));
}

#[test]
fn i2_default_policy_requires_explicit_approval() {
    assert!(SecurityPolicy::default().requires_explicit_approval());
}

#[test]
fn i1_external_submit_is_denied_even_with_a_perfect_token() {
    let g = Gateway::new();
    let r = g.authorize(
        token(b"x", 10),
        Action::ExternalSubmit,
        &job(),
        b"x",
        DEST,
        11,
    );
    assert_eq!(r.unwrap_err(), Denied::PolicyDisabled);
}

#[test]
fn i1_no_confirmation_means_no_token() {
    // Without typing the job id there is no UserConfirmation, so no token.
    for typed in ["", "y", "yes", "approve", "job-2"] {
        assert!(UserConfirmation::from_typed(typed, &job()).is_none());
    }
}

#[test]
fn i1_approval_is_bound_to_content_and_destination() {
    let g = Gateway::new();
    let act = Action::ExportForManualSubmission;
    assert_eq!(
        g.authorize(token(b"a", 10), act, &job(), b"b", DEST, 11)
            .unwrap_err(),
        Denied::ContentChanged
    );
    assert_eq!(
        g.authorize(
            token(b"a", 10),
            act,
            &job(),
            b"a",
            "https://other.example/1",
            11
        )
        .unwrap_err(),
        Denied::DestinationChanged
    );
    assert!(
        g.authorize(token(b"a", 10), act, &job(), b"a", DEST, 11)
            .is_ok()
    );
}

#[test]
fn i1_approval_expires() {
    let g = Gateway::new();
    let r = g.authorize(
        token(b"a", 10),
        Action::ExportForManualSubmission,
        &job(),
        b"a",
        DEST,
        10 + 301,
    );
    assert_eq!(r.unwrap_err(), Denied::Expired);
}
