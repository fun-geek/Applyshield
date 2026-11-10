//! Integration tests: the security policy exactly as an outside caller sees it.
//!
//! These guard invariants I1 and I2 from `docs/security-model.md`.
//! If one of these fails after a refactor, treat it as a security regression.

use applyshield::security::SecurityPolicy;

#[test]
fn i2_default_policy_denies_external_submission() {
    let policy = SecurityPolicy::default();
    assert!(!policy.allows_external_submission());
}

#[test]
fn i2_default_policy_requires_explicit_approval() {
    let policy = SecurityPolicy::default();
    assert!(policy.requires_explicit_approval());
}

#[test]
fn i1_default_policy_blocks_submission_even_if_user_approved() {
    // Approval alone is never enough: submission must also be enabled.
    let policy = SecurityPolicy::default();
    assert!(!policy.can_submit(true));
}

#[test]
fn i1_default_policy_blocks_submission_without_approval() {
    let policy = SecurityPolicy::default();
    assert!(!policy.can_submit(false));
}

#[test]
fn default_policy_is_stable_across_clones_and_calls() {
    // The default must not depend on state, environment, or call order.
    let a = SecurityPolicy::default();
    let b = SecurityPolicy::default();
    assert_eq!(a, b);
    assert_eq!(a.clone(), b);
}
