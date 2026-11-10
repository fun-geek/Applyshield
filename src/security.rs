//! Security policy: the default-deny gate for external actions.
//!
//! Design rules (see `docs/security-model.md`):
//! * Fail closed: anything not explicitly allowed is denied.
//! * Fields are private, so code outside this module cannot build an "open"
//!   policy. There is intentionally no public way to enable submission yet;
//!   that arrives with the approval-token design (Step 2).
//! * `can_submit(bool)` is a Milestone 1 placeholder. A plain `bool` can be
//!   passed as `true` by any caller, so it will be replaced by an unforgeable
//!   approval token bound to the exact content and destination.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityPolicy {
    allow_external_submission: bool,
    require_explicit_approval: bool,
}

impl Default for SecurityPolicy {
    /// The only publicly constructible policy: everything denied,
    /// explicit approval required.
    fn default() -> Self {
        Self {
            allow_external_submission: false,
            require_explicit_approval: true,
        }
    }
}

impl SecurityPolicy {
    /// Whether external submission is enabled in this policy.
    pub fn allows_external_submission(&self) -> bool {
        self.allow_external_submission
    }

    /// Whether explicit per-application user approval is required.
    pub fn requires_explicit_approval(&self) -> bool {
        self.require_explicit_approval
    }

    /// Checks whether an external submission is permitted.
    ///
    /// Fail-closed: all three conditions must hold. Turning off the approval
    /// requirement never opens the gate.
    pub fn can_submit(&self, user_approved: bool) -> bool {
        self.allow_external_submission && self.require_explicit_approval && user_approved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test-only helper: build a policy with arbitrary flags. It lives inside
    // `cfg(test)` so it does not exist in the shipped library.
    fn policy(allow: bool, require_approval: bool) -> SecurityPolicy {
        SecurityPolicy {
            allow_external_submission: allow,
            require_explicit_approval: require_approval,
        }
    }

    #[test]
    fn submission_is_disabled_by_default() {
        assert!(!SecurityPolicy::default().allows_external_submission());
    }

    #[test]
    fn explicit_approval_is_required_by_default() {
        assert!(SecurityPolicy::default().requires_explicit_approval());
    }

    #[test]
    fn submission_is_blocked_without_approval() {
        assert!(!policy(true, true).can_submit(false));
    }

    #[test]
    fn submission_is_blocked_when_permission_is_disabled() {
        assert!(!SecurityPolicy::default().can_submit(true));
    }

    #[test]
    fn submission_is_allowed_when_both_conditions_are_met() {
        assert!(policy(true, true).can_submit(true));
    }

    #[test]
    fn submission_is_blocked_if_approval_requirement_is_disabled() {
        assert!(!policy(true, false).can_submit(true));
    }

    #[test]
    fn only_one_combination_of_flags_ever_allows_submission() {
        for allow in [false, true] {
            for require in [false, true] {
                for approved in [false, true] {
                    let expected = allow && require && approved;
                    assert_eq!(policy(allow, require).can_submit(approved), expected);
                }
            }
        }
    }
}
