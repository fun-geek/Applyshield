<<<<<<< HEAD
#[derive(Debug)]
pub struct SecurityPolicy {
    pub allow_external_submission: bool,
    pub require_explicit_approval: bool,
}

impl Default for SecurityPolicy {
=======
//! Security policy: the default-deny gate for external actions.
//!
//! Design rules (see `docs/security-model.md`):
//! * Fail closed: anything not explicitly allowed is denied.
//! * Fields are private, so code outside this module cannot build an "open"
//!   policy. There is intentionally no public way to enable external
//!   submission: ApplyShield prepares applications and hands them to the user.
//! * The policy only says what is *ever* permitted. Whether a specific action
//!   may happen now is decided by [`crate::approval::Gateway`], which also needs
//!   a valid, unexpired, single-use approval token.

/// Things the program might be asked to do that leave the machine or commit
/// the user to something.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Write a complete application package to the local outbox so the user
    /// can submit it themselves. Nothing is sent anywhere.
    ExportForManualSubmission,
    /// Send an application to an employer's system on the user's behalf.
    /// Disabled by policy; no code path in this program performs it.
    ExternalSubmit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityPolicy {
    allow_external_submission: bool,
    require_explicit_approval: bool,
}

impl Default for SecurityPolicy {
    /// The only publicly constructible policy: external submission denied,
    /// explicit approval required.
>>>>>>> c31ce4e (Update in Applysheild)
    fn default() -> Self {
        Self {
            allow_external_submission: false,
            require_explicit_approval: true,
        }
    }
}

impl SecurityPolicy {
<<<<<<< HEAD
    // Checks whether an external submission is permitted.
    pub fn can_submit(&self, user_approved: bool) -> bool {
        self.allow_external_submission && self.require_explicit_approval && user_approved
=======
    pub fn allows_external_submission(&self) -> bool {
        self.allow_external_submission
    }

    pub fn requires_explicit_approval(&self) -> bool {
        self.require_explicit_approval
    }

    /// Whether the policy permits this kind of action at all. A `true` here is
    /// necessary but never sufficient: an approval token is still required.
    pub fn permits(&self, action: Action) -> bool {
        match action {
            Action::ExportForManualSubmission => true,
            Action::ExternalSubmit => self.allow_external_submission,
        }
>>>>>>> c31ce4e (Update in Applysheild)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
<<<<<<< HEAD
    fn submission_is_disabled_by_default() {
        let policy = SecurityPolicy::default();

        assert!(!policy.allow_external_submission);
=======
    fn external_submission_is_disabled_by_default() {
        let p = SecurityPolicy::default();
        assert!(!p.allows_external_submission());
        assert!(!p.permits(Action::ExternalSubmit));
>>>>>>> c31ce4e (Update in Applysheild)
    }

    #[test]
    fn explicit_approval_is_required_by_default() {
<<<<<<< HEAD
        let policy = SecurityPolicy::default();

        assert!(policy.require_explicit_approval);
    }

    #[test]
    fn submission_is_blocked_without_approval() {
        let policy = SecurityPolicy {
            allow_external_submission: true,
            require_explicit_approval: true,
        };

        assert!(!policy.can_submit(false));
    }

    #[test]
    fn submission_is_blocked_when_permission_is_disabled() {
        let policy = SecurityPolicy::default();

        assert!(!policy.can_submit(true));
    }

    #[test]
    fn submission_is_allowed_when_both_conditions_are_met() {
        let policy = SecurityPolicy {
            allow_external_submission: true,
            require_explicit_approval: true,
        };

        assert!(policy.can_submit(true));
    }

    #[test]
    fn submission_is_blocked_if_approval_requirement_is_disabled() {
        let policy = SecurityPolicy {
            allow_external_submission: true,
            require_explicit_approval: false,
        };

        assert!(!policy.can_submit(true));
    }
}

//{Submission Allowed}=permission enable && user approved}
=======
        assert!(SecurityPolicy::default().requires_explicit_approval());
    }

    #[test]
    fn manual_export_is_permitted_by_policy() {
        assert!(SecurityPolicy::default().permits(Action::ExportForManualSubmission));
    }

    #[test]
    fn an_open_policy_would_permit_external_submit() {
        // Test-only construction; the field is private outside this module.
        let open = SecurityPolicy {
            allow_external_submission: true,
            require_explicit_approval: true,
        };
        assert!(open.permits(Action::ExternalSubmit));
    }
}
>>>>>>> c31ce4e (Update in Applysheild)
