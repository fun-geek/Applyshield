#[derive(Debug)]
pub struct SecurityPolicy {
    pub allow_external_submission: bool,
    pub require_explicit_approval: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            allow_external_submission: false,
            require_explicit_approval: true,
        }
    }
}

impl SecurityPolicy {
    // Checks whether an external submission is permitted.
    pub fn can_submit(&self, user_approved: bool) -> bool {
        self.allow_external_submission && self.require_explicit_approval && user_approved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submission_is_disabled_by_default() {
        let policy = SecurityPolicy::default();

        assert!(!policy.allow_external_submission);
    }

    #[test]
    fn explicit_approval_is_required_by_default() {
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
