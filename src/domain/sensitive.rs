//! Sensitive personal data handling (see `docs/security-model.md`, T5).
//!
//! `Redacted<T>` makes leaking a value by accident hard: printing, `{:?}`
//! formatting, and logging all show `[REDACTED]`. Getting at the real value
//! requires a deliberate, greppable call to [`Redacted::expose_secret`].

use std::fmt;

/// How sensitive a piece of data is. Ordered from least to most sensitive.
///
/// Later steps use this for data minimisation: an application or an LLM
/// prompt is only given fields up to the class it actually needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DataClass {
    /// Safe to share broadly (for example a target role).
    Public,
    /// Identifies the person (name, email, phone). Share only when needed.
    Personal,
    /// Credentials, government IDs, and similar. Never sent to a model.
    Sensitive,
}

/// A value that must never appear in logs, debug output, or terminal output.
///
/// There is deliberately no `Serialize`, `PartialEq`, or `Deref`.
#[derive(Clone)]
pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Returns the real value. Call this only at the exact point it is needed
    /// (for example filling a form after approval), never for logging.
    pub fn expose_secret(&self) -> &T {
        &self.0
    }
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_display_hide_the_value() {
        let r = Redacted::new("secret@example.com".to_string());
        assert_eq!(format!("{r:?}"), "[REDACTED]");
        assert_eq!(format!("{r}"), "[REDACTED]");
    }

    #[test]
    fn pretty_debug_also_hides_the_value() {
        let r = Redacted::new("secret".to_string());
        assert!(!format!("{r:#?}").contains("secret"));
    }

    #[test]
    fn expose_secret_returns_the_real_value() {
        let r = Redacted::new("value".to_string());
        assert_eq!(r.expose_secret(), "value");
    }

    #[test]
    fn data_classes_are_ordered_by_sensitivity() {
        assert!(DataClass::Public < DataClass::Personal);
        assert!(DataClass::Personal < DataClass::Sensitive);
    }
}
