//! Run profile selection for the credential daemon.
//!
//! The `Legacy` profile is the historical credd/phylaxd behaviour. The
//! `Custody` profile is the hardened deployment: plaintext-returning routes are
//! not mounted at all, the vault key comes from YubiKey slot 1, startup refuses
//! unsafe hosts, and the master bearer is refused on the TCP listener.

use tracing::warn;

/// Environment variable that selects the custody profile (`"1"` exactly).
pub const CUSTODY_ENV: &str = "PHYLAX_CUSTODY";

/// Which behaviour set the daemon runs with. Chosen once at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RunProfile {
    /// Historical behaviour: every route mounted, master-only plaintext tiers.
    #[default]
    Legacy,
    /// Hardened custody behaviour: plaintext routes are not mounted.
    Custody,
}

/// Profile selection and queries.
impl RunProfile {
    /// Select a profile from the raw value of [`CUSTODY_ENV`].
    ///
    /// Exactly `"1"` selects [`RunProfile::Custody`]. An unset variable is
    /// `Legacy` silently; any other value is `Legacy` with a warning so a typo
    /// such as `"true"` cannot silently look like custody.
    pub fn from_env_value(raw: Option<&str>) -> Self {
        match raw {
            None => Self::Legacy,
            Some("1") => Self::Custody,
            Some(other) => {
                warn!(
                    env = CUSTODY_ENV,
                    value = other,
                    "unrecognised value (only \"1\" enables custody); running the legacy profile"
                );
                Self::Legacy
            }
        }
    }

    /// Select a profile from the process environment.
    pub fn from_env() -> Self {
        Self::from_env_value(std::env::var(CUSTODY_ENV).ok().as_deref())
    }

    /// True when this is the custody profile.
    pub fn is_custody(self) -> bool {
        self == Self::Custody
    }
}

/// Unit tests for profile selection.
#[cfg(test)]
mod tests {
    use super::*;

    /// Only the exact string "1" selects custody; everything else is legacy.
    #[test]
    fn only_exact_one_selects_custody() {
        assert_eq!(RunProfile::from_env_value(Some("1")), RunProfile::Custody);
        assert_eq!(RunProfile::from_env_value(None), RunProfile::Legacy);
        for other in ["", "0", "true", "yes", " 1", "1 ", "01", "custody"] {
            assert_eq!(
                RunProfile::from_env_value(Some(other)),
                RunProfile::Legacy,
                "{other:?} must not select custody"
            );
        }
    }

    /// The default profile is legacy so existing callers are unchanged.
    #[test]
    fn default_is_legacy() {
        assert_eq!(RunProfile::default(), RunProfile::Legacy);
        assert!(!RunProfile::Legacy.is_custody());
        assert!(RunProfile::Custody.is_custody());
    }
}
