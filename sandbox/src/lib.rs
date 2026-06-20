#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SandboxError {
    #[error("linux containment is not enabled in this build")]
    Disabled,
    #[error("linux containment is enabled at build time but not yet implemented (stub)")]
    NotImplemented,
}

/// Install OS-level containment (Landlock + seccomp) for the current process.
///
/// This is **not yet implemented**. It is intended as defense-in-depth on top
/// of the capability layer, not the primary control. Until real Landlock/seccomp
/// landing, every build fails loud rather than silently reporting success:
///
/// - Without the `linux-containment` feature, the call is [`SandboxError::Disabled`].
/// - With the feature enabled, the call is [`SandboxError::NotImplemented`] — so
///   enabling the flag can never be mistaken for "containment is active". A no-op
///   that returned `Ok(())` would be a false sense of security: callers would
///   believe the executed binary is OS-confined when nothing is enforced.
#[cfg(feature = "linux-containment")]
pub fn install_linux_containment() -> Result<(), SandboxError> {
    Err(SandboxError::NotImplemented)
}

/// See the feature-enabled variant above. Without `linux-containment`, the
/// containment code is not compiled in at all.
#[cfg(not(feature = "linux-containment"))]
pub fn install_linux_containment() -> Result<(), SandboxError> {
    Err(SandboxError::Disabled)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Either way the stub must fail loud — it must never return Ok(()) and let a
    // caller believe OS containment is active when none is enforced.
    #[test]
    fn install_linux_containment_never_silently_succeeds() {
        assert!(install_linux_containment().is_err());
    }

    #[cfg(feature = "linux-containment")]
    #[test]
    fn enabled_build_reports_not_implemented() {
        assert_eq!(
            install_linux_containment(),
            Err(SandboxError::NotImplemented)
        );
    }

    #[cfg(not(feature = "linux-containment"))]
    #[test]
    fn disabled_build_reports_disabled() {
        assert_eq!(install_linux_containment(), Err(SandboxError::Disabled));
    }
}
