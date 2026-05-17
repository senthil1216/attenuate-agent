#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("linux containment is not enabled in this build")]
    Disabled,
}

#[cfg(feature = "linux-containment")]
pub fn install_linux_containment() -> Result<(), SandboxError> {
    Ok(())
}

#[cfg(not(feature = "linux-containment"))]
pub fn install_linux_containment() -> Result<(), SandboxError> {
    Err(SandboxError::Disabled)
}
