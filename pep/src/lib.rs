use chrono::{DateTime, Utc};
use warden_capability::{ChildCapability, RequestBinding};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerificationError {
    #[error("capability is expired")]
    Expired,
    #[error("request-bound capability does not match the actual tool invocation")]
    RequestBindingMismatch,
}

#[derive(Debug, Clone)]
pub struct VerifiedCapability {
    capability: ChildCapability,
}

impl VerifiedCapability {
    pub fn capability(&self) -> &ChildCapability {
        &self.capability
    }
}

pub fn verify(
    capability: ChildCapability,
    now: DateTime<Utc>,
    actual_binding: Option<&RequestBinding>,
) -> Result<VerifiedCapability, VerificationError> {
    if capability.expires_at() <= now {
        return Err(VerificationError::Expired);
    }

    // Pre-biscuit scaffold: token integrity is type-system-only. The next milestone replaces this
    // value-level check with biscuit signature-chain verification while preserving this API shape.
    if let Some(expected_binding) = capability.request_binding() {
        if actual_binding != Some(expected_binding) {
            return Err(VerificationError::RequestBindingMismatch);
        }
    }

    Ok(VerifiedCapability { capability })
}
