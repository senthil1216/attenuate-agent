use chrono::{DateTime, Utc};
use warden_capability::{ChildCapability, RequestBinding};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerificationError {
    #[error("capability is expired")]
    Expired,
    #[error("request-bound capability does not match the actual tool invocation")]
    RequestBindingMismatch,
    #[error("biscuit signature chain failed to verify: {0}")]
    SignatureChain(String),
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
    capability
        .verify_signature()
        .map_err(|e| VerificationError::SignatureChain(e.to_string()))?;

    if capability.expires_at() <= now {
        return Err(VerificationError::Expired);
    }

    if let Some(expected_binding) = capability.request_binding() {
        if actual_binding != Some(expected_binding) {
            return Err(VerificationError::RequestBindingMismatch);
        }
    }

    Ok(VerifiedCapability { capability })
}

#[cfg(test)]
mod tests {
    use super::*;
    use biscuit_auth::KeyPair;
    use chrono::{Duration, TimeZone};
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    use uuid::Uuid;
    use warden_capability::{AttenuationRequest, NetworkPolicy, RootCapability};
    use warden_manifest::{ExecPolicy, FilesystemPolicy, TaskManifest};

    fn manifest() -> TaskManifest {
        TaskManifest {
            task_id: Uuid::nil(),
            repo_root: PathBuf::from("/repo"),
            ttl_seconds: 60,
            filesystem: FilesystemPolicy {
                readable_roots: vec![PathBuf::from("/repo")],
                writable_roots: vec![PathBuf::from("/repo/src")],
            },
            exec: ExecPolicy {
                allowed_binaries: vec!["python".to_string()],
            },
            network: NetworkPolicy::DenyAll,
        }
    }

    fn attenuation_request() -> AttenuationRequest {
        AttenuationRequest {
            readable_roots: ["/repo/pkg".into()].into_iter().collect(),
            writable_roots: BTreeSet::new(),
            exec_binaries: BTreeSet::new(),
            network: NetworkPolicy::DenyAll,
            ttl_seconds: 30,
            request_binding: None,
        }
    }

    #[test]
    fn verify_accepts_valid_signature_chain() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let root = RootCapability::mint(&manifest(), now).unwrap();
        let child = root.attenuate(attenuation_request(), now).unwrap();

        let verified = verify(child, now, None).unwrap();
        assert_eq!(
            verified.capability().expires_at(),
            now + Duration::seconds(30)
        );
    }

    #[test]
    fn verify_rejects_token_signed_with_different_root_key() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let root = RootCapability::mint(&manifest(), now).unwrap();
        let child = root.attenuate(attenuation_request(), now).unwrap();

        let other_pubkey: [u8; 32] = KeyPair::new().public().to_bytes();
        let mut json = serde_json::to_value(&child).unwrap();
        json["root_public_key"] = serde_json::json!(other_pubkey.to_vec());
        let tampered: warden_capability::ChildCapability = serde_json::from_value(json).unwrap();

        let err = verify(tampered, now, None).unwrap_err();
        assert!(
            matches!(err, VerificationError::SignatureChain(_)),
            "expected SignatureChain error, got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_expired_capability() {
        let mint_time = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let root = RootCapability::mint(&manifest(), mint_time).unwrap();
        let child = root.attenuate(attenuation_request(), mint_time).unwrap();

        let later = mint_time + Duration::seconds(31);
        assert_eq!(
            verify(child, later, None).unwrap_err(),
            VerificationError::Expired
        );
    }
}
