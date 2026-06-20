use chrono::{DateTime, Utc};
use warden_capability::{
    CapabilityError, ChildCapability, PermissionSet, RequestBinding, VerifiedState,
};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerificationError {
    #[error("capability is expired")]
    Expired,
    #[error("request-bound capability does not match the actual tool invocation")]
    RequestBindingMismatch,
    #[error("biscuit signature chain failed to verify: {0}")]
    SignatureChain(String),
    #[error("capability struct state disagrees with its signed token")]
    StateTampered,
}

/// A capability that has passed verification. Its accessors expose the
/// authoritative state recovered from the signed token — never the plaintext
/// struct fields of the submitted `ChildCapability`.
#[derive(Debug, Clone)]
pub struct VerifiedCapability {
    state: VerifiedState,
}

impl VerifiedCapability {
    /// The token-derived permissions the PDP must decide over.
    pub fn permissions(&self) -> &PermissionSet {
        self.state.permissions()
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.state.expires_at()
    }

    pub fn request_binding(&self) -> Option<&RequestBinding> {
        self.state.request_binding()
    }

    pub fn state(&self) -> &VerifiedState {
        &self.state
    }
}

pub fn verify(
    capability: ChildCapability,
    now: DateTime<Utc>,
    actual_binding: Option<&RequestBinding>,
) -> Result<VerifiedCapability, VerificationError> {
    // Recover the authoritative state FROM the signed token. This both verifies
    // the signature chain and rejects a struct whose plaintext fields were
    // tampered after signing — the bug that previously let a valid signature
    // launder a widened `permissions` struct past the PDP.
    let state = capability.verify_and_decode().map_err(|e| match e {
        CapabilityError::TokenStateMismatch => VerificationError::StateTampered,
        other => VerificationError::SignatureChain(other.to_string()),
    })?;

    if state.expires_at() <= now {
        return Err(VerificationError::Expired);
    }

    if let Some(expected_binding) = state.request_binding() {
        if actual_binding != Some(expected_binding) {
            return Err(VerificationError::RequestBindingMismatch);
        }
    }

    Ok(VerifiedCapability { state })
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
        assert_eq!(verified.expires_at(), now + Duration::seconds(30));
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

    // Regression for the P0 enforcement gap: a validly-signed token whose
    // plaintext `permissions` struct is widened after signing must be rejected.
    // Previously `verify` only checked the signature chain and a downstream PDP
    // read the (lying) struct field, silently widening authority across the
    // serde boundary the design advertises as "offline-attenuable".
    #[test]
    fn verify_rejects_struct_permissions_widened_after_signing() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let root = RootCapability::mint(&manifest(), now).unwrap();
        // Legitimately attenuated to read ONLY /repo/pkg, no write, no exec.
        let child = root.attenuate(attenuation_request(), now).unwrap();

        // Attacker keeps the untouched, validly-signed token + root key, but
        // widens the plaintext struct back toward the root's authority.
        let mut json = serde_json::to_value(&child).unwrap();
        json["permissions"]["readable_roots"] = serde_json::json!(["/repo"]);
        json["permissions"]["writable_roots"] = serde_json::json!(["/repo/src"]);
        json["permissions"]["exec_binaries"] = serde_json::json!(["python"]);
        let tampered: ChildCapability = serde_json::from_value(json).unwrap();

        // The OLD, vulnerable check — signature chain only — still passes on the
        // tampered capability, which is exactly how the widened struct used to
        // reach the PDP.
        assert!(tampered.verify_signature().is_ok());

        // The fixed path decodes the latest token block (which authorizes only
        // /repo/pkg), sees the divergence, and rejects the capability.
        let err = verify(tampered.clone(), now, None).unwrap_err();
        assert_eq!(err, VerificationError::StateTampered);

        // And the authoritative permissions the PDP would see come from the
        // token, never the tampered struct.
        let honest = root.attenuate(attenuation_request(), now).unwrap();
        let verified = verify(honest, now, None).unwrap();
        assert!(verified.permissions().allows_read("/repo/pkg/file"));
        assert!(!verified.permissions().allows_read("/repo/other"));
        assert!(!verified.permissions().allows_write("/repo/src/x"));
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
