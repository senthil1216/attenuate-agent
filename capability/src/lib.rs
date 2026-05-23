use biscuit_auth::KeyPair;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;
use warden_manifest::{ManifestError, TaskManifest};

pub use warden_manifest::NetworkPolicy;

#[allow(dead_code)]
mod biscuit_codec;

/// A narrowed set of permissions carried by a root or child capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionSet {
    readable_roots: BTreeSet<PathBuf>,
    writable_roots: BTreeSet<PathBuf>,
    exec_binaries: BTreeSet<String>,
    network: NetworkPolicy,
}

/// A request to append a child caveat. Every field must be equal to or narrower than the parent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttenuationRequest {
    pub readable_roots: BTreeSet<PathBuf>,
    pub writable_roots: BTreeSet<PathBuf>,
    pub exec_binaries: BTreeSet<String>,
    pub network: NetworkPolicy,
    pub ttl_seconds: u64,
    pub request_binding: Option<RequestBinding>,
}

/// Binds a child capability to one exact tool invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestBinding {
    pub tool_name: String,
    pub argument_hash: [u8; 32],
    pub nonce: Uuid,
}

/// The authority minted from the trusted task manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootCapability {
    task_id: Uuid,
    permissions: PermissionSet,
    expires_at: DateTime<Utc>,
    token: Vec<u8>,
    root_public_key: Vec<u8>,
}

/// A child capability created only by appending caveats that narrow its parent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildCapability {
    task_id: Uuid,
    permissions: PermissionSet,
    expires_at: DateTime<Utc>,
    caveats: Vec<Caveat>,
    token: Vec<u8>,
    root_public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Caveat {
    permissions: PermissionSet,
    expires_at: DateTime<Utc>,
    request_binding: Option<RequestBinding>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CapabilityError {
    #[error("invalid task manifest: {0}")]
    InvalidManifest(#[from] ManifestError),
    #[error("path must be absolute and must not contain . or .. components: {0}")]
    UnsafePath(PathBuf),
    #[error("requested filesystem read authority widens parent capability")]
    ReadScopeWidened,
    #[error("requested filesystem write authority widens parent capability")]
    WriteScopeWidened,
    #[error("requested exec authority widens parent capability")]
    ExecScopeWidened,
    #[error("requested TTL widens parent capability")]
    TtlWidened,
    #[error("requested TTL cannot be represented safely")]
    TtlOverflow,
    #[error("failed to build or parse biscuit token: {0}")]
    Biscuit(String),
}

impl From<biscuit_codec::CodecError> for CapabilityError {
    fn from(value: biscuit_codec::CodecError) -> Self {
        CapabilityError::Biscuit(value.to_string())
    }
}

impl PermissionSet {
    pub fn from_manifest(manifest: &TaskManifest) -> Result<Self, CapabilityError> {
        Ok(Self {
            readable_roots: checked_paths(&manifest.filesystem.readable_roots)?,
            writable_roots: checked_paths(&manifest.filesystem.writable_roots)?,
            exec_binaries: manifest.exec.allowed_binaries.iter().cloned().collect(),
            network: manifest.network,
        })
    }

    pub fn allows_read<P: AsRef<Path>>(&self, path: P) -> bool {
        checked_path(path.as_ref())
            .map(|path| is_under_any_root(&path, &self.readable_roots))
            .unwrap_or(false)
    }

    pub fn allows_write<P: AsRef<Path>>(&self, path: P) -> bool {
        checked_path(path.as_ref())
            .map(|path| is_under_any_root(&path, &self.writable_roots))
            .unwrap_or(false)
    }

    pub fn allows_exec(&self, binary: &str) -> bool {
        self.exec_binaries.contains(binary)
    }

    pub fn network(&self) -> NetworkPolicy {
        self.network
    }

    pub fn readable_roots(&self) -> &BTreeSet<PathBuf> {
        &self.readable_roots
    }

    pub fn writable_roots(&self) -> &BTreeSet<PathBuf> {
        &self.writable_roots
    }

    pub fn exec_binaries(&self) -> &BTreeSet<String> {
        &self.exec_binaries
    }

    fn contains_all_roots(&self, requested: &BTreeSet<PathBuf>, writable: bool) -> bool {
        let parent_roots = if writable {
            &self.writable_roots
        } else {
            &self.readable_roots
        };

        requested.iter().all(|requested_root| {
            checked_path(requested_root)
                .map(|path| is_under_any_root(&path, parent_roots))
                .unwrap_or(false)
        })
    }

    fn contains_all_exec(&self, requested: &BTreeSet<String>) -> bool {
        requested
            .iter()
            .all(|binary| self.exec_binaries.contains(binary))
    }

    pub(crate) fn from_codec(
        readable_roots: BTreeSet<PathBuf>,
        writable_roots: BTreeSet<PathBuf>,
        exec_binaries: BTreeSet<String>,
        network: NetworkPolicy,
    ) -> Self {
        Self {
            readable_roots,
            writable_roots,
            exec_binaries,
            network,
        }
    }

    pub(crate) fn readable_roots_iter(&self) -> impl Iterator<Item = &PathBuf> {
        self.readable_roots.iter()
    }

    pub(crate) fn writable_roots_iter(&self) -> impl Iterator<Item = &PathBuf> {
        self.writable_roots.iter()
    }

    pub(crate) fn exec_binaries_iter(&self) -> impl Iterator<Item = &str> {
        self.exec_binaries.iter().map(|s| s.as_str())
    }
}

impl RootCapability {
    pub fn mint(manifest: &TaskManifest, now: DateTime<Utc>) -> Result<Self, CapabilityError> {
        manifest.validate()?;
        let expires_at = checked_expires_at(now, manifest.ttl_seconds)?;
        let permissions = PermissionSet::from_manifest(manifest)?;

        let keypair = KeyPair::new();
        let root_public_key = keypair.public().to_bytes().to_vec();
        let token =
            biscuit_codec::build_root_token(manifest.task_id, &permissions, expires_at, &keypair)?;

        Ok(Self {
            task_id: manifest.task_id,
            permissions,
            expires_at,
            token,
            root_public_key,
        })
    }

    pub fn permissions(&self) -> &PermissionSet {
        &self.permissions
    }

    pub fn token(&self) -> &[u8] {
        &self.token
    }

    pub fn root_public_key(&self) -> &[u8] {
        &self.root_public_key
    }

    pub fn attenuate(
        &self,
        request: AttenuationRequest,
        now: DateTime<Utc>,
    ) -> Result<ChildCapability, CapabilityError> {
        validate_attenuation(&self.permissions, self.expires_at, &request, now)?;

        let expires_at = checked_expires_at(now, request.ttl_seconds)?;
        let permissions = PermissionSet {
            readable_roots: checked_paths(&request.readable_roots)?,
            writable_roots: checked_paths(&request.writable_roots)?,
            exec_binaries: request.exec_binaries,
            network: request.network,
        };

        let root_public_key = parse_public_key(&self.root_public_key)?;
        let token = biscuit_codec::append_block(
            &self.token,
            root_public_key,
            1,
            &permissions,
            expires_at,
            request.request_binding.as_ref(),
        )?;

        Ok(ChildCapability {
            task_id: self.task_id,
            caveats: vec![Caveat {
                permissions: permissions.clone(),
                expires_at,
                request_binding: request.request_binding,
            }],
            permissions,
            expires_at,
            token,
            root_public_key: self.root_public_key.clone(),
        })
    }
}

impl ChildCapability {
    pub fn attenuate(
        &self,
        request: AttenuationRequest,
        now: DateTime<Utc>,
    ) -> Result<Self, CapabilityError> {
        validate_attenuation(&self.permissions, self.expires_at, &request, now)?;

        let expires_at = checked_expires_at(now, request.ttl_seconds)?;
        let permissions = PermissionSet {
            readable_roots: checked_paths(&request.readable_roots)?,
            writable_roots: checked_paths(&request.writable_roots)?,
            exec_binaries: request.exec_binaries,
            network: request.network,
        };

        let next_block_id = (self.caveats.len() as i64) + 1;
        let root_public_key = parse_public_key(&self.root_public_key)?;
        let token = biscuit_codec::append_block(
            &self.token,
            root_public_key,
            next_block_id,
            &permissions,
            expires_at,
            request.request_binding.as_ref(),
        )?;

        let mut caveats = self.caveats.clone();
        caveats.push(Caveat {
            permissions: permissions.clone(),
            expires_at,
            request_binding: request.request_binding,
        });

        Ok(Self {
            task_id: self.task_id,
            permissions,
            expires_at,
            caveats,
            token,
            root_public_key: self.root_public_key.clone(),
        })
    }

    pub fn permissions(&self) -> &PermissionSet {
        &self.permissions
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn request_binding(&self) -> Option<&RequestBinding> {
        self.caveats
            .iter()
            .rev()
            .find_map(|caveat| caveat.request_binding.as_ref())
    }

    pub fn token(&self) -> &[u8] {
        &self.token
    }

    pub fn root_public_key(&self) -> &[u8] {
        &self.root_public_key
    }

    pub fn verify_signature(&self) -> Result<(), CapabilityError> {
        let public_key = parse_public_key(&self.root_public_key)?;
        biscuit_codec::verify_signature(&self.token, public_key)?;
        Ok(())
    }
}

fn parse_public_key(bytes: &[u8]) -> Result<biscuit_auth::PublicKey, CapabilityError> {
    biscuit_auth::PublicKey::from_bytes(bytes)
        .map_err(|e| CapabilityError::Biscuit(format!("invalid root public key: {e}")))
}

pub fn hash_tool_arguments(tool_name: &str, canonical_arguments: &[u8], nonce: Uuid) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(tool_name.as_bytes());
    hasher.update(&[0]);
    hasher.update(canonical_arguments);
    hasher.update(&[0]);
    hasher.update(nonce.as_bytes());
    *hasher.finalize().as_bytes()
}

fn validate_attenuation(
    parent: &PermissionSet,
    parent_expires_at: DateTime<Utc>,
    request: &AttenuationRequest,
    now: DateTime<Utc>,
) -> Result<(), CapabilityError> {
    if !parent.contains_all_roots(&request.readable_roots, false) {
        return Err(CapabilityError::ReadScopeWidened);
    }
    if !parent.contains_all_roots(&request.writable_roots, true) {
        return Err(CapabilityError::WriteScopeWidened);
    }
    if !parent.contains_all_exec(&request.exec_binaries) {
        return Err(CapabilityError::ExecScopeWidened);
    }
    if checked_expires_at(now, request.ttl_seconds)? > parent_expires_at {
        return Err(CapabilityError::TtlWidened);
    }

    Ok(())
}

fn checked_expires_at(
    now: DateTime<Utc>,
    ttl_seconds: u64,
) -> Result<DateTime<Utc>, CapabilityError> {
    let ttl_seconds = i64::try_from(ttl_seconds).map_err(|_| CapabilityError::TtlOverflow)?;
    now.checked_add_signed(Duration::seconds(ttl_seconds))
        .ok_or(CapabilityError::TtlOverflow)
}

fn checked_paths<I, P>(paths: I) -> Result<BTreeSet<PathBuf>, CapabilityError>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    paths
        .into_iter()
        .map(|path| checked_path(path.as_ref()))
        .collect()
}

fn checked_path(path: &Path) -> Result<PathBuf, CapabilityError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(CapabilityError::UnsafePath(path.to_path_buf()));
    }

    Ok(resolve_existing_ancestor(path))
}

fn resolve_existing_ancestor(path: &Path) -> PathBuf {
    let mut cursor = path;
    let mut suffix = Vec::<OsString>::new();

    loop {
        if cursor.exists() {
            let mut resolved = cursor
                .canonicalize()
                .unwrap_or_else(|_| cursor.components().collect());
            for component in suffix.iter().rev() {
                resolved.push(component);
            }
            return resolved;
        }

        if let Some(file_name) = cursor.file_name() {
            suffix.push(file_name.to_os_string());
        }

        match cursor.parent() {
            Some(parent) => cursor = parent,
            None => return path.components().collect(),
        }
    }
}

fn is_under_any_root(path: &Path, roots: &BTreeSet<PathBuf>) -> bool {
    roots.iter().any(|root| path.starts_with(root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use proptest::prelude::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use warden_manifest::{ExecPolicy, FilesystemPolicy};

    fn root_manifest() -> TaskManifest {
        TaskManifest {
            task_id: Uuid::nil(),
            repo_root: PathBuf::from("/repo"),
            ttl_seconds: 60,
            filesystem: FilesystemPolicy {
                readable_roots: vec![PathBuf::from("/repo")],
                writable_roots: vec![PathBuf::from("/repo/src")],
            },
            exec: ExecPolicy {
                allowed_binaries: vec!["python".to_string(), "pytest".to_string()],
            },
            network: NetworkPolicy::DenyAll,
        }
    }

    fn attenuation_request(
        readable_roots: &[&str],
        writable_roots: &[&str],
        exec_binaries: &[&str],
        ttl_seconds: u64,
    ) -> AttenuationRequest {
        AttenuationRequest {
            readable_roots: readable_roots.iter().map(PathBuf::from).collect(),
            writable_roots: writable_roots.iter().map(PathBuf::from).collect(),
            exec_binaries: exec_binaries
                .iter()
                .map(|binary| binary.to_string())
                .collect(),
            network: NetworkPolicy::DenyAll,
            ttl_seconds,
            request_binding: None,
        }
    }

    #[test]
    fn mint_validates_manifest() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut manifest = root_manifest();
        manifest.ttl_seconds = 0;

        assert!(matches!(
            RootCapability::mint(&manifest, now),
            Err(CapabilityError::InvalidManifest(ManifestError::EmptyTtl))
        ));
    }

    #[test]
    fn rejects_paths_with_parent_components() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let root = RootCapability::mint(&root_manifest(), now).unwrap();

        assert!(!root.permissions().allows_read("/repo/../secret"));
        assert_eq!(
            root.attenuate(attenuation_request(&["/repo/../secret"], &[], &[], 1), now)
                .unwrap_err(),
            CapabilityError::ReadScopeWidened
        );
    }

    #[test]
    fn accepts_trailing_slash_root_variants() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let root = RootCapability::mint(&root_manifest(), now).unwrap();

        assert!(root
            .attenuate(attenuation_request(&["/repo/"], &[], &[], 1), now)
            .is_ok());
    }

    #[test]
    fn rejects_write_scope_widening() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let root = RootCapability::mint(&root_manifest(), now).unwrap();

        assert_eq!(
            root.attenuate(attenuation_request(&[], &["/repo"], &[], 1), now)
                .unwrap_err(),
            CapabilityError::WriteScopeWidened
        );
    }

    #[test]
    fn accepts_write_scope_narrowing() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let root = RootCapability::mint(&root_manifest(), now).unwrap();

        assert!(root
            .attenuate(attenuation_request(&[], &["/repo/src/module"], &[], 1), now)
            .is_ok());
    }

    #[test]
    fn rejects_exec_scope_widening() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let root = RootCapability::mint(&root_manifest(), now).unwrap();

        assert_eq!(
            root.attenuate(attenuation_request(&[], &[], &["curl"], 1), now)
                .unwrap_err(),
            CapabilityError::ExecScopeWidened
        );
    }

    #[test]
    fn rejects_ttl_widening_and_overflow() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let root = RootCapability::mint(&root_manifest(), now).unwrap();

        assert_eq!(
            root.attenuate(attenuation_request(&[], &[], &[], 61), now)
                .unwrap_err(),
            CapabilityError::TtlWidened
        );
        assert_eq!(
            root.attenuate(attenuation_request(&[], &[], &[], u64::MAX), now)
                .unwrap_err(),
            CapabilityError::TtlOverflow
        );
    }

    #[test]
    fn chained_child_attenuation_remains_monotonic() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let root = RootCapability::mint(&root_manifest(), now).unwrap();
        let child = root
            .attenuate(attenuation_request(&["/repo/pkg"], &[], &[], 30), now)
            .unwrap();

        assert!(child
            .attenuate(attenuation_request(&["/repo/pkg/src"], &[], &[], 10), now)
            .is_ok());
        assert_eq!(
            child
                .attenuate(attenuation_request(&["/repo"], &[], &[], 10), now)
                .unwrap_err(),
            CapabilityError::ReadScopeWidened
        );
    }

    #[test]
    fn hash_tool_arguments_is_deterministic_and_nonce_bound() {
        let nonce = Uuid::nil();
        let first = hash_tool_arguments("fs_read", br#"{"path":"/repo/src/lib.rs"}"#, nonce);
        let second = hash_tool_arguments("fs_read", br#"{"path":"/repo/src/lib.rs"}"#, nonce);
        let different_nonce =
            hash_tool_arguments("fs_read", br#"{"path":"/repo/src/lib.rs"}"#, Uuid::new_v4());

        assert_eq!(first, second);
        assert_ne!(first, different_nonce);
    }

    #[test]
    fn rejects_symlink_escape_under_allowed_root() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        let outside = temp.path().join("outside");
        let link = repo.join("link");
        fs::create_dir_all(&repo).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, &link).unwrap();

        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let manifest = TaskManifest {
            task_id: Uuid::nil(),
            repo_root: repo.clone(),
            ttl_seconds: 60,
            filesystem: FilesystemPolicy {
                readable_roots: vec![repo.clone()],
                writable_roots: vec![repo],
            },
            exec: ExecPolicy {
                allowed_binaries: vec![],
            },
            network: NetworkPolicy::DenyAll,
        };
        let root = RootCapability::mint(&manifest, now).unwrap();

        assert!(!root.permissions().allows_read(link.join("secret.txt")));
        assert!(!root.permissions().allows_write(link.join("secret.txt")));
    }

    #[test]
    fn root_token_decodes_to_minted_state() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let manifest = root_manifest();
        let root = RootCapability::mint(&manifest, now).unwrap();

        let public_key = parse_public_key(root.root_public_key()).unwrap();
        let decoded = biscuit_codec::decode_state(root.token(), public_key).unwrap();

        assert_eq!(decoded.task_id, manifest.task_id);
        assert_eq!(decoded.block_id, 0);
        assert_eq!(&decoded.permissions, root.permissions());
        assert_eq!(decoded.expires_at, now + Duration::seconds(60));
        assert!(decoded.request_binding.is_none());
    }

    #[test]
    fn attenuated_token_decodes_to_latest_block_state() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let root = RootCapability::mint(&root_manifest(), now).unwrap();
        let nonce = Uuid::nil();
        let argument_hash = hash_tool_arguments("fs_read", b"args", nonce);
        let request = AttenuationRequest {
            readable_roots: ["/repo/pkg".into()].into_iter().collect(),
            writable_roots: BTreeSet::new(),
            exec_binaries: ["python".to_string()].into_iter().collect(),
            network: NetworkPolicy::DenyAll,
            ttl_seconds: 30,
            request_binding: Some(RequestBinding {
                tool_name: "fs_read".to_string(),
                argument_hash,
                nonce,
            }),
        };
        let child = root.attenuate(request, now).unwrap();

        let public_key = parse_public_key(child.root_public_key()).unwrap();
        let decoded = biscuit_codec::decode_state(child.token(), public_key).unwrap();

        assert_eq!(decoded.block_id, 1);
        assert_eq!(&decoded.permissions, child.permissions());
        assert_eq!(decoded.expires_at, now + Duration::seconds(30));
        let binding = decoded.request_binding.expect("binding present");
        assert_eq!(binding.tool_name, "fs_read");
        assert_eq!(binding.argument_hash, argument_hash);
        assert_eq!(binding.nonce, nonce);
    }

    #[test]
    fn token_rejects_wrong_root_public_key() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let root = RootCapability::mint(&root_manifest(), now).unwrap();
        let other_keypair = biscuit_auth::KeyPair::new();

        assert!(biscuit_codec::verify_signature(root.token(), other_keypair.public()).is_err());
    }

    proptest! {
        #[test]
        fn attenuation_rejects_read_scope_widening(path_suffix in "[a-z]{1,12}") {
            let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
            let root = RootCapability::mint(&root_manifest(), now).unwrap();
            let mut readable_roots = BTreeSet::new();
            readable_roots.insert(PathBuf::from(format!("/outside/{path_suffix}")));

            let request = AttenuationRequest {
                readable_roots,
                writable_roots: BTreeSet::new(),
                exec_binaries: BTreeSet::new(),
                network: NetworkPolicy::DenyAll,
                ttl_seconds: 1,
                request_binding: None,
            };

            prop_assert_eq!(
                root.attenuate(request, now).unwrap_err(),
                CapabilityError::ReadScopeWidened
            );
        }

        #[test]
        fn attenuation_accepts_read_scope_narrowing(path_suffix in "[a-z]{1,12}") {
            let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
            let root = RootCapability::mint(&root_manifest(), now).unwrap();
            let mut readable_roots = BTreeSet::new();
            readable_roots.insert(PathBuf::from(format!("/repo/{path_suffix}")));

            let request = AttenuationRequest {
                readable_roots,
                writable_roots: BTreeSet::new(),
                exec_binaries: BTreeSet::new(),
                network: NetworkPolicy::DenyAll,
                ttl_seconds: 1,
                request_binding: None,
            };

            prop_assert!(root.attenuate(request, now).is_ok());
        }
    }
}
