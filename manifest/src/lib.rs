use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskManifest {
    pub task_id: Uuid,
    pub repo_root: PathBuf,
    pub ttl_seconds: u64,
    pub filesystem: FilesystemPolicy,
    pub exec: ExecPolicy,
    pub network: NetworkPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    pub readable_roots: Vec<PathBuf>,
    pub writable_roots: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecPolicy {
    pub allowed_binaries: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum NetworkPolicy {
    DenyAll,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ManifestError {
    #[error("task manifest must have a non-zero TTL")]
    EmptyTtl,
    #[error("manifest path must be absolute and must not contain . or .. components: {0}")]
    UnsafePath(PathBuf),
    #[error("repo root must be present in readable roots")]
    RepoRootNotReadable,
}

impl TaskManifest {
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.ttl_seconds == 0 {
            return Err(ManifestError::EmptyTtl);
        }

        validate_safe_absolute_path(&self.repo_root)?;
        for root in &self.filesystem.readable_roots {
            validate_safe_absolute_path(root)?;
        }
        for root in &self.filesystem.writable_roots {
            validate_safe_absolute_path(root)?;
        }

        if !self
            .filesystem
            .readable_roots
            .iter()
            .any(|root| root == &self.repo_root)
        {
            return Err(ManifestError::RepoRootNotReadable);
        }

        Ok(())
    }
}

fn validate_safe_absolute_path(path: &Path) -> Result<(), ManifestError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ManifestError::UnsafePath(path.to_path_buf()));
    }

    Ok(())
}
