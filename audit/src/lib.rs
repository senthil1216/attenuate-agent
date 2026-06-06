use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event: AuditEvent,
    pub previous_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditEvent {
    RootMinted { task_id: Uuid },
    CapabilityAttenuated { task_id: Uuid },
    ToolAllowed { tool_name: String },
    ToolDenied { tool_name: String, reason: String },
}

impl std::fmt::Display for AuditEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditEvent::RootMinted { task_id } => {
                write!(f, "ROOT MINTED   task={task_id}")
            }
            AuditEvent::CapabilityAttenuated { task_id } => {
                write!(f, "ATTENUATED    task={task_id}")
            }
            AuditEvent::ToolAllowed { tool_name } => {
                write!(f, "ALLOWED       {tool_name}")
            }
            AuditEvent::ToolDenied { tool_name, reason } => {
                write!(f, "DENIED        {tool_name}  — {reason}")
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit chain is broken at entry {index}")]
    BrokenChain { index: usize },
    #[error("audit entry hash mismatch at entry {index}")]
    HashMismatch { index: usize },
}

pub fn chain_entry(
    previous_hash: [u8; 32],
    timestamp: DateTime<Utc>,
    event: AuditEvent,
) -> Result<AuditEntry, AuditError> {
    let id = Uuid::new_v4();
    let entry_hash = hash_entry_fields(id, timestamp, &event, previous_hash);

    Ok(AuditEntry {
        id,
        timestamp,
        event,
        previous_hash,
        entry_hash,
    })
}

pub fn verify_chain(entries: &[AuditEntry]) -> Result<(), AuditError> {
    for (index, entry) in entries.iter().enumerate() {
        let expected_hash =
            hash_entry_fields(entry.id, entry.timestamp, &entry.event, entry.previous_hash);
        if entry.entry_hash != expected_hash {
            return Err(AuditError::HashMismatch { index });
        }

        if let Some(previous) = index.checked_sub(1).and_then(|i| entries.get(i)) {
            if entry.previous_hash != previous.entry_hash {
                return Err(AuditError::BrokenChain { index });
            }
        }
    }

    Ok(())
}

fn hash_entry_fields(
    id: Uuid,
    timestamp: DateTime<Utc>,
    event: &AuditEvent,
    previous_hash: [u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(id.as_bytes());
    hasher.update(&timestamp.timestamp().to_be_bytes());
    hasher.update(&timestamp.timestamp_subsec_nanos().to_be_bytes());
    hash_event(&mut hasher, event);
    hasher.update(&previous_hash);
    *hasher.finalize().as_bytes()
}

fn hash_event(hasher: &mut blake3::Hasher, event: &AuditEvent) {
    match event {
        AuditEvent::RootMinted { task_id } => {
            hasher.update(b"root_minted");
            hasher.update(task_id.as_bytes());
        }
        AuditEvent::CapabilityAttenuated { task_id } => {
            hasher.update(b"capability_attenuated");
            hasher.update(task_id.as_bytes());
        }
        AuditEvent::ToolAllowed { tool_name } => {
            hasher.update(b"tool_allowed");
            hash_str(hasher, tool_name);
        }
        AuditEvent::ToolDenied { tool_name, reason } => {
            hasher.update(b"tool_denied");
            hash_str(hasher, tool_name);
            hash_str(hasher, reason);
        }
    }
}

fn hash_str(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_chain_continuity() {
        let first = chain_entry(
            [0; 32],
            Utc::now(),
            AuditEvent::RootMinted {
                task_id: Uuid::nil(),
            },
        )
        .unwrap();
        let second = chain_entry(
            first.entry_hash,
            Utc::now(),
            AuditEvent::ToolAllowed {
                tool_name: "fs_read".to_string(),
            },
        )
        .unwrap();

        assert!(verify_chain(&[first, second]).is_ok());
    }

    #[test]
    fn rejects_broken_chain_continuity() {
        let first = chain_entry(
            [0; 32],
            Utc::now(),
            AuditEvent::RootMinted {
                task_id: Uuid::nil(),
            },
        )
        .unwrap();
        let second = chain_entry(
            [1; 32],
            Utc::now(),
            AuditEvent::ToolAllowed {
                tool_name: "fs_read".to_string(),
            },
        )
        .unwrap();

        assert!(matches!(
            verify_chain(&[first, second]),
            Err(AuditError::BrokenChain { index: 1 })
        ));
    }
}
