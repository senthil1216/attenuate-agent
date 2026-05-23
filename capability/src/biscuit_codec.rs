use biscuit_auth::builder::BlockBuilder;
use biscuit_auth::{Biscuit, KeyPair, PublicKey};
use chrono::{DateTime, Utc};
use std::collections::BTreeSet;
use std::path::PathBuf;
use uuid::Uuid;

use crate::{NetworkPolicy, PermissionSet, RequestBinding};

#[derive(Debug, thiserror::Error)]
pub(crate) enum CodecError {
    #[error("biscuit error: {0}")]
    Biscuit(String),
    #[error("biscuit token is missing required fact: {0}")]
    MissingFact(&'static str),
    #[error("biscuit fact has unparseable value: {0}")]
    InvalidValue(&'static str),
}

impl From<biscuit_auth::error::Token> for CodecError {
    fn from(value: biscuit_auth::error::Token) -> Self {
        CodecError::Biscuit(value.to_string())
    }
}

pub(crate) fn build_root_token(
    task_id: Uuid,
    permissions: &PermissionSet,
    expires_at: DateTime<Utc>,
    keypair: &KeyPair,
) -> Result<Vec<u8>, CodecError> {
    let mut builder = Biscuit::builder();
    builder.add_fact(format!("task_id(\"{task_id}\")").as_str())?;
    for fact in state_facts(0, permissions, expires_at, None) {
        builder.add_fact(fact.as_str())?;
    }
    let biscuit = builder.build(keypair)?;
    Ok(biscuit.to_vec()?)
}

pub(crate) fn append_block(
    token_bytes: &[u8],
    root_public_key: PublicKey,
    block_id: i64,
    permissions: &PermissionSet,
    expires_at: DateTime<Utc>,
    binding: Option<&RequestBinding>,
) -> Result<Vec<u8>, CodecError> {
    let biscuit = Biscuit::from(token_bytes, root_public_key)?;
    let mut block = BlockBuilder::new();
    for fact in state_facts(block_id, permissions, expires_at, binding) {
        block.add_fact(fact.as_str())?;
    }
    let appended = biscuit.append(block)?;
    Ok(appended.to_vec()?)
}

pub(crate) fn verify_signature(
    token_bytes: &[u8],
    root_public_key: PublicKey,
) -> Result<(), CodecError> {
    Biscuit::from(token_bytes, root_public_key)?;
    Ok(())
}

#[derive(Debug)]
pub(crate) struct DecodedState {
    pub task_id: Uuid,
    pub permissions: PermissionSet,
    pub expires_at: DateTime<Utc>,
    pub request_binding: Option<RequestBinding>,
    pub block_id: i64,
}

pub(crate) fn decode_state(
    token_bytes: &[u8],
    root_public_key: PublicKey,
) -> Result<DecodedState, CodecError> {
    let biscuit = Biscuit::from(token_bytes, root_public_key)?;
    let mut authorizer = biscuit.authorizer()?;

    let task_id_rows: Vec<(String,)> = authorizer.query_all("data($id) <- task_id($id)")?;
    let task_id_str = task_id_rows
        .into_iter()
        .next()
        .ok_or(CodecError::MissingFact("task_id"))?
        .0;
    let task_id = Uuid::parse_str(&task_id_str).map_err(|_| CodecError::InvalidValue("task_id"))?;

    let expires_rows: Vec<(i64, String)> =
        authorizer.query_all("data($id, $val) <- expires_at($id, $val)")?;
    let (block_id, expires_str) = expires_rows
        .into_iter()
        .max_by_key(|(id, _)| *id)
        .ok_or(CodecError::MissingFact("expires_at"))?;
    let expires_at = DateTime::parse_from_rfc3339(&expires_str)
        .map_err(|_| CodecError::InvalidValue("expires_at"))?
        .with_timezone(&Utc);

    let read_rows: Vec<(i64, String)> =
        authorizer.query_all("data($id, $val) <- read_root($id, $val)")?;
    let readable_roots: BTreeSet<PathBuf> = read_rows
        .into_iter()
        .filter(|(id, _)| *id == block_id)
        .map(|(_, v)| PathBuf::from(v))
        .collect();

    let write_rows: Vec<(i64, String)> =
        authorizer.query_all("data($id, $val) <- write_root($id, $val)")?;
    let writable_roots: BTreeSet<PathBuf> = write_rows
        .into_iter()
        .filter(|(id, _)| *id == block_id)
        .map(|(_, v)| PathBuf::from(v))
        .collect();

    let exec_rows: Vec<(i64, String)> =
        authorizer.query_all("data($id, $val) <- exec_binary($id, $val)")?;
    let exec_binaries: BTreeSet<String> = exec_rows
        .into_iter()
        .filter(|(id, _)| *id == block_id)
        .map(|(_, v)| v)
        .collect();

    let network_rows: Vec<(i64, String)> =
        authorizer.query_all("data($id, $val) <- network($id, $val)")?;
    let network_str = network_rows
        .into_iter()
        .filter(|(id, _)| *id == block_id)
        .map(|(_, v)| v)
        .next()
        .ok_or(CodecError::MissingFact("network"))?;
    let network = parse_network(&network_str)?;

    let permissions =
        PermissionSet::from_codec(readable_roots, writable_roots, exec_binaries, network);

    let binding_tool_rows: Vec<(i64, String)> =
        authorizer.query_all("data($id, $val) <- binding_tool($id, $val)")?;
    let binding_tool = binding_tool_rows
        .into_iter()
        .filter(|(id, _)| *id == block_id)
        .map(|(_, v)| v)
        .next();

    let request_binding = if let Some(tool_name) = binding_tool {
        let hash_rows: Vec<(i64, String)> =
            authorizer.query_all("data($id, $val) <- binding_arg_hash($id, $val)")?;
        let hash_hex = hash_rows
            .into_iter()
            .filter(|(id, _)| *id == block_id)
            .map(|(_, v)| v)
            .next()
            .ok_or(CodecError::MissingFact("binding_arg_hash"))?;
        let argument_hash =
            decode_hex32(&hash_hex).ok_or(CodecError::InvalidValue("binding_arg_hash"))?;
        let nonce_rows: Vec<(i64, String)> =
            authorizer.query_all("data($id, $val) <- binding_nonce($id, $val)")?;
        let nonce_str = nonce_rows
            .into_iter()
            .filter(|(id, _)| *id == block_id)
            .map(|(_, v)| v)
            .next()
            .ok_or(CodecError::MissingFact("binding_nonce"))?;
        let nonce =
            Uuid::parse_str(&nonce_str).map_err(|_| CodecError::InvalidValue("binding_nonce"))?;
        Some(RequestBinding {
            tool_name,
            argument_hash,
            nonce,
        })
    } else {
        None
    };

    Ok(DecodedState {
        task_id,
        permissions,
        expires_at,
        request_binding,
        block_id,
    })
}

fn state_facts(
    block_id: i64,
    permissions: &PermissionSet,
    expires_at: DateTime<Utc>,
    binding: Option<&RequestBinding>,
) -> Vec<String> {
    let mut facts = Vec::new();
    facts.push(format!(
        "expires_at({block_id}, \"{}\")",
        escape(&expires_at.to_rfc3339())
    ));
    for path in permissions.readable_roots_iter() {
        facts.push(format!(
            "read_root({block_id}, \"{}\")",
            escape(&path.to_string_lossy())
        ));
    }
    for path in permissions.writable_roots_iter() {
        facts.push(format!(
            "write_root({block_id}, \"{}\")",
            escape(&path.to_string_lossy())
        ));
    }
    for binary in permissions.exec_binaries_iter() {
        facts.push(format!("exec_binary({block_id}, \"{}\")", escape(binary)));
    }
    facts.push(format!(
        "network({block_id}, \"{}\")",
        network_to_str(permissions.network())
    ));
    if let Some(b) = binding {
        facts.push(format!(
            "binding_tool({block_id}, \"{}\")",
            escape(&b.tool_name)
        ));
        facts.push(format!(
            "binding_arg_hash({block_id}, \"{}\")",
            encode_hex(&b.argument_hash)
        ));
        facts.push(format!("binding_nonce({block_id}, \"{}\")", b.nonce));
    }
    facts
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn network_to_str(policy: NetworkPolicy) -> &'static str {
    match policy {
        NetworkPolicy::DenyAll => "deny_all",
        _ => "deny_all",
    }
}

fn parse_network(s: &str) -> Result<NetworkPolicy, CodecError> {
    match s {
        "deny_all" => Ok(NetworkPolicy::DenyAll),
        _ => Err(CodecError::InvalidValue("network")),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = (bytes[i * 2] as char).to_digit(16)?;
        let lo = (bytes[i * 2 + 1] as char).to_digit(16)?;
        *byte = ((hi << 4) | lo) as u8;
    }
    Some(out)
}
