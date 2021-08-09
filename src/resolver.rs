use std::io;

use secp256k1::PublicKey;

use crate::{
    document::{self, DIDDocument},
    errors::SecurityError,
    identifier,
};

pub async fn register(url: &str, token: String) -> Result<(), SecurityError> {
    surf::post(&format!("{}/1.0/register", url))
        .header("Content-Type", "application/json")
        .body(token)
        .await
        .map_err(|e| SecurityError::NetworkError(e.to_string()))?;

    Ok(())
}

/// discover: Calls the resolver and returns DIDDocument instance or Error
pub async fn discover(
    url: &str,
    agent_did: &str,
    agent_public_key_ecdsa: &PublicKey,
) -> Result<DIDDocument, SecurityError> {
    let agent_did = agent_did.to_string();
    let did_id = agent_did.split("#").collect::<Vec<&str>>()[0];

    identifier::validate_identifier(did_id)?;

    let mut res = surf::get(format!("{}/1.0/discover/{}", url, agent_did))
        .header("Content-Type", "application/json")
        .await
        .map_err(|e| SecurityError::NetworkError(e.to_string()))?;

    let json: serde_json::Value = res
        .body_json()
        .await
        .map_err(|e| SecurityError::NetworkError(e.to_string()))?;

    match json["token"].as_str() {
        Some(token) => document::verify_document(agent_public_key_ecdsa, token.to_string()),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "resolver token").into()),
    }
}
