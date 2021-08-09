use document::Delegation;
use errors::SecurityError;
use identifier::DIDType;
use jwt_compact::{alg::Es256k, AlgorithmExt, Claims, Renamed};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};

pub mod document;
pub mod errors;
pub mod identifier;
mod resolver;

#[derive(Debug, Clone)]
pub struct Config {
    // TODO: make the fields private
    pub host_address: String,
    pub resolver_address: String,
    pub user_did: String,
    pub agent_did: String,
    pub agent_key_name: String,
    pub agent_secret: String,
    pub token_duration: i64,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct CustomClaims {
    #[serde(rename = "sub")]
    subject: String,
    #[serde(rename = "iss")]
    issuer: String,
    #[serde(rename = "aud")]
    audience: String,
    // #[serde(rename = "iat")]
    // issued_at: i64,
    #[serde(rename = "exp")]
    expiration: i64,
}

pub fn new_authentication_token(config: &Config) -> String {
    let (agent_private_key_ecdsa, _) = build_keys(config);

    let secp = Secp256k1::new();
    let alg: Es256k = Es256k::new(secp);
    let alg = Renamed::new(alg, "ES256");

    #[cfg(feature = "wasm")]
    let now = js_sys::Date::now() as i64 / 1000;

    #[cfg(feature = "default")]
    let now = chrono::Utc::now().timestamp_millis() - config.token_duration * 1000;

    // let issued_at = now - config.token_duration * 1000;
    let expiration = now + config.token_duration * 1000;

    let claims = Claims::new(CustomClaims {
        subject: config.user_did.clone(),
        issuer: format!("{}#{}", config.agent_did, config.agent_key_name),
        audience: "not-currently-used.example.com".to_string(),
        // issued_at,
        expiration,
    });

    let token = alg
        .token(Default::default(), &claims, &agent_private_key_ecdsa)
        .unwrap();

    token
}

pub async fn new_twin_did(config: &Config, label: String) -> Result<String, SecurityError> {
    let seed = hex::encode(&label);
    let master = identifier::seed_to_master(&seed);
    let twin_private_key_hex =
        identifier::new_private_hex_from_path_str(master, identifier::DIDType::twin, label);
    let twin_private_key_ecdsa = identifier::private_hex_to_ecdsa(twin_private_key_hex);
    let twin_public_key_ecdsa = identifier::private_ecdsa_to_public_ecdsa(&twin_private_key_ecdsa);

    let (agent_private_key_ecdsa, agent_public_key_ecdsa) = build_keys(config);

    let agent_doc = resolver::discover(
        &config.resolver_address,
        &config.agent_did,
        &agent_public_key_ecdsa,
    )
    .await?;

    let mut twin_doc =
        document::new_did_document(DIDType::twin, &twin_private_key_ecdsa, "".to_string()).await?;
    let twin_id = twin_doc.id();

    let twin_doc_existing =
        resolver::discover(&config.resolver_address, twin_id, &twin_public_key_ecdsa).await;

    if let Ok(_) = twin_doc_existing {
        return Ok(twin_id.to_string());
    }

    for delegation in twin_doc.delegate_control() {
        if delegation.controller().contains(&config.agent_did) {
            return Err(SecurityError::DelegationExists);
        }
    }

    let proof = document::new_proof(&twin_doc.id(), &agent_private_key_ecdsa);
    let controller = format!(
        "{}{}",
        &config.agent_did,
        agent_doc.public_keys().first().unwrap().id()
    );

    let delegation = Delegation::new(
        format!("#{}", &config.agent_key_name),
        controller.clone(),
        proof,
        false,
    )
    .await?;

    twin_doc.add_control_delegation(delegation).await?;

    let issuer = format!(
        "{}{}",
        twin_doc.id(),
        twin_doc.public_keys().first().unwrap().id()
    );

    let twin_id = twin_doc.id().clone().to_string();

    let token = document::new_document_token(
        twin_doc,
        config.resolver_address.clone(),
        issuer,
        &twin_private_key_ecdsa,
    );

    resolver::register(&config.resolver_address, token).await?;

    Ok(twin_id)
}

fn build_keys(config: &Config) -> (SecretKey, PublicKey) {
    let master = identifier::seed_to_master(&config.agent_secret);

    let private_key_hex =
        identifier::new_private_hex_from_path(master, identifier::DIDType::agent, 0);

    let secret_key = identifier::private_hex_to_ecdsa(private_key_hex);
    let public_key = identifier::private_ecdsa_to_public_ecdsa(&secret_key);

    (secret_key, public_key)
}
