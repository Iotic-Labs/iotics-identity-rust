use std::convert::TryFrom;

use jwt_compact::{alg::Es256k, AlgorithmExt, Claims, Header, Renamed, Token, UntrustedToken};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    errors::SecurityError,
    identifier::{self, DIDType},
};

const DOCUMENT_CONTEXT: &str = "https://w3id.org/did/v1";
const DOCUMENT_VERSION: &str = "0.0.1";
const DOCUMENT_PUBLICKEY_TYPE: &str = "Secp256k1VerificationKey2018";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyID {
    id: String,
    #[serde(rename = "type")]
    key_type: String,
    #[serde(rename = "publicKeyBase58")]
    public_base58: String,
    revoked: Option<bool>,
}

impl KeyID {
    pub fn new_keyid_publickey(name: String, public_base58: String, revoked: bool) -> Self {
        Self {
            id: name,
            key_type: DOCUMENT_PUBLICKEY_TYPE.to_string(),
            public_base58,
            revoked: Some(revoked),
        }
    }

    pub fn id(&self) -> &String {
        &self.id
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Delegation {
    id: String,
    controller: String,
    proof: String,
    revoked: bool,
}

impl Delegation {
    pub async fn new(
        name: String,
        controller: String,
        proof: String,
        revoked: bool,
    ) -> Result<Self, SecurityError> {
        let delegation = Self {
            id: name,
            controller,
            proof,
            revoked: revoked,
        };

        delegation.validate(None).await?;

        Ok(delegation)
    }

    pub fn id(&self) -> &String {
        &self.id
    }

    pub fn controller(&self) -> &String {
        &self.controller
    }

    pub async fn validate(&self, parent_id: Option<&String>) -> Result<(), SecurityError> {
        identifier::validate_key_name(&self.id)?;
        identifier::validate_identifier(&self.controller)?;

        if let Some(parent_id) = parent_id {
            if identifier::compare_identifier_only(parent_id, &self.controller) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Delegate to self",
                )
                .into());
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Metadata {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DIDDocument {
    #[serde(rename = "@context")]
    context: String,
    id: String,
    #[serde(rename = "ioticsSpecVersion")]
    iotics_spec_version: String,
    #[serde(rename = "ioticsDIDType")]
    iotics_did_type: String,
    #[serde(rename = "updateTime")]
    update_time: i64,
    proof: String,
    #[serde(rename = "publicKey")]
    public_keys: Vec<KeyID>,
    #[serde(default)]
    authentication: Vec<String>,
    #[serde(default, rename = "delegateControl")]
    delegate_control: Vec<Delegation>,
    #[serde(default, rename = "delegateAuthentication")]
    delegate_authentication: Vec<String>,
    metadata: Metadata,
}

impl DIDDocument {
    pub async fn new(
        did_type: DIDType,
        did_identifier: String,
        proof: String,
        key_id: KeyID,
    ) -> Result<DIDDocument, SecurityError> {
        #[cfg(feature = "wasm")]
        let update_time = js_sys::Date::now() as i64;

        #[cfg(feature = "default")]
        let update_time = chrono::Utc::now().timestamp_millis();

        let doc = DIDDocument {
            context: DOCUMENT_CONTEXT.to_string(),
            id: did_identifier,
            iotics_spec_version: DOCUMENT_VERSION.to_string(),
            iotics_did_type: did_type.to_string(),
            update_time,
            proof,
            public_keys: vec![key_id],
            authentication: Vec::new(),
            delegate_control: Vec::new(),
            delegate_authentication: Vec::new(),
            metadata: Metadata {},
        };

        doc.validate().await?;

        Ok(doc)
    }

    pub async fn validate(&self) -> Result<(), SecurityError> {
        for delegate in &self.delegate_control {
            delegate.validate(Some(&self.id)).await?;
        }

        Ok(())
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn delegate_control(&self) -> &Vec<Delegation> {
        &self.delegate_control
    }

    pub fn public_keys(&self) -> &Vec<KeyID> {
        &self.public_keys
    }

    pub fn check_delegation_uniqueness(&self, _name: &String) -> Result<(), SecurityError> {
        // TODO
        Ok(())
    }

    pub async fn add_control_delegation(
        &mut self,
        delegation: Delegation,
    ) -> Result<(), SecurityError> {
        delegation.validate(None).await?;
        self.check_delegation_uniqueness(delegation.id())?;

        let delegate_control = &mut self.delegate_control;

        delegate_control.push(delegation);

        Ok(())
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ClaimsDIDDocument {
    #[serde(rename = "iss")]
    issuer: String,
    #[serde(rename = "aud")]
    audience: String,
    doc: DIDDocument,
}

/// verify_document: Take a DDO token string and return DIDDocument instance or error
pub fn verify_document(
    public_key_ecdsa: &PublicKey,
    token_string: String,
) -> Result<DIDDocument, SecurityError> {
    let token = UntrustedToken::try_from(token_string.as_str())?;

    let secp = Secp256k1::new();
    let alg: Es256k = Es256k::new(secp);
    let alg = Renamed::new(alg, "ES256");

    let token: Token<ClaimsDIDDocument> = alg.validate_integrity(&token, public_key_ecdsa)?;

    let claims = &token.claims().custom;

    let document = claims.doc.clone();

    // TODO: verify document

    Ok(document)
}

/// new_did_document: Returns a new DIDDocument instance
pub async fn new_did_document(
    did_type: DIDType,
    private_ecdsa: &SecretKey,
    name: String,
) -> Result<DIDDocument, SecurityError> {
    let mut name = name;

    if name.len() == 0 {
        name = format!("#{}-0", did_type.to_string());
    }

    let public_ecdsa = identifier::private_ecdsa_to_public_ecdsa(private_ecdsa);
    let public_bytes = identifier::public_ecdsa_to_bytes(&public_ecdsa);
    let public_base58 = identifier::public_ecdsa_to_base58(&public_ecdsa);
    let did_identifier = identifier::make_identifier(public_bytes);

    let proof = new_proof(&did_identifier, private_ecdsa);

    let key_id = KeyID::new_keyid_publickey(name.to_string(), public_base58, false);

    DIDDocument::new(did_type, did_identifier, proof, key_id).await
}

/// new_proof: Return base64 encoded signature of sha256(content)
/// Note: Signature format is ASN1(R,S)
pub fn new_proof(content: &str, private_ecdsa: &SecretKey) -> String {
    // TODO: use bitcoin_hashes
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let hashed_content = hasher.finalize();
    let hashed_content = hashed_content.as_ref();

    let message = Message::from_slice(&hashed_content).expect("32 bytes");

    let secp = Secp256k1::new();
    let sig = secp.sign(&message, private_ecdsa).serialize_der().to_vec();

    base64::encode_config(sig, base64::STANDARD)
}

/// new_document_token: Takes a DIDDocument instance and returns a jwt for registering with the resolver
pub fn new_document_token(
    doc: DIDDocument,
    audience: String,
    issuer: String,
    private_ecdsa: &SecretKey,
) -> String {
    let secp = Secp256k1::new();
    let alg: Es256k = Es256k::new(secp);
    let alg = Renamed::new(alg, "ES256");

    let claims = Claims::new(ClaimsDIDDocument {
        issuer,
        audience,
        doc,
    });

    let header = Header::default().with_key_id("my-JWT");

    let token = alg.token(header, &claims, &private_ecdsa).unwrap();

    token
}
