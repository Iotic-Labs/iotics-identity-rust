use std::fmt;

use blake2::{
    digest::{Update, VariableOutput},
    VarBlake2b,
};
use hmac::{Hmac, Mac, NewMac};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use regex::Regex;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Sha256, Sha512};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

pub const IDENTIFIER_NAME_PATTERN: &str = r"^\#[a-zA-Z\-_0-9]{1,24}$";
pub const IDENTIFIER_PREFIX: &str = "did:iotics:";
pub const IDENTIFIER_PATH: &str = "iotics/0";
pub const IDENTIFIER_ID_PATTERN: &str =
    r"^did:iotics:iot(?P<hash>[a-km-zA-HJ-NP-Z1-9]{33})(?P<keyname>\#[a-zA-Z\-_0-9]{1,24})?$";

use std::string::ToString;

use crate::errors::SecurityError;

/// DIDType: enum for valid DID Document types
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum DIDType {
    host,
    user,
    agent,
    twin,
}

impl fmt::Display for DIDType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// new_master_seed: Make a new random seed length 256 bits returns hex string
pub fn new_master_seed() -> String {
    // TODO: ensure that this is up to the crypto standards
    let mut rng = ChaCha20Rng::from_entropy();
    let mut data_bytes = [0; 32];
    rng.fill_bytes(&mut data_bytes);

    let data_hex = hex::encode(data_bytes.as_ref());
    data_hex
}

/// seed_to_master: Takes seed hex and returns master bytes
pub fn seed_to_master(seed_hex: &String) -> Vec<u8> {
    let seed = hex::decode(seed_hex).unwrap();
    let mac = HmacSha512::new_varkey(&seed).unwrap();
    let result = mac.finalize();
    let master = result.into_bytes().to_vec();
    master
}

/// new_private_hex_from_path: Takes master bytes, purpose and count and returns new private key str hex
pub fn new_private_hex_from_path(master: Vec<u8>, purpose: DIDType, count: u16) -> String {
    let name = format!("{:02}", count);
    new_private_hex_from_path_str(master, purpose, name)
}

/// new_private_hex_from_path: Takes master bytes, purpose and count and returns new private key str hex
pub fn new_private_hex_from_path_str(master: Vec<u8>, purpose: DIDType, name: String) -> String {
    let path = format!("{}/{}/{}", IDENTIFIER_PATH, purpose.to_string(), name);
    let path = path.as_bytes();

    let mut mac = HmacSha256::new_varkey(&master).unwrap();
    mac.update(path);

    let private_key = mac.finalize();

    let private_key = private_key.into_bytes();
    let private_key = hex::encode(private_key);

    private_key
}

/// private_hex_to_ECDSA: Return ECDSA private key instance from private exponent hex
pub fn private_hex_to_ecdsa(private_key_hex: String) -> SecretKey {
    let private_key = hex::decode(private_key_hex).unwrap();
    let secret_key = SecretKey::from_slice(&private_key).expect("32 bytes, within curve order");
    secret_key
}

// validate_identifier: Takes DID Identifier string and returns () or error
pub fn validate_key_name(ident: &str) -> Result<(), SecurityError> {
    let re = Regex::new(IDENTIFIER_NAME_PATTERN)?;

    if !re.is_match(ident) {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Identifier name `{}` is not valid", ident),
        )
        .into())
    } else {
        Ok(())
    }
}

// validate_identifier: Takes DID Identifier string and returns () or error
pub fn validate_identifier(ident: &str) -> Result<(), SecurityError> {
    let re = Regex::new(IDENTIFIER_ID_PATTERN)?;

    if !re.is_match(ident) {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Identifier does not match pattern",
        )
        .into())
    } else {
        Ok(())
    }
}

/// private_ECDSA_to_public_ECDSA: Returns public key instance
pub fn private_ecdsa_to_public_ecdsa(private_ecdsa: &SecretKey) -> PublicKey {
    let secp = Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, &private_ecdsa);
    public_key
}

/// public_ECDSA_to_bytes: Takes a public key and returns DER uncompressed bytes
pub fn public_ecdsa_to_bytes(public_ecdsa: &PublicKey) -> Vec<u8> {
    public_ecdsa.serialize_uncompressed().to_vec()
}

/// public_ECDSA_to_base58: Takes a public key and returns base58 string of DER uncompressed bytes
pub fn public_ecdsa_to_base58(public_ecdsa: &PublicKey) -> String {
    bs58::encode(public_ecdsa_to_bytes(public_ecdsa)).into_string()
}

/// make_identifier: Take public key hex (DER) and return iotics DID identifier string
pub fn make_identifier(public_bytes: Vec<u8>) -> String {
    // TODO: double-check this logic
    let method = 0x05;
    let version = 0x55;
    let pad = 0x59;

    let mut bl2 = VarBlake2b::new(20).unwrap();
    bl2.update(public_bytes);

    let pk_digest = bl2.finalize_boxed().to_vec();

    let mut cl2 = VarBlake2b::new(20).unwrap();
    cl2.update(pk_digest.clone());
    let checksum = cl2.finalize_boxed().to_vec();
    let mut checksum = checksum[..4].to_vec();

    let mut to_encode: Vec<u8> = vec![method, version, pad];
    to_encode.append(&mut pk_digest.clone());
    to_encode.append(&mut checksum);

    format!(
        "{}{}",
        IDENTIFIER_PREFIX,
        bs58::encode(to_encode).into_string()
    )
}

/// compare_identifier_only: Compares two DID Identifiers ignoring name returns bool
pub fn compare_identifier_only(id_a: &String, id_b: &String) -> bool {
    return id_a.split("#").collect::<Vec<&str>>()[0] == id_b.split("#").collect::<Vec<&str>>()[0];
}
