use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Invalid Regex")]
    InvalidRegex(#[from] regex::Error),
    #[error("Invalid Input {0}")]
    InvalidInput(#[from] std::io::Error),
    #[error("Network Error {0}")]
    NetworkError(String),
    #[error("JWT Parse Error")]
    JwtParseError(#[from] jwt_compact::ParseError),
    #[error("JWT Validation Error")]
    JwtValidationError(#[from] jwt_compact::ValidationError),
    #[error("Delegation Exists")]
    DelegationExists,
    #[error("DID Document Error: {0}")]
    DIDDocumentError(String),
}
