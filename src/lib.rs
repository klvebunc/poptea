use std::fmt;
use std::str::FromStr;

mod infra;
pub use infra::*;

#[derive(Debug)]
pub enum GemStatus {
    Input,
    SensitiveInput,
    Success,
    RedirectTemporary,
    RedirectPermanent,
    TemporaryFailure,
    ServerUnavailable,
    CgiError,
    ProxyError,
    SlowDown,
    PermanentFailure,
    NotFound,
    Gone,
    ProxyRequestRefused,
    BadRequest,
    ClientCertificateRequired,
    CertificateNotAuthorized,
    CertificateNotValid,
}

#[derive(Debug)]
pub enum GemMimeType {
    GeminiText,
}

#[derive(Debug)]
pub struct GemResponse {
    pub status: GemStatus,
    pub meta: String,
    pub body: Option<Vec<u8>>,
}

impl FromStr for GemStatus {
    type Err = PopError;

    fn from_str(input: &str) -> Result<GemStatus, Self::Err> {
        match input {
            "20" => Ok(GemStatus::Success),
            _ => Err(PopError::Local("unimplemented status code".into())),
        }
    }
}

pub trait GeminiClient {
    fn get(&self, url: &str) -> PopResult<GemResponse>;
}

#[derive(Debug)]
pub enum PopError {
    Local(String),
    Remote(String),
}

impl fmt::Display for PopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PopError::Local(e) => write!(f, "{}", e.to_string()),
            PopError::Remote(e) => write!(f, "{}", e.to_string()),
        }
    }
}

pub type PopResult<T> = Result<T, PopError>;

pub trait TrustStore: Send + Sync {
    fn verify(&mut self, addr: &str, fingerprint: String) -> PopResult<VerifyStatus>;
}

pub enum VerifyStatus {
    Trusted,
    Untrusted,
}
