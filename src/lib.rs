mod infra;

enum GemStatus {
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

enum GemMimeType {
    GeminiText,
}

struct GemResponse {
    status: GemStatus,
    meta: Option<String>,
    body: Option<String>,
}

trait GeminiClient {
    fn get(&self, url: &str) -> PopResult<GemResponse>;
}

enum PopError {
    Local(String),
    Remote(String),
}

pub type PopResult<T> = Result<T, PopError>;
