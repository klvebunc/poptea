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

enum GemError {
    Local(String),
    Remote(String),
}

trait GeminiClient {
    fn get(&self, url: &str) -> Result<GemResponse, GemError>;
}

