use std::net::TcpStream;

use io::{Read, Write};
use std::io;
use std::sync::Arc;
use rustls::ClientConnection;

use crate::{PopResult, GemResponse, GeminiClient};

struct NoCertificateVerification {}

impl rustls::client::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

struct TlsClient {
    socket: TcpStream,
    closing: bool,
    clean_closure: bool,
    tls_conn: rustls::ClientConnection,
}

impl TlsClient {
    fn new(
        sock: TcpStream,
        server_name: rustls::ServerName,
        cfg: Arc<rustls::ClientConfig>,
    ) -> Self {
        Self {
            socket: sock,
            closing: false,
            clean_closure: false,
            tls_conn: ClientConnection::new(cfg, server_name).unwrap(),
        }
    }

    fn get_stream(&self, url: &str) -> PopResult<rustls::Stream<ClientConnection, TcpStream>> {
        let root_store = rustls::RootCertStore::empty();
        let mut config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoCertificateVerification {}));
        let arc = std::sync::Arc::new(config);

        let mut sess =
            rustls::ClientConnection::new(arc, "transjovian.org".try_into().unwrap()).unwrap();
        let mut sock = std::net::TcpStream::connect("transjovian.org:1965").unwrap();
        let mut stream = rustls::Stream::new(&mut sess, &mut sock);
        Ok(stream)
    }
}

impl GeminiClient for TlsClient {
    fn get(&self, url: &str) -> PopResult<GemResponse> {
        unimplemented!()
    }
}
