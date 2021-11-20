use std::sync::Arc;
use io::{Read, Write};
use std::io;

fn main() {
    let root_store = rustls::RootCertStore::empty();
    let mut config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.dangerous()
        .set_certificate_verifier(Arc::new(NoCertificateVerification{}));
    let arc = std::sync::Arc::new(config);

    let mut sess = rustls::ClientConnection::new(arc, "transjovian.org".try_into().unwrap()).unwrap();
    let mut sock = std::net::TcpStream::connect("transjovian.org:1965").unwrap();
    let mut stream = rustls::Stream::new(&mut sess, &mut sock);

    stream.write_all(b"gemini://transjovian.org/oracle/\r\n").unwrap();
    let mut plaintext = Vec::new();
    stream.read_to_end(&mut plaintext).unwrap();
    io::stdout().write_all(&plaintext).unwrap();
}

pub struct NoCertificateVerification {}

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

