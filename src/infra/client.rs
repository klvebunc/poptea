use std::fs::File;
use url::Url;

use io::{Read, Write};
use std::str::FromStr;
use std::sync::Arc;
use std::{io, io::BufRead, convert::Into};
use x509_parser::prelude::*;

use crate::{GemResponse, GemStatus, GeminiClient, PopResult, TrustStore, VerifyStatus};

fn fingerprint(cert: &rustls::Certificate) -> PopResult<(String, String)> {
    let (_, pk) = X509Certificate::from_der(cert.as_ref()).unwrap();
    let res = pk.public_key().subject_public_key.as_ref();

    Ok((pk.subject().to_string(), format!("{:?}", res)))
}

struct TofuVerification {
    store: Arc<dyn TrustStore>,
}

impl rustls::client::ServerCertVerifier for TofuVerification {
    fn verify_server_cert(
        &self,
        cert: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        let path = "cert.der";
        let mut file = File::create(path).unwrap();
        file.write_all(cert.as_ref()).unwrap();
        let (addr, fingerprint) = fingerprint(cert).unwrap();
        match self.store.verify(&addr, fingerprint) {
            Ok(VerifyStatus::Trusted) => Ok(rustls::client::ServerCertVerified::assertion()),
            Ok(VerifyStatus::Untrusted) => {
                Err(rustls::Error::InvalidCertificateData("untrusted".into()))
            }
            Err(_) => Err(rustls::Error::General("storage error".into())),
        }
    }
}

pub struct TlsClient {
    store: Arc<dyn TrustStore>,
}

impl TlsClient {
    pub fn new(store: Arc<dyn TrustStore>) -> Self {
        Self { store }
    }

    pub fn get_plain(&self, url: &str) -> PopResult<Vec<u8>> {
        let url = Url::parse(url).map_err(|_| crate::PopError::Local("failed to parse".into()))?;
        let root_store = rustls::RootCertStore::empty();

        let mut plaintext = vec![];
        let host = url
            .host_str()
            .ok_or_else(|| crate::PopError::Local("host is missing".into()))?;
        let addr = format!("{}:{:?}", host, url.port().unwrap_or(1965));
        let req = format!("{}\r\n", url);

        let mut config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(TofuVerification {
                store: self.store.clone(),
            }));
        let arc = std::sync::Arc::new(config);

        let mut sess = rustls::ClientConnection::new(arc, host.try_into().unwrap()).unwrap();
        let mut sock = std::net::TcpStream::connect(addr).unwrap();
        let mut stream = rustls::Stream::new(&mut sess, &mut sock);
        stream.write_all(req.as_bytes()).unwrap();
        stream.read_to_end(&mut plaintext).unwrap();

        Ok(plaintext)
    }
}

impl GeminiClient for TlsClient {
    fn get(&self, url: &str) -> PopResult<GemResponse> {
        let plaintext = self.get_plain(url)?;
        let header = plaintext.lines().next().unwrap().unwrap();
        let body = plaintext[header.len()..].to_vec();

        let (status, meta) = header
            .split_once(" ")
            .map(|(s, m)| (GemStatus::from_str(s), m.into()))
            .ok_or_else(|| crate::PopError::Remote("invalid header".into()))?;

        let body = match &body.len() {
            0 => None,
            _ => Some(body),
        };

        Ok(GemResponse {
            status: status?,
            meta,
            body,
        })
    }
}
