use crate::{PopResult, TrustStore, VerifyStatus};

pub struct FileSystem {}

impl FileSystem {
    pub fn new(pop_dir: String) -> Self {
        Self {}
    }
}

impl TrustStore for FileSystem {
    fn verify(&self, addr: &str, fingerprint: String) -> PopResult<VerifyStatus> {
        println!("{} {}", addr, fingerprint);
        Ok(VerifyStatus::Untrusted)
    }
}
