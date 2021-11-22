use crate::{PopResult, TrustStore, VerifyStatus};
use std::fs::{create_dir, OpenOptions};
use std::io::{self, BufRead};
use std::io::prelude::*;
use std::io::LineWriter;
use std::collections::HashMap;

pub struct FileSystem {
    trust_store: HashMap<String, String>,
    pop_dir: String,
}

impl FileSystem {
    pub fn new(pop_dir: String) -> Self {
        let mut trust_store = HashMap::new();
        Self::load_trust_store(&pop_dir, &mut trust_store);

        Self { 
            trust_store,
            pop_dir,
        }
    }

    fn load_trust_store(pop_dir: &str, store: &mut HashMap<String, String>) {
        let trust_path = format!("{}/known_hosts", pop_dir);
        let file = OpenOptions::new()
            .write(true)
            .read(true)
            .open(trust_path).unwrap();

        for line in io::BufReader::new(file).lines() {
            if let Ok(kh) = line {
                let (host, fingerprint) = kh
                    .split_once(" ").unwrap();

                store.insert(host.to_string(), fingerprint.to_string());
            }
        }
    }

    pub fn flush_trust_store(&self) {
        let trust_path = format!("{}/known_hosts", self.pop_dir);
        let file = OpenOptions::new()
            .write(true)
            .read(true)
            .open(trust_path).unwrap();
        let mut file = LineWriter::new(file);

        for (h, f) in &self.trust_store {
            file.write_all(format!("{} {}\n", h, f).as_bytes()).unwrap();
        };

        file.flush().unwrap();
    }
}

impl TrustStore for FileSystem {
    fn verify(&mut self, addr: &str, fingerprint: String) -> PopResult<VerifyStatus> {
        let remote_f = fingerprint.clone();
        let f = &self
            .trust_store
            .entry(addr.to_string())
            .or_insert(fingerprint)
            .to_string();

        if remote_f.eq(f) {
            Ok(VerifyStatus::Trusted)
        } else {
            Ok(VerifyStatus::Untrusted)
        }
    }
}
