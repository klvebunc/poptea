use io::Write;
use poptea::GeminiClient;
use std::{
    io,
    sync::{Arc, Mutex},
};

fn main() {
    let url = std::env::args().nth(1).expect("please provide gemini url");
    let fs = Arc::new(
        Mutex::new(poptea::FileSystem::new(".poptea".into()))
    );

    let client = poptea::TlsClient::new(fs.clone());
    let res = client.get(&url).expect("failed to make a request");

    io::stdout()
        .write_all(&res.body.unwrap_or_else(|| b"response has no body".to_vec()))
        .expect("failed to write to stdout");

    fs.lock().unwrap().flush_trust_store();
}
