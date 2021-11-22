use io::Write;
use poptea::GeminiClient;
use std::{
    io,
    sync::{Arc, Mutex},
};

fn main() {
    let url = std::env::args().nth(1).expect("please provide gemini url");
    /* To use file as a trust store uncomment the code bellow */
    // let fs = Arc::new(Mutex::new(
    //     poptea::FileSystem::new(".poptea".into()).expect("failed to init file storage"),
    // ));

    let no_ts = poptea::NoTrustStore::default();
    let ts = Arc::new(Mutex::new(no_ts));

    let client = poptea::TlsClient::new(ts.clone());
    let res = client.get(&url).expect("failed to make a request");

    io::stdout()
        .write_all(&res.body.unwrap_or_else(|| b"response has no body".to_vec()))
        .expect("failed to write to stdout");

    // fs.lock()
    //     .expect("filesystem mutex deadlock")
    //     .flush_trust_store()
    //     .expect("failed to persist known hosts");
}
