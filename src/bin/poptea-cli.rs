use io::Write;
use poptea::GeminiClient;
use std::{io, sync::Arc};

fn main() {
    let url = std::env::args().nth(1).expect("please provide gemini url");
    let fs = poptea::FileSystem::new("~/.poptea".into());

    let client = poptea::TlsClient::new(Arc::new(fs));
    let res = client.get(&url).expect("failed to make a request");

    io::stdout()
        .write_all(&res.body.unwrap_or_else(|| b"response has no body".to_vec()))
        .expect("failed to write to stdout");
}
