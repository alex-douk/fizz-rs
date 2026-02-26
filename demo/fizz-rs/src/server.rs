use std::fs::File;
use fizz_rs::{CertificatePublic, DelegatedCredentialData, ServerTlsContext, VerificationInfo};
use serde::Deserialize;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

const CREDENTIAL_FILE: &'static str = "/tmp/fizz_server.json";
const PUBLIC_CERTIFICATE_FILE: &'static str = "../fizz-sidecar/fizz.crt";

#[derive(Deserialize)]
struct DelegatedCredential {
    pub signatureScheme: u16,
    pub credentialPEM: String,
}

#[tokio::main]
async fn main() {
    println!("Hello, world!");

    let cert = CertificatePublic::load_from_file(PUBLIC_CERTIFICATE_FILE).unwrap();

    let file = File::open(CREDENTIAL_FILE).unwrap();
    let json: DelegatedCredential = serde_json::from_reader(file).unwrap();
    let dc = DelegatedCredentialData::from_pem(&json.credentialPEM).unwrap();

    let tls = ServerTlsContext::new(cert, dc).unwrap();

    let listener = TcpListener::bind("localhost:8443").await.unwrap();

    println!("Listening!");
    let mut conn = tls.accept(&listener).await.unwrap();

    println!("Accepted!");
    let read = conn.read_i32().await.unwrap();
    println!("Read: {read}");

    // TODO(babman): EOF is not getting sent/read properly.
    let mut my_string = String::new();
    conn.read_to_string(&mut my_string).await.unwrap();
    println!("Received: {}", my_string);
}
