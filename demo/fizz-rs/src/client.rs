use std::fs::File;
use fizz_rs::{ClientTlsContext, VerificationInfo};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

const VERIFICATION_INFO_FILE: &'static str = "/tmp/fizz_client.json";
const PUBLIC_CERTIFICATE_FILE: &'static str = "../fizz-sidecar/fizz.crt";


#[tokio::main]
async fn main() {
    println!("Hello, world!");

    let file = File::open(VERIFICATION_INFO_FILE).unwrap();
    let info: VerificationInfo = serde_json::from_reader(file).unwrap();
    let tls = ClientTlsContext::new(info, PUBLIC_CERTIFICATE_FILE).unwrap();

    let stream = TcpStream::connect("localhost:8443").await.unwrap();
    let mut conn = tls.connect(stream, "localhost").await.unwrap();

    println!("Sending");
    conn.write_i32(25).await.unwrap();
    conn.write_all("Text sent via delegated TLS!".as_bytes()).await.unwrap();
    conn.flush().await.unwrap();
    println!("Sent!");
    conn.shutdown().await.unwrap();
}

