//! Opt-in TLS key logging through `SSLKEYLOGFILE` (offline). The variable
//! is read once per process, so this file holds a single test.

mod common;

use koon_core::{Chrome, Client};

#[tokio::test]
async fn sslkeylogfile_receives_the_secrets_of_every_handshake() {
    // Removed with the log file at the end of the test, also on a panic.
    let dir = common::temp_dir("keylog");
    let path = dir.path().join("keys.log");
    // SAFETY: set before the first TLS context of this process exists and
    // before any other thread reads the environment.
    unsafe { std::env::set_var("SSLKEYLOGFILE", &path) };

    let port = common::plain_server("127.0.0.1").await;
    let mut profile = Chrome::latest();
    profile.tls.danger_accept_invalid_certs = true;
    let client = Client::new(profile).unwrap();
    let url = format!("https://127.0.0.1:{port}/");
    assert_eq!(client.get(&url).await.unwrap().status, 200);
    client.close();
    assert_eq!(client.get(&url).await.unwrap().status, 200);

    let log = std::fs::read_to_string(&path).expect("key log written");
    // NSS key log format: label, client random, secret; one line each.
    for line in log.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        assert_eq!(fields.len(), 3, "{line}");
        assert_eq!(fields[1].len(), 64, "{line}");
        assert!(
            fields[1..]
                .iter()
                .all(|f| f.bytes().all(|b| b.is_ascii_hexdigit()))
        );
    }
    let count = |label: &str| log.lines().filter(|l| l.starts_with(label)).count();
    // Two TLS 1.3 handshakes.
    assert_eq!(count("CLIENT_HANDSHAKE_TRAFFIC_SECRET "), 2, "{log}");
    assert_eq!(count("SERVER_HANDSHAKE_TRAFFIC_SECRET "), 2);
    assert_eq!(count("CLIENT_TRAFFIC_SECRET_0 "), 2);
    assert_eq!(count("SERVER_TRAFFIC_SECRET_0 "), 2);
}
