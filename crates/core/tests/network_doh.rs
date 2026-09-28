//! Network-required tests (`--ignored`) of DNS-over-HTTPS resolvers against
//! real providers (the offline answer-parsing/decision tests live in
//! `tests/https_rr.rs`).

#![cfg(feature = "doh")]

use koon_core::*;

#[tokio::test]
#[ignore]
async fn doh_cloudflare() {
    let client = Client::builder(Chrome::latest())
        .doh(koon_core::dns::DohResolver::with_cloudflare().unwrap())
        .build()
        .unwrap();

    let resp = client.get("https://httpbin.org/get").await.unwrap();
    assert_eq!(resp.status, 200);
}

#[tokio::test]
#[ignore]
async fn doh_google() {
    let client = Client::builder(Chrome::latest())
        .doh(koon_core::dns::DohResolver::with_google().unwrap())
        .build()
        .unwrap();

    let resp = client.get("https://httpbin.org/get").await.unwrap();
    assert_eq!(resp.status, 200);
}
