//! Network-required tests (`--ignored`) of certificate chain verification
//! against real sites.

use koon_core::*;

/// Chromium 152+ advertise the trust anchor IDs of the Chrome Root Store.
/// Google's QUIC frontend answers them with the leaf alone: its issuer WE2
/// is an intermediate the store trusts as an anchor, so the connection only
/// verifies against what Chrome trusts (Mozilla's roots: "unknown CA").
#[tokio::test]
#[ignore]
async fn chrome_verifies_quic_chains_shortened_for_its_trust_anchor_ids() {
    let profiles = [
        ("Chrome 152", Chrome::version(152, Os::Windows).unwrap()),
        ("Chrome 153", Chrome::version(153, Os::Windows).unwrap()),
        ("Chrome 154", Chrome::version(154, Os::Windows).unwrap()),
        ("Opera 136", Opera::version(136, Os::Windows).unwrap()),
    ];
    for (name, profile) in profiles {
        let client = Client::new(profile).unwrap();
        let url = "https://www.google.com/generate_204";
        // The DNS HTTPS record's `alpn` (`https_rr`, on by default) already
        // gets this to QUIC on the very first connection; no need to prime
        // Alt-Svc with an h2 request first, as when this test needed one.
        let quic = client
            .get(url)
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!((quic.status, quic.version.as_str()), (204, "h3"), "{name}");
    }
}

/// Every profile verifies the chains of major sites: Google Trust Services,
/// Let's Encrypt (incl. its 2026 hierarchy), Sectigo, Amazon, DigiCert.
#[tokio::test]
#[ignore]
async fn root_stores_verify_major_sites() {
    let urls = [
        "https://www.google.com/generate_204",
        "https://www.cloudflare.com/",
        "https://letsencrypt.org/",
        "https://www.wikipedia.org/",
        "https://github.com/",
        "https://www.amazon.com/",
        "https://www.digicert.com/",
    ];
    let profiles = [
        ("Chrome", Chrome::latest()),
        ("Chrome 152", Chrome::version(152, Os::Windows).unwrap()),
        ("Firefox", Firefox::latest()),
        ("Edge", Edge::latest()),
    ];
    for (name, profile) in profiles {
        let client = Client::new(profile).unwrap();
        for url in urls {
            let resp = client
                .get(url)
                .await
                .unwrap_or_else(|e| panic!("{name} {url}: {e}"));
            assert!(resp.status < 500, "{name} {url}: {}", resp.status);
        }
    }
}

/// Sites of root CAs whose chain ends at a root Mozilla keeps and the Chrome
/// Root Store dropped: verifying against the Chrome Root Store alone
/// rejects them.
const MOZILLA_ONLY_ROOTED: &[(&str, &str)] = &[
    (
        "https://global-root-ca.chain-demos.digicert.com/",
        "DigiCert Global Root CA",
    ),
    (
        "https://assured-id-root-ca.chain-demos.digicert.com/",
        "DigiCert Assured ID Root CA",
    ),
    (
        "https://comodocertificationauthority-ev.comodoca.com/",
        "COMODO Certification Authority",
    ),
];

/// Every profile verifies against one store: Mozilla's roots and the Chrome
/// anchors. A chain that ends at a root Chrome dropped but Mozilla keeps
/// verifies with the Chrome profile too.
#[tokio::test]
#[ignore]
async fn chrome_verifies_chains_to_roots_only_mozilla_keeps() {
    for (url, root) in MOZILLA_ONLY_ROOTED {
        for profile in [Chrome::latest(), Opera::latest()] {
            let client = Client::new(profile).unwrap();
            let resp = client
                .get(url)
                .await
                .unwrap_or_else(|e| panic!("{url} (chain to {root}): {e}"));
            assert!(resp.status < 500, "{url}: {}", resp.status);
        }
    }
}
