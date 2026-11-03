//! Whether koon is up to date: its newest profiles against the browsers' current stable releases,
//! and the Chrome field trials that touch TLS, QUIC or HTTP against the ones last reviewed. The
//! weekly freshness workflow runs these; a failure means a profile update or a review is due.

use koon_core::{Brave, Chrome, Client, Edge, Firefox, Opera, SAFARI_VERSIONS};

async fn json(client: &Client, url: &str) -> serde_json::Value {
    let response = client.get(url).await.unwrap();
    assert_eq!(response.status, 200, "{url}");
    serde_json::from_slice(&response.body).unwrap()
}

/// A dotted version as numbers, for comparing.
fn parts(version: &str) -> Vec<u32> {
    version
        .split('.')
        .map(|part| part.parse().unwrap_or(0))
        .collect()
}

#[tokio::test]
#[ignore = "network"]
async fn the_newest_profiles_are_the_current_stable_releases() {
    let client = Client::new(Chrome::latest()).unwrap();
    let chrome = json(
        &client,
        "https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Windows&num=1",
    )
    .await[0]["version"]
        .as_str()
        .unwrap()
        .to_string();
    let firefox = json(
        &client,
        "https://product-details.mozilla.org/1.0/firefox_versions.json",
    )
    .await["LATEST_FIREFOX_VERSION"]
        .as_str()
        .unwrap()
        .to_string();
    let edge = json(&client, "https://edgeupdates.microsoft.com/api/products")
        .await
        .as_array()
        .unwrap()
        .iter()
        .find(|product| product["Product"] == "Stable")
        .and_then(|product| {
            product["Releases"].as_array()?.iter().find(|release| {
                release["Platform"] == "Windows" && release["Architecture"] == "x64"
            })
        })
        .and_then(|release| release["ProductVersion"].as_str())
        .unwrap()
        .to_string();
    // Safari ships with the OS release, and its profiles follow the OS.
    let macos =
        json(&client, "https://endoflife.date/api/v1/products/macos/").await["result"]["releases"]
            [0]["latest"]["name"]
            .as_str()
            .unwrap()
            .to_string();
    let safari = SAFARI_VERSIONS.last().unwrap().version;
    let opera_archive = client
        .get("https://get.geo.opera.com/pub/opera/desktop/")
        .await
        .unwrap();
    let opera_archive = opera_archive.text();
    let opera = opera_archive
        .split("href=\"")
        .filter_map(|link| link.split_once("/\"").map(|(version, _)| version))
        .filter(|version| version.split('.').all(|part| part.parse::<u32>().is_ok()))
        .max_by_key(|version| parts(version))
        .unwrap()
        .to_string();
    // Brave's profiles go by the Chromium version of its release, as its release title names it.
    let brave = json(
        &client,
        "https://api.github.com/repos/brave/brave-browser/releases/latest",
    )
    .await["name"]
        .as_str()
        .and_then(|name| name.split("Chromium ").nth(1))
        .and_then(|version| version.split(')').next())
        .unwrap()
        .to_string();

    let mut stale = Vec::new();
    for (browser, stable, newest) in [
        ("Chrome", &chrome, Chrome::LATEST_VERSION),
        ("Firefox", &firefox, Firefox::LATEST_VERSION),
        ("Edge", &edge, Edge::LATEST_VERSION),
        ("Opera", &opera, Opera::LATEST_VERSION),
        ("Brave (Chromium)", &brave, Brave::LATEST_VERSION),
    ] {
        if parts(stable)[0] > newest {
            stale.push(format!("{browser} {stable} (koon: {newest})"));
        }
    }
    if parts(&macos)[..2] > parts(safari)[..] {
        stale.push(format!("Safari of macOS {macos} (koon: {safari})"));
    }
    assert!(
        stale.is_empty(),
        "newer than koon's newest profiles: {stale:?}"
    );
}

/// The Chrome field trials on TLS, QUIC and HTTP in the stable seed, without their group
/// suffixes, as last reviewed (2026-11-03, milestone 156).
const REVIEWED_TRIALS: &[&str] = &[
    "ConfigureMinimalQuicHints",
    "ConfigureQuicHints",
    "IgnoreQuicCryptoConfigMemoryPressure",
    "IncreaseHttp3Usage",
    "TryQuicByDefault",
];

/// A trial name without the group parts around it (`ForcedOn_TryQuicByDefault`,
/// `TryQuicByDefaultJ2`, `IncreaseHttp3Usage8`).
fn study(name: &str) -> &str {
    let name = [
        "ForcedOn_",
        "ForcedOff_",
        "EnabledWith",
        "Enabled_",
        "Disabled_",
    ]
    .iter()
    .find_map(|prefix| name.strip_prefix(prefix))
    .unwrap_or(name);
    let tail = name
        .bytes()
        .rev()
        .take_while(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
        .count();
    if (1..=2).contains(&tail) {
        let stem = &name[..name.len() - tail];
        stem.strip_suffix('J').unwrap_or(stem)
    } else {
        name
    }
}

#[tokio::test]
#[ignore = "network"]
async fn chromes_network_field_trials_are_the_reviewed_ones() {
    let client = Client::new(Chrome::latest()).unwrap();
    let url = format!(
        "https://clientservices.googleapis.com/chrome-variations/seed?osname=win&channel=stable&milestone={}",
        Chrome::LATEST_VERSION
    );
    let seed = client.get(&url).await.unwrap().body;
    const TOPICS: &[&str] = &[
        "TLS",
        "Tls",
        "Ssl",
        "SSL",
        "Quic",
        "QUIC",
        "Http3",
        "HTTP3",
        "Http2",
        "HTTP2",
        "Ech",
        "ECH",
        "Kyber",
        "MLKEM",
        "PostQuantum",
        "Padding",
        "TrustAnchor",
        "Alps",
        "ALPS",
    ];
    // The seed is a protobuf; its study, group and feature names are plain strings in it.
    let mut seen: Vec<String> = seed
        .split(|b| !(b.is_ascii_alphanumeric() || *b == b'_'))
        .filter(|word| word.len() >= 6 && word[0].is_ascii_alphabetic())
        .map(|word| String::from_utf8_lossy(word).into_owned())
        .filter(|name| TOPICS.iter().any(|topic| name.contains(topic)))
        .map(|name| study(&name).to_string())
        .collect();
    seen.sort();
    seen.dedup();
    let reviewed: Vec<String> = REVIEWED_TRIALS.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        seen, reviewed,
        "Chrome's network trials changed: review them and the profiles"
    );
}
