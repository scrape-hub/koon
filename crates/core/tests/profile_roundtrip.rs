//! Offline unit tests: profile JSON roundtrips, profile invariants,
//! `ClientBuilder`, `Multipart`, error display, and the option parsers the
//! bindings share.

use koon_core::*;
use std::time::Duration;

// ============================================================
// Profile JSON roundtrip
// ============================================================

/// A `BrowserProfile` survives JSON serialization -> deserialization:
/// serializing the restored profile must give the identical JSON, so every
/// serialized field (extension order, key shares, trust anchors, H2/QUIC
/// settings, headers) is covered.
fn assert_profile_roundtrips(name: &str, profile: &BrowserProfile) {
    let json = profile
        .to_json_pretty()
        .unwrap_or_else(|e| panic!("{name}: serialize failed: {e}"));
    let restored = BrowserProfile::from_json(&json)
        .unwrap_or_else(|e| panic!("{name}: deserialize failed: {e}"));
    let again = restored
        .to_json_pretty()
        .unwrap_or_else(|e| panic!("{name}: re-serialize failed: {e}"));
    assert_eq!(json, again, "{name}: JSON changed in a roundtrip");
}

#[test]
fn profile_json_roundtrip_per_browser() {
    assert_profile_roundtrips("chrome154", &Chrome::version(154, Os::Windows).unwrap());
    assert_profile_roundtrips("chrome140", &Chrome::version(140, Os::Windows).unwrap());
    assert_profile_roundtrips("firefox156", &Firefox::version(156, Os::Windows).unwrap());
    assert_profile_roundtrips("firefox146", &Firefox::version(146, Os::Windows).unwrap());
    assert_profile_roundtrips("safari26.6", &Safari::version("26.6", Os::MacOS).unwrap());
    // The private QUIC transport parameter, no resumption, no Alt-Svc.
    assert_profile_roundtrips("safari18.2", &Safari::version("18.2", Os::MacOS).unwrap());
    assert_profile_roundtrips("safari18.4", &Safari::version("18.4", Os::Ios).unwrap());
    assert_profile_roundtrips("edge151", &Edge::version(151, Os::Windows).unwrap());
    assert_profile_roundtrips("opera134", &Opera::version(134, Os::Windows).unwrap());
    assert_profile_roundtrips("opera136", &Opera::version(136, Os::Windows).unwrap());
    assert_profile_roundtrips("okhttp5", &OkHttp::latest());
}

/// `firefox` as koon 0.8.1 exported it.
const FIREFOX_0_8_JSON: &str = r#"{
  "tls": {
    "cipher_list": "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA",
    "curves": "X25519MLKEM768:X25519:P-256:P-384:P-521:ffdhe2048:ffdhe3072",
    "sigalgs": "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512:ecdsa_sha1:rsa_pkcs1_sha1",
    "alpn": ["h2", "http/1.1"],
    "alps": null,
    "alps_use_new_codepoint": false,
    "min_version": "tls12",
    "max_version": "tls13",
    "grease": false,
    "ech_grease": true,
    "permute_extensions": false,
    "extension_order": [23, 65281, 10, 11, 35, 16, 5, 34, 18, 51, 43, 13, 45, 28, 27, 65037],
    "ocsp_stapling": true,
    "signed_cert_timestamps": true,
    "cert_compression": ["zlib", "brotli", "zstd"],
    "pre_shared_key": true,
    "session_ticket": true,
    "key_shares_limit": 3,
    "delegated_credentials": "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:ecdsa_sha1",
    "record_size_limit": 16385,
    "preserve_tls13_cipher_order": true,
    "danger_accept_invalid_certs": false
  },
  "http2": {
    "header_table_size": 65536,
    "enable_push": false,
    "max_concurrent_streams": null,
    "initial_window_size": 131072,
    "max_frame_size": 16384,
    "max_header_list_size": null,
    "initial_conn_window_size": 12582912,
    "pseudo_header_order": ["method", "path", "authority", "scheme"],
    "settings_order": ["header_table_size", "enable_push", "initial_window_size", "max_frame_size"],
    "headers_stream_dependency": null,
    "priorities": [],
    "no_rfc7540_priorities": null,
    "enable_connect_protocol": null
  },
  "quic": {
    "initial_max_data": 12582912,
    "initial_max_stream_data_bidi_local": 1048576,
    "initial_max_stream_data_bidi_remote": 1048576,
    "initial_max_stream_data_uni": 1048576,
    "initial_max_streams_bidi": 16,
    "initial_max_streams_uni": 16,
    "max_idle_timeout_ms": 30000,
    "max_udp_payload_size": 1472,
    "ack_delay_exponent": 3,
    "max_ack_delay_ms": 25,
    "active_connection_id_limit": 2,
    "disable_active_migration": false,
    "grease_quic_bit": false,
    "qpack_max_table_capacity": 0,
    "qpack_blocked_streams": 0,
    "max_field_section_size": null
  },
  "headers": [
    ["te", "trailers"],
    ["user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:154.0) Gecko/20100101 Firefox/154.0"],
    ["accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"],
    ["accept-language", "en-US,en;q=0.5"],
    ["accept-encoding", "gzip, deflate, br, zstd"],
    ["upgrade-insecure-requests", "1"],
    ["sec-fetch-dest", "document"],
    ["sec-fetch-mode", "navigate"],
    ["sec-fetch-site", "none"],
    ["sec-fetch-user", "?1"],
    ["priority", "u=0, i"]
  ]
}"#;

/// Profile JSON of koon 0.8 fails to load, and the error names what the
/// current form does not have.
#[test]
fn profile_json_of_koon_0_8_is_rejected() {
    let err = BrowserProfile::from_json(FIREFOX_0_8_JSON).unwrap_err();
    assert!(
        err.to_string()
            .contains("unknown field `alps_use_new_codepoint`"),
        "{err}"
    );

    // Each field and form of 0.8, in an otherwise current profile.
    let current = serde_json::to_value(Firefox::latest()).unwrap();
    let cases = [
        (
            "tls",
            "pre_shared_key",
            true.into(),
            "unknown field `pre_shared_key`",
        ),
        (
            "tls",
            "alps_use_new_codepoint",
            true.into(),
            "unknown field `alps_use_new_codepoint`",
        ),
        (
            "tls",
            "permute_extensions",
            true.into(),
            "unknown field `permute_extensions`",
        ),
        (
            "tls",
            "root_store",
            serde_json::json!({ "chrome": 39 }),
            "unknown field `root_store`",
        ),
        ("tls", "alps", "h2".into(), "unknown variant `h2`"),
        // serde_json names no field here, only the position.
        ("tls", "ech_grease", true.into(), "expected value at line 1"),
        (
            "tls",
            "extension_order",
            serde_json::json!([0, 23]),
            "expected value at line 1",
        ),
        (
            "quic",
            "ack_delay_exponent",
            3.into(),
            "unknown field `ack_delay_exponent`",
        ),
        (
            "quic",
            "disable_active_migration",
            false.into(),
            "unknown field `disable_active_migration`",
        ),
        (
            "quic",
            "grease_quic_bit",
            false.into(),
            "unknown field `grease_quic_bit`",
        ),
    ];
    for (section, field, value, expected) in cases {
        let mut json = current.clone();
        json[section][field] = value;
        let err = BrowserProfile::from_json(&json.to_string()).unwrap_err();
        assert!(
            err.to_string().contains(expected),
            "{section}.{field}: {err}"
        );
    }

    let mut json = current;
    json["quic"].as_object_mut().unwrap().remove("stack");
    let err = BrowserProfile::from_json(&json.to_string()).unwrap_err();
    assert!(err.to_string().contains("missing field `stack`"), "{err}");
}

/// Every built-in profile name, from the core's profile list.
fn all_profile_names() -> Vec<String> {
    BrowserProfile::names().map(|p| p.name).collect()
}

#[test]
fn profile_json_roundtrip_all_browsers() {
    let names = all_profile_names();
    assert!(
        names.len() > 200,
        "expected the full profile matrix, got {}",
        names.len()
    );

    for name in &names {
        let profile =
            BrowserProfile::resolve(name).unwrap_or_else(|e| panic!("resolve {name}: {e}"));
        assert_profile_roundtrips(name, &profile);
    }
}

#[test]
fn profile_json_never_carries_insecure_flag() {
    let mut profile = Chrome::latest();
    profile.tls.danger_accept_invalid_certs = true;
    let json = profile.to_json_pretty().unwrap();
    assert!(!json.contains("danger_accept_invalid_certs"));
    let injected = json.replacen(
        "\"cipher_list\"",
        "\"danger_accept_invalid_certs\": true,\n    \"cipher_list\"",
        1,
    );
    let err = BrowserProfile::from_json(&injected).unwrap_err();
    assert!(
        err.to_string()
            .contains("unknown field `danger_accept_invalid_certs`"),
        "{err}"
    );
}

// ============================================================
// Profile invariants
// ============================================================

#[test]
fn latest_profiles_exist() {
    let _ = Chrome::latest();
    let _ = Firefox::latest();
    let _ = Safari::latest();
    let _ = Edge::latest();
    let _ = Opera::latest();
}

#[test]
fn chrome_profiles_have_quic() {
    assert!(
        Chrome::version(145, Os::Windows).unwrap().quic.is_some(),
        "Chrome should have QUIC config"
    );
}

#[test]
fn safari_profiles_follow_alt_svc_per_release() {
    // Every Safari profile has Apple's QUIC stack; macOS 15.1 and 15.2 and
    // iOS 18.0 to 18.2 ignore Alt-Svc and stay on HTTP/2.
    for (version, os, alt_svc) in [
        ("17.0", Os::MacOS, true),
        ("18.1", Os::MacOS, false),
        ("18.2", Os::MacOS, false),
        ("18.2", Os::Ios, false),
        ("18.3", Os::Ios, true),
        ("18.4", Os::MacOS, true),
        ("27.0", Os::MacOS, true),
    ] {
        let quic = Safari::version(version, os).unwrap().quic;
        assert_eq!(
            quic.map(|q| q.alt_svc),
            Some(alt_svc),
            "Safari {version} {os}"
        );
    }
}

#[test]
fn firefox_tls13_cipher_order() {
    let profile = Firefox::version(147, Os::Windows).unwrap();
    assert!(
        profile.tls.preserve_tls13_cipher_order,
        "Firefox should preserve TLS 1.3 cipher order"
    );
    // Firefox/NSS order: AES_128 -> CHACHA20 -> AES_256
    assert!(
        profile.tls.cipher_list.starts_with(
            "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384"
        ),
        "Firefox cipher order should be AES_128->CHACHA20->AES_256"
    );
}

#[test]
fn firefox_record_size_limit() {
    let profile = Firefox::version(147, Os::Windows).unwrap();
    assert_eq!(
        profile.tls.record_size_limit,
        Some(16385),
        "Firefox should have record_size_limit=16385"
    );
}

#[test]
fn safari_psk_key_exchange_modes() {
    let profile = Safari::version("18.3", Os::MacOS).unwrap();
    assert!(
        profile.tls.psk_key_exchange_modes,
        "Safari sends psk_key_exchange_modes"
    );
}

#[test]
fn chrome_grease_and_permutation() {
    let profile = Chrome::version(145, Os::Windows).unwrap();
    assert!(profile.tls.grease, "Chrome should use GREASE");
    assert_eq!(
        profile.tls.extension_order,
        koon_core::tls::ExtensionOrder::Permuted,
        "Chrome should permute extensions"
    );
    assert_eq!(
        profile.tls.ech_grease,
        koon_core::tls::EchGrease::BoringSsl,
        "Chrome should use ECH GREASE"
    );
}

#[test]
fn safari_h2_window_sizes() {
    // The stream window of the OS network stack (captured): 4 MB on macOS
    // 14 and 15.0 (and the older releases), 2 MB on iOS 17 and from macOS
    // 15.1 on.
    let window = |version, os| {
        Safari::version(version, os)
            .unwrap()
            .http2
            .initial_window_size
    };
    assert_eq!(window("15.6", Os::MacOS), 4194304);
    assert_eq!(window("17.0", Os::MacOS), 4194304);
    assert_eq!(window("17.0", Os::Ios), 2097152);
    assert_eq!(window("18.0", Os::MacOS), 4194304);
    assert_eq!(window("18.1", Os::MacOS), 2097152);
    assert_eq!(window("18.3", Os::MacOS), 2097152);
    assert_eq!(window("27.0", Os::MacOS), 2097152);
}

// ============================================================
// Client builder
// ============================================================

#[test]
fn client_builder_default() {
    let client = Client::new(Chrome::latest());
    assert!(client.is_ok(), "Client::new should succeed");
}

#[test]
fn client_builder_options() {
    let result = Client::builder(Firefox::latest())
        .follow_redirects(false)
        .max_redirects(5)
        .timeout(Duration::from_secs(10))
        .cookie_jar(false)
        .session_resumption(false)
        .build();
    assert!(result.is_ok(), "ClientBuilder with options should succeed");
}

#[test]
fn client_builder_invalid_proxy() {
    let result = Client::builder(Chrome::latest()).proxy("not-a-valid-url");
    assert!(result.is_err(), "Invalid proxy URL should error");
}

#[test]
fn client_profile_access() {
    let profile = Chrome::version(145, Os::Windows).unwrap();
    let client = Client::new(profile.clone()).unwrap();
    assert_eq!(
        client.profile().tls.cipher_list,
        profile.tls.cipher_list,
        "Client should expose its profile"
    );
}

// ============================================================
// Multipart builder
// ============================================================

#[test]
fn multipart_builder() {
    let multipart = Multipart::new()
        .text("field1", "value1")
        .text("field2", "value2")
        .file("upload", "test.txt", "text/plain", b"hello world".to_vec());

    let (body, content_type) = multipart.build();
    assert!(
        content_type.starts_with("multipart/form-data; boundary="),
        "Content-Type should include boundary"
    );
    assert!(!body.is_empty(), "Body should not be empty");

    let body_str = String::from_utf8_lossy(&body);
    assert!(body_str.contains("field1"), "Body should contain field1");
    assert!(body_str.contains("value1"), "Body should contain value1");
    assert!(
        body_str.contains("test.txt"),
        "Body should contain filename"
    );
    assert!(
        body_str.contains("hello world"),
        "Body should contain file data"
    );
}

// ============================================================
// Error types
// ============================================================

#[test]
fn error_display() {
    let err = Error::ConnectionFailed("test error".into(), None);
    assert!(
        format!("{err}").contains("test error"),
        "Error should display message"
    );
}

// ============================================================
// Option parsers shared by the bindings
// ============================================================

fn invalid_argument<T: std::fmt::Debug>(result: Result<T, Error>) -> String {
    let err = result.unwrap_err();
    assert_eq!(err.code(), "INVALID_ARGUMENT");
    err.to_string()
}

#[test]
fn option_parsers() {
    assert_eq!(parse_method("patch").unwrap(), http::Method::PATCH);
    assert_eq!(parse_method("PROPFIND").unwrap().as_str(), "PROPFIND");
    assert!(invalid_argument(parse_method("GE T")).contains("GE T"));

    assert_eq!("4".parse::<IpVersion>().unwrap(), IpVersion::V4);
    assert_eq!("IPv6".parse::<IpVersion>().unwrap(), IpVersion::V6);
    assert_eq!(IpVersion::try_from(6u8).unwrap(), IpVersion::V6);
    invalid_argument(IpVersion::try_from(5u8));
    invalid_argument("v5".parse::<IpVersion>());

    assert_eq!(
        "Passthrough".parse::<HeaderMode>().unwrap(),
        HeaderMode::Passthrough
    );
    assert_eq!(
        "impersonate".parse::<HeaderMode>().unwrap(),
        HeaderMode::Impersonate
    );
    invalid_argument("mirror".parse::<HeaderMode>());

    assert_eq!("macos".parse::<Os>().unwrap(), Os::MacOS);
    invalid_argument("beos".parse::<Os>());
    assert!(
        invalid_argument(BrowserProfile::resolve("chrome152-ios"))
            .contains("Chrome is not available on ios")
    );
}

#[cfg(feature = "doh")]
#[test]
fn doh_provider_names() {
    use koon_core::dns::DohConfig;
    let config: DohConfig = "Cloudflare".parse().unwrap();
    assert_eq!(config.server_hostname, "cloudflare-dns.com");
    assert_eq!(config.server_ip.to_string(), "1.1.1.1");
    let config: DohConfig = "google".parse().unwrap();
    assert_eq!(config.server_hostname, "dns.google");
    assert!(invalid_argument("quad9".parse::<DohConfig>()).contains("quad9"));
}

// ============================================================
// Cookie jar serialization
// ============================================================

#[test]
fn cookie_jar_json_roundtrip() {
    let url: http::Uri = "https://example.com/path".parse().unwrap();
    let mut jar = CookieJar::new();
    jar.store_from_response(
        &url,
        &[
            ("set-cookie".into(), "name=value; Path=/; Secure".into()),
            (
                "set-cookie".into(),
                "session=abc123; Path=/; HttpOnly".into(),
            ),
        ],
    );

    let json = jar.to_json().unwrap();
    assert!(json.contains("name"), "JSON should contain cookie name");

    let jar2 = CookieJar::from_json(&json).unwrap();

    let cookies = jar2.cookie_header(&url);
    assert!(
        cookies.is_some(),
        "Restored jar should have cookies for example.com"
    );
    let header = cookies.unwrap();
    assert!(header.contains("name=value"), "Should contain name=value");
    assert!(
        header.contains("session=abc123"),
        "Should contain session=abc123"
    );
}
