//! Runs `koon verify` against a local mock of the fingerprint services (no
//! network): the human-readable and JSON output and the exit codes.

use std::process::{Command, Output};

mod common;
use common::{closed_port, text};

/// What real Chrome 150-154 shows browserleaks (the reference of
/// `chrome154-windows`), plus the JA3 of one connection.
const CHROME_JSON: &str = r#"{
  "user_agent": "Mozilla/5.0",
  "ja4": "t13d1517h2_8daaf6152771_cb7bf5808d99",
  "ja3_hash": "9ca2569240e510d5cde6f8e7a0c3bd38",
  "ja3n_hash": "bd4930bd9b000ee684830e44bab76fdf",
  "akamai_hash": "52d84b11737d980aef856699f885ca86",
  "akamai_text": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
}"#;

/// The same in tls.peet.ws's format, which has no JA3N.
const CHROME_PEET_JSON: &str = r#"{
  "http_version": "h2",
  "tls": {"ja3_hash": "9ca2569240e510d5cde6f8e7a0c3bd38", "ja4": "t13d1517h2_8daaf6152771_cb7bf5808d99"},
  "http2": {
    "akamai_fingerprint": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    "akamai_fingerprint_hash": "52d84b11737d980aef856699f885ca86"
  }
}"#;

/// Chrome without trust_anchors: one extension fewer.
const WRONG_JA4: &str = "t13d1516h2_8daaf6152771_806a8c22fdea";

/// Chrome 152+ in PqcBandwidthExperiment: server_padding besides.
const PADDED_JA4: &str = "t13d1518h2_8daaf6152771_4980c97edce0";
const PADDED_JA3N: &str = "a3a3161a080b73bda9cc285fb367fcc0";

/// Mock services, one request per connection. Routes: `/chrome` ->
/// `CHROME_JSON`, `/peet` -> `CHROME_PEET_JSON`, `/wrong` -> `CHROME_JSON`
/// with `WRONG_JA4`, `/padded` -> `CHROME_JSON` with `PADDED_JA4` and
/// `PADDED_JA3N`, `/down` -> 503, `/html` -> a page without JSON.
fn server() -> u16 {
    common::mock_server(|_method, path, _head, _body| {
        let (status, content_type, body) = match path {
            "/chrome" => (200, "application/json", CHROME_JSON.to_string()),
            "/peet" => (200, "application/json", CHROME_PEET_JSON.to_string()),
            "/wrong" => (
                200,
                "application/json",
                CHROME_JSON.replace("t13d1517h2_8daaf6152771_cb7bf5808d99", WRONG_JA4),
            ),
            "/padded" => (
                200,
                "application/json",
                CHROME_JSON
                    .replace("t13d1517h2_8daaf6152771_cb7bf5808d99", PADDED_JA4)
                    .replace("bd4930bd9b000ee684830e44bab76fdf", PADDED_JA3N),
            ),
            "/down" => (503, "text/plain", "maintenance".to_string()),
            "/html" => (200, "text/html", "<html>hello</html>".to_string()),
            _ => (404, "text/plain", "no route".to_string()),
        };
        (
            status,
            vec![("content-type", content_type.to_string())],
            body.into_bytes(),
        )
    })
}

/// `koon verify` without the HTTP/3 check. Chrome's PqcBandwidthExperiment
/// is pinned outside the study unless a test pins a group itself, so the
/// references do not depend on the group a client draws.
fn koon_verify(args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_koon"));
    command.arg("verify").arg("--skip-http3");
    if !args.contains(&"--server-padding") {
        command.args(["--server-padding", "none"]);
    }
    command.args(args).output().expect("koon runs")
}

/// The profile name `name` resolves to (`chrome154` -> `chrome154-<default
/// OS>`).
fn canonical(name: &str) -> String {
    koon_core::BrowserProfile::resolve_name(name)
        .expect("a built-in profile")
        .name
}

#[test]
fn matching_fingerprint_exits_0() {
    let service = format!("http://127.0.0.1:{}/chrome", server());
    let out = koon_verify(&["-b", "chrome154-windows", "--service", &service]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(stdout.contains("chrome154-windows: match\n"), "{stdout}");
    assert!(
        stdout.contains("  reference    chromium-mldsa-trust-anchors: "),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!("  service      {service}\n")),
        "{stdout}"
    );
    assert!(
        stdout.contains("  ja4          match        t13d1517h2_8daaf6152771_cb7bf5808d99\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "  ja3_hash     not checked  9ca2569240e510d5cde6f8e7a0c3bd38 (no reference value)\n"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains("  quic_ja4     not checked  (HTTP/3 check skipped)\n"),
        "{stdout}"
    );
    assert!(stdout.ends_with("1 profile: 1 match\n"), "{stdout}");
}

#[test]
fn mismatch_exits_20_with_expected_and_actual() {
    let service = format!("http://127.0.0.1:{}/wrong", server());
    let out = koon_verify(&["-b", "chrome154", "--service", &service]);
    let stdout = text(&out.stdout);
    let stderr = text(&out.stderr);
    let chrome = canonical("chrome154");
    assert_eq!(out.status.code(), Some(20), "{stdout}{stderr}");
    assert!(
        stdout.contains(&format!("chrome154 -> {chrome}: MISMATCH\n")),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "  ja4          MISMATCH     {WRONG_JA4}\n{:>27} t13d1517h2_8daaf6152771_cb7bf5808d99\n",
            "expected"
        )),
        "{stdout}"
    );
    assert!(
        stdout.contains("  akamai_text  match        1:65536;"),
        "{stdout}"
    );
    assert!(
        stdout.ends_with("1 profile: 0 match, 1 mismatch\n"),
        "{stdout}"
    );
    assert!(
        stderr.contains(&format!(
            "Error: fingerprint differs from the real browser: {chrome}"
        )),
        "{stderr}"
    );
}

#[test]
fn json_output_reports_every_field() {
    let service = format!("http://127.0.0.1:{}/chrome", server());
    // Chrome's fingerprint matches chrome, not firefox; Firefox 140 on Android
    // (a release without a capture of its own) has no reference.
    let out = koon_verify(&[
        "--json",
        "-b",
        "chrome154,firefox156",
        "firefox-mobile140",
        "--service",
        &service,
    ]);
    assert_eq!(out.status.code(), Some(20), "{}", text(&out.stderr));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON output");
    assert_eq!(json["outcome"], "mismatch");
    assert_eq!(json["koon_version"], env!("CARGO_PKG_VERSION"));
    let results = json["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);

    let chrome = &results[0];
    assert_eq!(chrome["requested"], "chrome154");
    assert_eq!(chrome["profile"], canonical("chrome154").as_str());
    assert_eq!(chrome["outcome"], "match");
    assert_eq!(chrome["service"], service.as_str());
    let fields = chrome["fields"].as_array().unwrap();
    let names: Vec<&str> = fields
        .iter()
        .map(|f| f["field"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "ja4",
            "ja3n_hash",
            "ja3_hash",
            "akamai_hash",
            "akamai_text",
            "quic_ja4"
        ]
    );
    assert_eq!(fields[0]["status"], "match");
    assert_eq!(fields[0]["value"], "t13d1517h2_8daaf6152771_cb7bf5808d99");
    assert_eq!(fields[2]["status"], "not_checked");
    assert_eq!(fields[2]["reason"], "no_reference");
    assert_eq!(fields[5]["reason"], "skipped");

    let firefox = &results[1];
    assert_eq!(firefox["profile"], canonical("firefox156").as_str());
    assert_eq!(firefox["outcome"], "mismatch");
    assert_eq!(firefox["fields"][0]["status"], "mismatch");
    assert_eq!(
        firefox["fields"][0]["expected"],
        "t13d1517h2_8daaf6152771_3cbfd9057e0d"
    );
    assert_eq!(
        firefox["fields"][0]["actual"],
        "t13d1517h2_8daaf6152771_cb7bf5808d99"
    );

    let unreferenced = &results[2];
    assert_eq!(unreferenced["outcome"], "no_reference");
    assert_eq!(unreferenced["references"].as_array().unwrap().len(), 0);
    assert_eq!(unreferenced["fields"][0]["reason"], "no_reference");
}

#[test]
fn no_reference_is_no_failure() {
    let service = format!("http://127.0.0.1:{}/chrome", server());
    let out = koon_verify(&["-b", "firefox-mobile140", "--service", &service]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(
        stdout.contains("firefox-mobile140 -> firefox140-android: no reference"),
        "{stdout}"
    );
    assert!(
        stdout.ends_with("1 profile: 0 match, 1 without reference\n"),
        "{stdout}"
    );
}

/// A client in a group of PqcBandwidthExperiment is compared with the
/// padded ClientHello, whatever the group asks for.
#[test]
fn padded_clients_are_compared_with_the_padded_reference() {
    let port = server();
    let padded = format!("http://127.0.0.1:{port}/padded");
    for bytes in ["0", "6000", "16000"] {
        let out = koon_verify(&[
            "-b",
            "chrome154-windows",
            "--server-padding",
            bytes,
            "--service",
            &padded,
        ]);
        let stdout = text(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
        assert!(
            stdout.contains("  reference    chrome-server-padding: "),
            "{stdout}"
        );
        assert!(
            stdout.contains(&format!("  ja4          match        {PADDED_JA4}\n")),
            "{stdout}"
        );
    }
    // Outside the study the padded fingerprint differs from the reference.
    let out = koon_verify(&[
        "-b",
        "chrome154-windows",
        "--server-padding",
        "none",
        "--service",
        &padded,
    ]);
    assert_eq!(out.status.code(), Some(20), "{}", text(&out.stdout));
}

#[test]
fn falls_back_to_the_next_service() {
    let port = server();
    let down = format!("http://127.0.0.1:{port}/down");
    let peet = format!("http://127.0.0.1:{port}/peet");
    let out = koon_verify(&["-b", "chrome", "--service", &down, "--service", &peet]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(
        stdout.contains(&format!("  service      {peet}\n")),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!("  failed       {down}: answered HTTP 503\n")),
        "{stdout}"
    );
    assert!(
        stdout.contains("  ja3n_hash    not checked  (not reported by the service)\n"),
        "{stdout}"
    );
    assert!(stdout.contains("  ja4          match "), "{stdout}");
}

#[test]
fn unreachable_service_exits_with_the_connection_error() {
    let service = format!("http://127.0.0.1:{}/json", closed_port());
    let out = koon_verify(&["-b", "chrome", "--service", &service]);
    let stdout = text(&out.stdout);
    let stderr = text(&out.stderr);
    let chrome = canonical("chrome");
    assert_eq!(out.status.code(), Some(7), "{stdout}{stderr}");
    assert!(
        stdout.contains(&format!(
            "chrome -> {chrome}: fingerprint service unreachable\n"
        )),
        "{stdout}"
    );
    assert!(
        stdout.ends_with("1 profile: 0 match, 1 unreachable\n"),
        "{stdout}"
    );
    assert!(
        stderr.contains(&format!(
            "Error: no fingerprint service reachable for {chrome} (check the network or the proxy): "
        )),
        "{stderr}"
    );
    assert!(stderr.contains(&service), "{stderr}");

    let out = koon_verify(&["--json", "-b", "chrome", "--service", &service]);
    assert_eq!(out.status.code(), Some(7));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON output");
    assert_eq!(json["outcome"], "unreachable");
    assert_eq!(json["results"][0]["errors"][0]["code"], "CONNECTION_FAILED");
}

#[test]
fn service_errors_have_their_exit_codes() {
    let port = server();
    let out = koon_verify(&[
        "-b",
        "chrome",
        "--service",
        &format!("http://127.0.0.1:{port}/down"),
    ]);
    assert_eq!(out.status.code(), Some(22), "{}", text(&out.stderr));
    let out = koon_verify(&[
        "-b",
        "chrome",
        "--service",
        &format!("http://127.0.0.1:{port}/html"),
    ]);
    assert_eq!(out.status.code(), Some(8), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("no JSON in the answer"));
}

#[test]
fn unknown_profile_exits_2_before_any_request() {
    let out = koon_verify(&[
        "-b",
        "chrome",
        "netscape",
        "--service",
        "http://127.0.0.1:1/",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(text(&out.stderr).contains("Unknown browser: 'netscape'"));
}

#[test]
fn proxy_errors_exit_97() {
    let service = format!("http://127.0.0.1:{}/chrome", server());
    let proxy = format!("http://user:secret@127.0.0.1:{}", closed_port());
    let out = koon_verify(&["-b", "chrome", "--service", &service, "--proxy", &proxy]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(97), "{}{stderr}", text(&out.stdout));
    assert!(
        stderr.contains("* Proxy: http://***@127.0.0.1:"),
        "{stderr}"
    );
    assert!(!stderr.contains("secret"), "{stderr}");
}
