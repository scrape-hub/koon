//! Checks the fingerprints of real servers against the reference values of
//! `koon_core::verify`, captured from real browsers.
//!
//! Every profile of `verify::CHECKPOINTS` (both ends of every version range
//! a reference covers) goes through `verify::verify_with`, which asks
//! `https://tls.browserleaks.com/json` (tls.peet.ws as fallback) for JA4,
//! JA3N, exact JA3 where the reference has one, and the Akamai HTTP/2
//! fingerprint, and quic.browserleaks.com over HTTP/3 for the QUIC JA4 where
//! a reference has one.
//!
//! References must come from captures against a hostname: an IP literal
//! drops SNI and Chrome's trust_anchors extension from the ClientHello.
//!
//! One runner checks every checkpoint, one after the other (browserleaks
//! resets handshakes under load), and reports all mismatches together.
//!
//! Run with: `cargo test --test fingerprint -- --ignored`

use koon_core::verify::{self, Check, Field, NotChecked, Outcome, Services};
use koon_core::{BrowserProfile, Client};

/// What differs in `report`, if anything: mismatching fields, unreachable
/// services, and a QUIC JA4 the reference has but the check could not
/// compare.
fn failure(report: &verify::VerifyReport) -> Option<String> {
    let mut lines = Vec::new();
    for check in &report.fields {
        match &check.check {
            Check::Mismatch { expected, actual } => lines.push(format!(
                "    {:<12} actual={actual}\n    {:<12} expected={expected}",
                check.field.name(),
                ""
            )),
            Check::NotChecked {
                reason: reason @ (NotChecked::NoHttp3 | NotChecked::Unreachable),
                ..
            } if check.field == Field::QuicJa4 => {
                lines.push(format!(
                    "    quic_ja4     not checked: {}",
                    reason.describe()
                ));
            }
            _ => {}
        }
    }
    if report.outcome == Outcome::Unreachable {
        lines.push("    no fingerprint service answered".into());
    }
    for error in &report.errors {
        lines.push(format!(
            "    {} failed ({}): {}",
            error.service, error.code, error.message
        ));
    }
    (!lines.is_empty() || report.outcome != Outcome::Match).then(|| lines.join("\n"))
}

/// Every checkpoint of `verify::CHECKPOINTS`; all failures are reported
/// together.
#[tokio::test]
#[ignore]
async fn fingerprints_match_browser_captures() {
    let services = Services::default();
    let mut failures = Vec::new();
    for &name in verify::CHECKPOINTS {
        let profile = BrowserProfile::resolve_name(name).expect("a known profile");
        let client = Client::builder(BrowserProfile::resolve(name).unwrap())
            .timeout(verify::DEFAULT_TIMEOUT)
            .build()
            .expect("client creation failed");
        let report = verify::verify_with(&profile, &client, &services).await;
        client.shutdown().await;
        if let Some(diff) = failure(&report) {
            failures.push(format!("{name} ({:?}):\n{diff}", report.outcome));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} profiles differ:\n{}",
        failures.len(),
        verify::CHECKPOINTS.len(),
        failures.join("\n")
    );
}
