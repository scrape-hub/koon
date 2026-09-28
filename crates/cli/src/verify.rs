//! `koon verify`: checks the fingerprints of the built-in profiles against
//! the ones captured from the real browsers (`koon_core::verify`).

use std::fmt::Write as _;
use std::time::Duration;

use clap::Args;
use koon_core::BrowserProfile;
use koon_core::verify::{
    Check, Outcome, QUIC_SERVICE, Services, TLS_SERVICES, VerifyReport, verify_with,
};
use serde_json::json;

use crate::{CliError, ConnectionArgs, exit_code, failed, parse_timeout, write_stdout};

/// The profiles `koon verify` checks without `-b`: the latest version of
/// each browser, on the default OS.
const DEFAULT_PROFILES: &[&str] = &[
    "chrome",
    "firefox",
    "safari",
    "edge",
    "opera",
    "brave",
    "samsung",
    "opera-mobile",
    "okhttp",
];

/// Exit code when a fingerprint differs from the real browser's.
pub const MISMATCH_EXIT: u8 = 20;

pub const VERIFY_HELP: &str = "\
Each profile connects to tls.browserleaks.com (tls.peet.ws if that fails),
which reports the JA4, JA3N, JA3 and Akamai HTTP/2 fingerprint it sees, and,
where a QUIC reference exists, over HTTP/3 to quic.browserleaks.com for the
QUIC JA4. Every field is compared with the value captured from the real
browser: match, MISMATCH (expected vs. actual), or not checked (no reference
value, not reported by the service, HTTP/3 not used). Versions without a
capture (Safari releases between the captured ones, Firefox on Android
before 146) are reported as 'no reference'.

Chrome 151 and later draw their group of Chrome's field trial
PqcBandwidthExperiment per client, as a real installation does: 6 % of them
ask servers for padding (server_padding, 0x12E0), and those are compared
with the padded ClientHellos. --server-padding pins the group: 'none' (not
in the study, like 94 % of real Chrome) or the bytes a group asks for
(0, 6000, 9000, 12000, 14000, 16000).

Examples:
  koon verify
  koon verify -b firefox154-windows chrome-mobile
  koon verify -b chrome --server-padding 6000
  koon verify --json --proxy http://user:pass@host:8080

Exit codes:
  0   every checked field matches (profiles without reference included)
  20  a field differs from the real browser
  7, 28, 35, 97, ...  no fingerprint service reachable (as for a request)
  22  the service answered with an HTTP error; 8 without a fingerprint
  2   unknown profile or invalid option";

/// Check that the installed koon still produces the real browsers'
/// fingerprints (TLS, HTTP/2, HTTP/3)
#[derive(Args)]
pub struct VerifyArgs {
    /// Profiles to check, several allowed (chrome, firefox154-windows, ...)
    /// [default: chrome firefox safari edge opera brave samsung opera-mobile okhttp]
    #[arg(
        short = 'b',
        long = "browser",
        value_name = "PROFILE",
        num_args = 1..,
        value_delimiter = ','
    )]
    browsers: Vec<String>,

    /// Structured JSON output
    #[arg(long = "json")]
    json_output: bool,

    /// Timeout in seconds of each request, fractions allowed (0: no timeout)
    #[arg(long, default_value = "30", value_parser = parse_timeout)]
    timeout: Duration,

    /// Fingerprint service to ask instead of tls.browserleaks.com and
    /// tls.peet.ws (repeatable, tried in order; JSON in the format of either)
    #[arg(long = "service", value_name = "URL")]
    services: Vec<String>,

    /// Skip the HTTP/3 check (QUIC JA4 over quic.browserleaks.com)
    #[arg(long = "skip-http3")]
    skip_http3: bool,

    /// How the checks connect: proxy, DNS, local address, `--server-padding`, ...
    #[command(flatten)]
    connection: ConnectionArgs,
}

/// The status column of a field.
const fn status(check: &Check) -> &'static str {
    match check {
        Check::Match { .. } => "match",
        Check::Mismatch { .. } => "MISMATCH",
        Check::NotChecked { .. } => "not checked",
    }
}

/// The headline result of a report.
const fn outcome_text(report: &VerifyReport) -> &'static str {
    match report.outcome {
        Outcome::Match => "match",
        Outcome::Mismatch => "MISMATCH",
        Outcome::NoReference => "no reference (no capture of this browser version)",
        Outcome::Unreachable => "fingerprint service unreachable",
    }
}

/// A report as a block of the human-readable output.
fn format_report(requested: &str, report: &VerifyReport) -> String {
    let mut out = String::new();
    let title = if requested.eq_ignore_ascii_case(&report.profile) {
        report.profile.clone()
    } else {
        format!("{requested} -> {}", report.profile)
    };
    let _ = writeln!(out, "{title}: {}", outcome_text(report));
    for reference in &report.references {
        let _ = writeln!(out, "  reference    {}: {}", reference.id, reference.source);
    }
    if let Some(service) = &report.service {
        let _ = writeln!(out, "  service      {service}");
    }
    if let Some(service) = &report.http3_service {
        let _ = writeln!(out, "  http3        {service}");
    }
    for error in &report.errors {
        let _ = writeln!(out, "  failed       {}: {}", error.service, error.message);
    }
    if report.outcome != Outcome::Unreachable {
        for field in &report.fields {
            let name = field.field.name();
            let status = status(&field.check);
            let _ = match &field.check {
                Check::Match { value } => writeln!(out, "  {name:<12} {status:<12} {value}"),
                Check::Mismatch { expected, actual } => {
                    writeln!(out, "  {name:<12} {status:<12} {actual}")
                        .and_then(|()| writeln!(out, "  {:<12} {:>12} {expected}", "", "expected"))
                }
                Check::NotChecked { reason, actual } => match actual {
                    Some(actual) => writeln!(
                        out,
                        "  {name:<12} {status:<12} {actual} ({})",
                        reason.describe()
                    ),
                    None => writeln!(out, "  {name:<12} {status:<12} ({})", reason.describe()),
                },
            };
        }
    }
    out.push('\n');
    out
}

/// The last line of the human-readable output.
fn summary(reports: &[(String, VerifyReport)]) -> String {
    let count = |outcome| reports.iter().filter(|(_, r)| r.outcome == outcome).count();
    let mut parts = vec![format!("{} match", count(Outcome::Match))];
    for (outcome, label) in [
        (Outcome::Mismatch, "mismatch"),
        (Outcome::NoReference, "without reference"),
        (Outcome::Unreachable, "unreachable"),
    ] {
        let n = count(outcome);
        if n > 0 {
            parts.push(format!("{n} {label}"));
        }
    }
    let profiles = if reports.len() == 1 {
        "profile"
    } else {
        "profiles"
    };
    format!("{} {profiles}: {}\n", reports.len(), parts.join(", "))
}

/// The error `koon verify` ends with, if any: a mismatch first, then a
/// profile no service answered for (with the exit code of its first
/// failure).
fn verdict(reports: &[(String, VerifyReport)]) -> Result<(), CliError> {
    let mismatched: Vec<&str> = reports
        .iter()
        .filter(|(_, r)| r.outcome == Outcome::Mismatch)
        .map(|(_, r)| r.profile.as_str())
        .collect();
    if !mismatched.is_empty() {
        return Err(CliError {
            message: format!(
                "fingerprint differs from the real browser: {}",
                mismatched.join(", ")
            ),
            exit_code: MISMATCH_EXIT,
        });
    }
    if let Some((_, report)) = reports
        .iter()
        .find(|(_, r)| r.outcome == Outcome::Unreachable)
    {
        let failures: Vec<String> = report
            .errors
            .iter()
            .map(|e| format!("{}: {}", e.service, e.message))
            .collect();
        return Err(CliError {
            message: format!(
                "no fingerprint service reachable for {} (check the network or the proxy): {}",
                report.profile,
                failures.join("; ")
            ),
            exit_code: report.errors.first().map_or(1, |e| exit_code(e.code)),
        });
    }
    Ok(())
}

/// The `--json` document of the reports.
fn json_document(reports: &[(String, VerifyReport)]) -> Result<Vec<u8>, CliError> {
    let outcome = if reports.iter().any(|(_, r)| r.outcome == Outcome::Mismatch) {
        "mismatch"
    } else if reports
        .iter()
        .any(|(_, r)| r.outcome == Outcome::Unreachable)
    {
        "unreachable"
    } else {
        "match"
    };
    let results = reports
        .iter()
        .map(|(requested, report)| {
            let mut value = serde_json::to_value(report)
                .map_err(|e| CliError::other(format!("Failed to serialize JSON: {e}")))?;
            if let Some(object) = value.as_object_mut() {
                object.insert("requested".into(), json!(requested));
            }
            Ok(value)
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    let document = json!({
        "koon_version": env!("CARGO_PKG_VERSION"),
        "outcome": outcome,
        "results": results,
    });
    let mut bytes = serde_json::to_vec_pretty(&document)
        .map_err(|e| CliError::other(format!("Failed to serialize JSON: {e}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub async fn run_verify(args: VerifyArgs) -> Result<(), CliError> {
    let names: Vec<String> = if args.browsers.is_empty() {
        DEFAULT_PROFILES.iter().map(ToString::to_string).collect()
    } else {
        args.browsers.clone()
    };
    // Every name is checked before the first request. `--server-padding`, part of `connection`,
    // is applied to each profile inside `client_builder` below.
    let profiles = names
        .iter()
        .map(|name| {
            let profile = BrowserProfile::resolve(name)?;
            Ok((name, BrowserProfile::resolve_name(name)?, profile))
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    let services = Services {
        tls: if args.services.is_empty() {
            TLS_SERVICES.iter().map(ToString::to_string).collect()
        } else {
            args.services.clone()
        },
        quic: (!args.skip_http3).then(|| QUIC_SERVICE.to_string()),
    };

    if !args.json_output {
        eprintln!(
            "koon {}: comparing {} profile(s) with real-browser fingerprints via {}",
            env!("CARGO_PKG_VERSION"),
            profiles.len(),
            services.tls.join(", ")
        );
        args.connection.print_settings();
    }
    let mut reports = Vec::new();
    for (requested, entry, profile) in profiles {
        let client = args
            .connection
            .client_builder(profile)?
            .timeout(args.timeout)
            .build()
            .map_err(failed("Client build failed"))?;
        let report = verify_with(&entry, &client, &services).await;
        client.shutdown().await;
        if !args.json_output {
            write_stdout(format_report(requested, &report).as_bytes())?;
        }
        reports.push((requested.clone(), report));
    }
    if args.json_output {
        write_stdout(&json_document(&reports)?)?;
    } else {
        write_stdout(summary(&reports).as_bytes())?;
    }
    verdict(&reports)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Command};
    use clap::Parser;

    fn verify_args(args: &[&str]) -> VerifyArgs {
        let cli = Cli::try_parse_from(args).expect("valid arguments");
        match cli.command {
            Some(Command::Verify(args)) => args,
            _ => panic!("expected the verify command"),
        }
    }

    #[test]
    fn parses_profiles_and_options() {
        let args = verify_args(&["koon", "verify"]);
        assert!(args.browsers.is_empty() && !args.json_output && !args.skip_http3);
        let args = verify_args(&[
            "koon",
            "verify",
            "-b",
            "chrome",
            "firefox154",
            "-b",
            "safari,okhttp4",
            "--json",
            "--proxy",
            "http://u:p@proxy:8080",
            "--timeout",
            "5",
            "--skip-http3",
        ]);
        assert_eq!(args.browsers, ["chrome", "firefox154", "safari", "okhttp4"]);
        assert!(args.json_output && args.skip_http3);
        assert_eq!(
            args.connection.proxy.as_deref(),
            Some("http://u:p@proxy:8080")
        );
        assert_eq!(args.timeout, Duration::from_secs(5));
        assert!(Cli::try_parse_from(["koon", "verify", "-b"]).is_err());
    }

    #[test]
    fn server_padding_is_parsed_and_shared_with_the_main_cli() {
        // `--server-padding` lives on the shared `ConnectionArgs`: `koon verify` gets it for
        // free, and pinning itself (`BrowserProfile::pin_server_padding`) is a core test.
        let args = verify_args(&["koon", "verify", "--server-padding", "none"]);
        assert_eq!(
            args.connection.server_padding,
            Some(koon_core::ServerPadding::None)
        );
        let args = verify_args(&["koon", "verify", "--server-padding", "6000"]);
        assert_eq!(
            args.connection.server_padding,
            Some(koon_core::ServerPadding::Bytes(6000))
        );
        assert!(Cli::try_parse_from(["koon", "verify", "--server-padding", "x"]).is_err());
    }
}
