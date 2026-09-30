//! Runs the `koon` binary against a local HTTP/1.1 server: output to files
//! and pipes, curl's -i/-I/-f/-F/--resolve, uploads from files, timeouts.

use std::process::{Command, Output};
use std::thread;
use std::time::Duration;

use tempfile::TempDir;

mod common;
use common::text;

/// Local server answering one request per connection. Routes: `/echo` ->
/// the request line, headers and body as text; `/status/N` -> status N;
/// `/big` -> 1 MiB; `/slow` -> after 3 s.
fn server() -> u16 {
    common::mock_server(|_method, path, head, body| {
        let headers = vec![
            ("content-type", "text/plain".to_string()),
            ("x-test", "yes".to_string()),
        ];
        let (status, payload): (u16, Vec<u8>) = if path == "/echo" {
            let mut echo = head.as_bytes().to_vec();
            echo.extend_from_slice(body);
            (200, echo)
        } else if let Some(code) = path.strip_prefix("/status/") {
            (code.parse().unwrap(), b"status body".to_vec())
        } else if path == "/big" {
            (200, (0..1 << 20).map(|i| (i % 251) as u8).collect())
        } else if path == "/slow" {
            thread::sleep(Duration::from_secs(3));
            (200, b"late".to_vec())
        } else {
            (404, b"no route".to_vec())
        };
        (status, headers, payload)
    })
}

fn koon(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_koon"))
        .args(args)
        .output()
        .expect("koon runs")
}

/// A fresh directory in the temp directory that no other test uses. It is
/// removed with its files when the guard is dropped, also when the test
/// fails.
fn temp_dir() -> TempDir {
    tempfile::Builder::new()
        .prefix("koon-cli-")
        .tempdir()
        .expect("temp dir")
}

#[test]
fn output_to_a_file_and_a_pipe_is_the_body() {
    let port = server();
    let url = format!("http://127.0.0.1:{port}/big");
    let expected: Vec<u8> = (0..1 << 20).map(|i| (i % 251) as u8).collect();

    let out = koon(&[&url]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(out.stdout, expected);

    let dir = temp_dir();
    let file = dir.path().join("big.bin");
    let out = koon(&["-o", file.to_str().unwrap(), "-v", &url]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(std::fs::read(&file).unwrap(), expected);
    assert!(text(&out.stderr).contains("* Written 1048576 bytes to"));
}

#[test]
fn max_response_body_caps_the_response() {
    let port = common::mock_server(|_method, _path, _head, _body| {
        (200, Vec::new(), "x".repeat(2000).into_bytes())
    });
    let url = format!("http://127.0.0.1:{port}/");

    // --json: the collected path.
    let out = koon(&["--json", "--max-response-body", "100", &url]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("exceeded 100 bytes"),
        "{}",
        text(&out.stderr)
    );
    // 0 disables the cap even against a body the default (100 MiB) would allow anyway.
    let out = koon(&["--json", "--max-response-body", "0", &url]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON output");
    assert_eq!(json["body"].as_str().unwrap().len(), 2000);

    // Piped stdout: streamed chunk by chunk, still capped the same way.
    let out = koon(&["--max-response-body", "100", &url]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("exceeded 100 bytes"),
        "{}",
        text(&out.stderr)
    );
    assert!(out.stdout.len() < 2000, "{} bytes", out.stdout.len());
    let out = koon(&["--max-response-body", "0", &url]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(out.stdout.len(), 2000);

    // -o FILE: also streamed and capped; the partial file is left on disk, shorter than the
    // full body, the way curl leaves a partial download past --max-filesize.
    let dir = temp_dir();
    let file = dir.path().join("capped.txt");
    let out = koon(&[
        "--max-response-body",
        "100",
        "-o",
        file.to_str().unwrap(),
        &url,
    ]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let partial = std::fs::read(&file).expect("the partial file is left on disk");
    assert!(partial.len() < 2000, "{} bytes", partial.len());
}

#[test]
fn include_and_head_print_the_response_head() {
    let port = server();
    let out = koon(&["-i", &format!("http://127.0.0.1:{port}/status/201")]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.starts_with("HTTP/1.1 201\r\n"), "{stdout}");
    assert!(stdout.contains("x-test: yes\r\n"), "{stdout}");
    assert!(stdout.ends_with("\r\n\r\nstatus body"), "{stdout}");

    let out = koon(&["-I", &format!("http://127.0.0.1:{port}/echo")]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.starts_with("HTTP/1.1 200\r\n"), "{stdout}");
    assert!(stdout.ends_with("\r\n\r\n"), "no body: {stdout}");
}

#[test]
fn fail_exits_22_without_output() {
    let port = server();
    let dir = temp_dir();
    let file = dir.path().join("fail.txt");
    let out = koon(&[
        "-f",
        "-o",
        file.to_str().unwrap(),
        &format!("http://127.0.0.1:{port}/status/404"),
    ]);
    assert_eq!(out.status.code(), Some(22));
    assert!(out.stdout.is_empty());
    assert!(!file.exists(), "no output file");
    assert!(text(&out.stderr).contains("The requested URL returned error: 404"));

    let out = koon(&["-f", &format!("http://127.0.0.1:{port}/status/302")]);
    assert!(out.status.success(), "below 400 is no error");
    let out = koon(&[&format!("http://127.0.0.1:{port}/status/500")]);
    assert!(
        out.status.success(),
        "without -f an HTTP error is a response"
    );
    assert_eq!(text(&out.stdout), "status body");
}

#[test]
fn form_fields_are_sent_as_multipart() {
    let port = server();
    let dir = temp_dir();
    let upload = dir.path().join("notes.txt");
    std::fs::write(&upload, "file content").unwrap();
    let out = koon(&[
        "-F",
        "name=value",
        "-F",
        &format!("doc=@{}", upload.display()),
        "-F",
        &format!(
            "raw=@{};type=application/x-test;filename=r.bin",
            upload.display()
        ),
        "-F",
        &format!("inline=<{}", upload.display()),
        &format!("http://127.0.0.1:{port}/echo"),
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let echo = text(&out.stdout);
    assert!(echo.starts_with("POST /echo HTTP/1.1"), "{echo}");
    assert!(
        echo.contains("multipart/form-data; boundary=----WebKitFormBoundary"),
        "{echo}"
    );
    assert!(echo.contains("name=\"name\"\r\n\r\nvalue\r\n"), "{echo}");
    let file_name = upload.file_name().unwrap().to_str().unwrap();
    assert!(
        echo.contains(&format!(
            "name=\"doc\"; filename=\"{file_name}\"\r\nContent-Type: text/plain\r\n\r\nfile content"
        )),
        "{echo}"
    );
    assert!(
        echo.contains("filename=\"r.bin\"\r\nContent-Type: application/x-test"),
        "{echo}"
    );
    assert!(
        echo.contains("name=\"inline\"\r\n\r\nfile content\r\n"),
        "{echo}"
    );

    // Firefox's boundary for a Firefox profile; -X keeps the form.
    let out = koon(&[
        "-b",
        "firefox",
        "-X",
        "PUT",
        "-F",
        "a=1",
        &format!("http://127.0.0.1:{port}/echo"),
    ]);
    let echo = text(&out.stdout);
    assert!(echo.starts_with("PUT /echo"), "{echo}");
    assert!(echo.contains("boundary=----geckoformboundary"), "{echo}");
}

#[test]
fn data_from_a_file_is_uploaded() {
    let port = server();
    let dir = temp_dir();
    let small = dir.path().join("small.json");
    std::fs::write(&small, "{\"a\":1}").unwrap();
    let out = koon(&[
        "-d",
        &format!("@{}", small.display()),
        &format!("http://127.0.0.1:{port}/echo"),
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let echo = text(&out.stdout);
    assert!(echo.starts_with("POST /echo"), "{echo}");
    assert!(echo.ends_with("\r\n\r\n{\"a\":1}"), "{echo}");

    // Above the threshold the file is streamed, with its length.
    let big = dir.path().join("big.bin");
    let size = 17 * 1024 * 1024 + 3;
    let content: Vec<u8> = (0..size).map(|i| (i % 253) as u8).collect();
    std::fs::write(&big, &content).unwrap();
    let out = koon(&[
        "-X",
        "PUT",
        "-d",
        &format!("@{}", big.display()),
        &format!("http://127.0.0.1:{port}/echo"),
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let head_end = out
        .stdout
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap()
        + 4;
    let head = text(&out.stdout[..head_end]);
    assert!(
        head.to_ascii_lowercase()
            .contains(&format!("content-length: {size}\r\n")),
        "{head}"
    );
    assert!(
        out.stdout[head_end..] == content[..],
        "the file arrives whole"
    );

    let out = koon(&["-d", "@/no/such/file", "http://127.0.0.1:1/"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("Failed to read '/no/such/file'"));
}

#[test]
fn resolve_connects_to_the_given_address() {
    let port = server();
    let out = koon(&[
        "--resolve",
        &format!("koon.test:{port}:127.0.0.1"),
        &format!("http://koon.test:{port}/echo"),
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let echo = text(&out.stdout);
    assert!(
        echo.contains(&format!("Host: koon.test:{port}\r\n")),
        "{echo}"
    );

    let out = koon(&["--resolve", "koon.test:80", "http://koon.test/"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("Invalid resolve entry"));
}

#[test]
fn curl_options_without_effect_are_accepted() {
    let port = server();
    let out = koon(&[
        "-sSL",
        "--compressed",
        "-s",
        &format!("http://127.0.0.1:{port}/status/200"),
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "status body");
}

#[test]
fn fractional_timeouts_apply() {
    let port = server();
    let started = std::time::Instant::now();
    let out = koon(&["--timeout", "0.5", &format!("http://127.0.0.1:{port}/slow")]);
    assert_eq!(out.status.code(), Some(28), "{}", text(&out.stderr));
    assert!(started.elapsed() < Duration::from_secs(3));
}
