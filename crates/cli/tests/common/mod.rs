//! A one-request-per-connection mock HTTP/1.1 server shared by the CLI's
//! integration tests, each with its own route table.

// Each test binary uses a part of the helpers.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

/// A route's answer: status, extra response headers (`content-length` and
/// `connection: close` are added by the server), and the body. Never sent
/// for a HEAD request.
type Answer = (u16, Vec<(&'static str, String)>, Vec<u8>);

/// Start a server that answers every connection with one request, handed to
/// `route(method, path, head, body)`: `head` is the full request line and
/// headers, as sent, without the trailing blank line. Returns the port.
pub fn mock_server<R>(route: R) -> u16
where
    R: Fn(&str, &str, &str, &[u8]) -> Answer + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let route = Arc::new(route);
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let route = route.clone();
            thread::spawn(move || handle(stream, &*route));
        }
    });
    port
}

fn handle<R>(stream: TcpStream, route: &R)
where
    R: Fn(&str, &str, &str, &[u8]) -> Answer,
{
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    let mut head = request_line.clone();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        head.push_str(&line);
        if line == "\r\n" {
            break;
        }
    }
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let length = head
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    let mut body = vec![0; length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }

    let (status, headers, payload) = route(&method, &path, &head, &body);
    let mut response = format!("HTTP/1.1 {status} X\r\n");
    for (name, value) in &headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str(&format!(
        "content-length: {}\r\nconnection: close\r\n\r\n",
        payload.len()
    ));
    let mut stream = stream;
    let _ = stream.write_all(response.as_bytes());
    if method != "HEAD" {
        let _ = stream.write_all(&payload);
    }
}

/// A local port nothing listens on.
pub fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

pub fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
