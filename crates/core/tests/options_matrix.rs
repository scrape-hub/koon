//! Every request option against local servers over HTTP/1.1, HTTP/2 and HTTP/3: an option that
//! holds on one protocol only fails here.

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::h3::{H3Server, h3_route_server};
use common::routes::{Proto, STALL, tcp_server};
use koon_core::{Chrome, Client, ClientBuilder, Error, RequestOptions};

const HOST: &str = "matrix.koon.test";
const PROTOS: [Proto; 3] = [Proto::H1, Proto::H2, Proto::H3];
const TIMEOUT: Duration = Duration::from_millis(500);

/// A client whose requests to [`HOST`] go over `proto`, and the URL base to use.
struct Target {
    client: Client,
    base: String,
    proto: Proto,
    _h3: Option<H3Server>,
}

impl Target {
    async fn new(proto: Proto, configure: impl FnOnce(ClientBuilder) -> ClientBuilder) -> Self {
        let mut profile = Chrome::latest();
        profile.tls.danger_accept_invalid_certs = true;
        let h3 = (proto == Proto::H3).then(|| {
            let (cert, key) = common::leaf(HOST);
            h3_route_server(cert, key)
        });
        let tcp_proto = if proto == Proto::H1 {
            Proto::H1
        } else {
            Proto::H2
        };
        let port = tcp_server(HOST, tcp_proto, h3.as_ref().map(|h3| h3.addr.port())).await;
        let mut builder =
            Client::builder(profile).resolve(HOST, SocketAddr::from(([127, 0, 0, 1], port)));
        if let Some(h3) = &h3 {
            builder = builder.resolve(HOST, h3.addr);
        }
        let client = configure(builder).build().unwrap();
        let base = format!("https://{HOST}:{port}");
        if h3.is_some() {
            // The first response offers HTTP/3 (Alt-Svc); without its pooled HTTP/2 connection
            // the client then takes HTTP/3.
            client.get(&format!("{base}/ok")).await.unwrap();
            client.close();
        }
        Self {
            client,
            base,
            proto,
            _h3: h3,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    async fn get(
        &self,
        path: &str,
        options: RequestOptions,
    ) -> Result<koon_core::HttpResponse, Error> {
        let response = self
            .client
            .send(http::Method::GET, &self.url(path), None::<Vec<u8>>, options)
            .await?;
        assert_eq!(response.version, self.proto.version(), "{path}");
        Ok(response)
    }
}

fn text(body: &[u8]) -> String {
    String::from_utf8_lossy(body).into_owned()
}

#[tokio::test]
async fn timeout_covers_a_stalled_head_and_a_stalled_body() {
    for proto in PROTOS {
        let target = Target::new(proto, |b| b.timeout(TIMEOUT)).await;
        for path in ["/slow-head", "/slow-body"] {
            let started = Instant::now();
            let result = target.get(path, RequestOptions::default()).await;
            assert!(
                matches!(result, Err(Error::Timeout)),
                "{proto:?} {path}: {result:?}"
            );
            assert!(started.elapsed() < STALL, "{proto:?} {path}");
        }
        // A request's own timeout overrides the client's.
        let options = RequestOptions {
            timeout: Some(Duration::from_secs(10)),
            ..RequestOptions::default()
        };
        let late = target.get("/slow-body", options).await.unwrap();
        assert_eq!(late.body, b"ok"[..], "{proto:?}");
    }
}

#[tokio::test]
async fn a_streamed_body_times_out_while_it_stalls() {
    for proto in PROTOS {
        let target = Target::new(proto, |b| b.timeout(TIMEOUT)).await;
        let mut stream = target
            .client
            .send_streaming(
                http::Method::GET,
                &target.url("/slow-body"),
                None::<Vec<u8>>,
                RequestOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(stream.version, proto.version());
        let started = Instant::now();
        let result = stream.collect_body().await;
        assert!(
            matches!(result, Err(Error::Timeout)),
            "{proto:?}: {result:?}"
        );
        assert!(started.elapsed() < STALL, "{proto:?}");
    }
}

#[tokio::test]
async fn max_response_body_caps_plain_and_decoded_bodies() {
    for proto in PROTOS {
        let target = Target::new(proto, |b| b.max_response_body(1000)).await;
        for path in ["/big", "/gzip"] {
            let result = target.get(path, RequestOptions::default()).await;
            assert!(
                matches!(result, Err(Error::ResponseTooLarge(1000))),
                "{proto:?} {path}: {result:?}"
            );
            let mut stream = target
                .client
                .send_streaming(
                    http::Method::GET,
                    &target.url(path),
                    None::<Vec<u8>>,
                    RequestOptions::default(),
                )
                .await
                .unwrap();
            stream.decode_content();
            let collected = stream.collect_body().await;
            assert!(
                matches!(collected, Err(Error::ResponseTooLarge(1000))),
                "{proto:?} {path} streamed: {collected:?}"
            );
        }
        let ok = target.get("/ok", RequestOptions::default()).await.unwrap();
        assert_eq!(ok.body, b"ok"[..]);
    }
}

#[tokio::test]
async fn client_and_request_headers_reach_the_server() {
    for proto in PROTOS {
        let headers = vec![("X-Client".to_string(), "c".to_string())];
        let target = Target::new(proto, |b| b.headers(headers)).await;
        let options = RequestOptions {
            headers: vec![("X-Request".to_string(), "r".to_string())],
            ..RequestOptions::default()
        };
        let echo = text(&target.get("/echo", options).await.unwrap().body);
        assert!(echo.contains("x-client: c\n"), "{proto:?}: {echo}");
        assert!(echo.contains("x-request: r\n"), "{proto:?}: {echo}");
    }
}

#[tokio::test]
async fn redirects_follow_the_options() {
    for proto in PROTOS {
        let target = Target::new(proto, |b| b.max_redirects(2)).await;
        let followed = target
            .get("/redirect/2", RequestOptions::default())
            .await
            .unwrap();
        assert_eq!(
            (followed.status, text(&followed.body).as_str()),
            (200, "end")
        );
        assert!(
            followed.url.ends_with("/redirect/0"),
            "{proto:?}: {}",
            followed.url
        );

        let too_many = target.get("/redirect/3", RequestOptions::default()).await;
        assert!(
            matches!(too_many, Err(Error::TooManyRedirects)),
            "{proto:?}: {too_many:?}"
        );

        let options = RequestOptions {
            follow_redirects: Some(false),
            ..RequestOptions::default()
        };
        let stopped = target.get("/redirect/1", options).await.unwrap();
        assert_eq!(stopped.status, 302, "{proto:?}");
    }
}

#[tokio::test]
async fn cookies_go_back_to_the_server() {
    for proto in PROTOS {
        let target = Target::new(proto, |b| b).await;
        target
            .get("/set-cookie", RequestOptions::default())
            .await
            .unwrap();
        let echo = text(
            &target
                .get("/echo", RequestOptions::default())
                .await
                .unwrap()
                .body,
        );
        assert!(echo.contains("cookie: matrix=1\n"), "{proto:?}: {echo}");
    }
}

#[tokio::test]
async fn hooks_see_every_hop() {
    for proto in PROTOS {
        let seen: Arc<Mutex<Vec<(String, u16)>>> = Arc::default();
        let (requests, responses) = (seen.clone(), seen.clone());
        let target = Target::new(proto, move |b| {
            b.on_request(move |_, url| {
                requests.lock().unwrap().push((url.to_string(), 0));
                Ok(())
            })
            .on_response(move |status, url, _| {
                responses.lock().unwrap().push((url.to_string(), status));
                Ok(())
            })
        })
        .await;
        seen.lock().unwrap().clear();
        target
            .get("/redirect/1", RequestOptions::default())
            .await
            .unwrap();
        let hops: Vec<(String, u16)> = seen
            .lock()
            .unwrap()
            .iter()
            .map(|(url, status)| (url.trim_start_matches(&target.base).to_string(), *status))
            .collect();
        let expected = [
            ("/redirect/1", 0),
            ("/redirect/1", 302),
            ("/redirect/0", 0),
            ("/redirect/0", 200),
        ]
        .map(|(path, status)| (path.to_string(), status));
        assert_eq!(hops, expected, "{proto:?}");
    }
}

#[tokio::test]
async fn without_a_cookie_jar_no_cookie_goes_back() {
    for proto in PROTOS {
        let target = Target::new(proto, |b| b.cookie_jar(false)).await;
        target
            .get("/set-cookie", RequestOptions::default())
            .await
            .unwrap();
        let echo = text(
            &target
                .get("/echo", RequestOptions::default())
                .await
                .unwrap()
                .body,
        );
        assert!(!echo.contains("cookie:"), "{proto:?}: {echo}");
    }
}

#[tokio::test]
async fn an_on_redirect_hook_that_says_no_stops_the_redirect() {
    for proto in PROTOS {
        let target = Target::new(proto, |b| b.on_redirect(|_, _, _| Ok(false))).await;
        let stopped = target
            .get("/redirect/1", RequestOptions::default())
            .await
            .unwrap();
        assert_eq!(stopped.status, 302, "{proto:?}");
    }
}

#[tokio::test]
async fn locale_sets_the_accept_language() {
    for proto in PROTOS {
        let target = Target::new(proto, |b| b.locale("de-DE")).await;
        let echo = text(
            &target
                .get("/echo", RequestOptions::default())
                .await
                .unwrap()
                .body,
        );
        assert!(
            echo.contains("accept-language: de-DE,de;"),
            "{proto:?}: {echo}"
        );
    }
}
