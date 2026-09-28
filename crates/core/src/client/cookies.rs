//! Import/export API for the cookie jar: lets a caller seed the jar from an external source (e.g. a
//! browser's cookies via Playwright/CDP) and read it back out for export.

use crate::cookie::{
    Cookie, CookieParams, SkippedCookie, is_public_suffix, normalize_domain, prefix_ok,
    validate_name_value,
};
use crate::error::Error;

use super::Client;

impl Client {
    /// Insert or replace cookies from an external source (e.g. a browser's cookie jar, imported via
    /// Playwright/CDP `cookies()`/`addCookies()`). An invalid cookie is skipped rather than failing
    /// the whole import; returns the skipped ones with their position in `cookies` (0-based), name
    /// and reason. A cookie whose `expires` is already in the past deletes the matching stored
    /// cookie instead, as a live `Set-Cookie` response would. Validation shares its name/value and
    /// prefix rules with the jar's own `Set-Cookie` parser (see [`crate::cookie`]).
    ///
    /// # Errors
    /// [`Error::CookieJarDisabled`] for a client built without a jar.
    pub fn set_cookies(&self, cookies: Vec<Cookie>) -> Result<Vec<SkippedCookie>, Error> {
        // A raw `Cookie` never went through `CookieParams::into_cookie`'s validation, unlike
        // `set_cookie_params` below: this is the one place it gets checked.
        self.import_cookies(cookies.into_iter().map(|mut cookie| {
            match validate_and_normalize(&mut cookie) {
                Ok(()) => Ok(cookie),
                Err(reason) => Err((cookie.name, reason.to_string())),
            }
        }))
    }

    /// [`set_cookies`](Self::set_cookies) from the Playwright/CDP shape (see [`CookieParams`]); a
    /// cookie whose fields don't convert (e.g. both `url` and `domain`), whose name/value or
    /// `__Secure-`/`__Host-` prefix is invalid, or that names a public-suffix domain without
    /// `host_only`, is skipped too, and so is a
    /// partitioned (CHIPS) one, since koon never makes the third-party requests it needs. Fails as
    /// `set_cookies` does.
    pub fn set_cookie_params(
        &self,
        cookies: Vec<CookieParams>,
    ) -> Result<Vec<SkippedCookie>, Error> {
        self.import_cookies(cookies.into_iter().map(|params| {
            let name = params.name.clone();
            params.into_cookie().map_err(|reason| (name, reason))
        }))
    }

    /// Store the already-validated `cookies` (or report the name and reason a conversion failed
    /// with). Each import path validates its cookies exactly once, before it gets here:
    /// [`set_cookies`](Self::set_cookies) itself (a raw [`Cookie`] never passed through
    /// [`CookieParams::into_cookie`]) and [`set_cookie_params`](Self::set_cookie_params) via that
    /// conversion.
    fn import_cookies(
        &self,
        cookies: impl Iterator<Item = Result<Cookie, (String, String)>>,
    ) -> Result<Vec<SkippedCookie>, Error> {
        let jar = self.cookie_jar.as_ref().ok_or(Error::CookieJarDisabled)?;

        let mut valid = Vec::new();
        let mut skipped = Vec::new();
        for (index, cookie) in cookies.enumerate() {
            match cookie {
                Ok(cookie) => valid.push(cookie),
                Err((name, reason)) => skipped.push(SkippedCookie {
                    index,
                    name,
                    reason,
                }),
            }
        }

        // Held for the whole function body, which is exactly as long as it's needed.
        #[allow(clippy::significant_drop_tightening)]
        let mut jar = crate::util::lock_recover(jar);
        for cookie in valid {
            jar.set(cookie);
        }
        jar.prune();
        Ok(skipped)
    }

    /// Return a snapshot of every cookie currently stored in the jar (e.g. to export back into a
    /// browser via Playwright/CDP `addCookies()`).
    ///
    /// Returns an empty `Vec` if the cookie jar is disabled, same as an empty jar — there's nothing
    /// to export either way.
    pub fn cookies(&self) -> Vec<Cookie> {
        match &self.cookie_jar {
            Some(jar) => crate::util::lock_recover(jar).cookies().to_vec(),
            None => Vec::new(),
        }
    }

    /// [`cookies`](Self::cookies) in the Playwright/CDP shape: domain cookies with a leading dot,
    /// host-only cookies without, `expires` in Unix seconds (`-1` for session cookies).
    pub fn cookie_params(&self) -> Vec<CookieParams> {
        match &self.cookie_jar {
            Some(jar) => crate::util::lock_recover(jar)
                .cookies()
                .iter()
                .map(CookieParams::from)
                .collect(),
            None => Vec::new(),
        }
    }
}

/// Validate an imported cookie and normalize its `domain` in place. See [`Client::set_cookies`] for
/// the exact rules.
fn validate_and_normalize(cookie: &mut Cookie) -> Result<(), &'static str> {
    validate_name_value(&cookie.name, &cookie.value)?;
    cookie.domain = normalize_domain(&cookie.domain);
    if cookie.domain.is_empty() {
        return Err("domain cannot be empty");
    }
    if !cookie.path.starts_with('/') {
        return Err("path must start with '/'");
    }
    if !cookie.host_only && is_public_suffix(&cookie.domain) {
        return Err("domain cannot be a public suffix unless host_only");
    }
    prefix_ok(
        &cookie.name,
        &cookie.value,
        cookie.secure,
        cookie.host_only,
        cookie.path == "/",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cookie::SameSite;
    use crate::profile::Chrome;
    use std::time::SystemTime;

    fn imported(name: &str, value: &str, domain: &str, host_only: bool) -> Cookie {
        Cookie {
            name: name.to_string(),
            value: value.to_string(),
            domain: domain.to_string(),
            path: "/".to_string(),
            secure: true,
            http_only: true,
            expires: None,
            same_site: SameSite::Lax,
            host_only,
            creation_time: SystemTime::now(),
        }
    }

    /// Import `cookie` alone into `client`; the reason it was skipped, if it was.
    fn skip_reason(client: &Client, cookie: Cookie) -> Option<String> {
        let mut skipped = client.set_cookies(vec![cookie]).unwrap();
        assert!(skipped.len() <= 1);
        skipped.pop().map(|s| s.reason)
    }

    #[test]
    fn set_cookies_requires_cookie_jar() {
        let client = Client::builder(Chrome::latest())
            .cookie_jar(false)
            .build()
            .unwrap();
        let err = client
            .set_cookies(vec![imported("a", "1", "example.com", true)])
            .unwrap_err();
        assert_eq!(err.code(), "COOKIE_JAR_DISABLED");
        assert!(!err.is_retryable());
        assert!(err.to_string().to_lowercase().contains("disabled"));
        let err = client.set_cookie_params(vec![]).unwrap_err();
        assert_eq!(err.code(), "COOKIE_JAR_DISABLED");
    }

    #[test]
    fn set_cookie_params_skips_and_reports_partitioned_cookies() {
        let client = Client::new(Chrome::latest()).unwrap();
        let param = |name: &str, partitioned: bool| CookieParams {
            name: name.to_string(),
            value: "v".to_string(),
            domain: Some("example.com".to_string()),
            partitioned,
            ..CookieParams::default()
        };
        let skipped = client
            .set_cookie_params(vec![param("kept", false), param("chips", true)])
            .unwrap();
        assert_eq!(skipped.len(), 1);
        assert_eq!((skipped[0].index, skipped[0].name.as_str()), (1, "chips"));
        assert!(skipped[0].reason.contains("partitioned"), "{skipped:?}");
        let names: Vec<String> = client.cookies().into_iter().map(|c| c.name).collect();
        assert_eq!(names, ["kept"]);
    }

    #[test]
    fn set_cookies_imports_the_valid_cookies_and_reports_the_rest() {
        let client = Client::new(Chrome::latest()).unwrap();
        let mut bad = imported("b", "1", "example.com", true);
        bad.name = "b;ad".to_string();

        let skipped = client
            .set_cookies(vec![
                imported("good", "1", "example.com", true),
                bad,
                imported("also-good", "1", "example.com", true),
            ])
            .unwrap();
        assert_eq!(skipped.len(), 1);
        assert_eq!((skipped[0].index, skipped[0].name.as_str()), (1, "b;ad"));
        assert!(!skipped[0].reason.is_empty());
        let mut names: Vec<String> = client.cookies().into_iter().map(|c| c.name).collect();
        names.sort();
        assert_eq!(names, ["also-good", "good"]);
    }

    #[test]
    fn set_cookies_and_export_roundtrip() {
        let client = Client::new(Chrome::latest()).unwrap();
        let skipped = client
            .set_cookies(vec![imported("a", "1", "example.com", true)])
            .unwrap();
        assert!(skipped.is_empty());

        let exported = client.cookies();
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].name, "a");
        assert_eq!(exported[0].domain, "example.com");
    }

    #[test]
    fn set_cookies_normalizes_domain() {
        let client = Client::new(Chrome::latest()).unwrap();
        client
            .set_cookies(vec![imported("a", "1", ".EXAMPLE.com", false)])
            .unwrap();

        assert_eq!(client.cookies()[0].domain, "example.com");
    }

    #[test]
    fn set_cookies_skips_public_suffix_domain_cookie() {
        let client = Client::new(Chrome::latest()).unwrap();
        for domain in ["co.uk", "com"] {
            let reason = skip_reason(&client, imported("a", "1", domain, false));
            assert!(reason.unwrap().contains("public suffix"));
        }
        assert!(client.cookies().is_empty());
    }

    #[test]
    fn set_cookies_allows_host_only_public_suffix() {
        // host_only means "exactly this host", so it is not the cross-eTLD sharing risk a domain
        // cookie on a public suffix would be.
        let client = Client::new(Chrome::latest()).unwrap();
        assert_eq!(
            skip_reason(&client, imported("a", "1", "co.uk", true)),
            None
        );
        assert_eq!(client.cookies().len(), 1);
    }

    #[test]
    fn set_cookies_skips_empty_name_and_value() {
        let client = Client::new(Chrome::latest()).unwrap();
        assert!(skip_reason(&client, imported("", "", "example.com", true)).is_some());
        assert!(client.cookies().is_empty());
    }

    #[test]
    fn set_cookies_allows_empty_name_with_value() {
        let client = Client::new(Chrome::latest()).unwrap();
        assert_eq!(
            skip_reason(&client, imported("", "abc", "example.com", true)),
            None
        );
        assert_eq!(client.cookies().len(), 1);

        let prefixed = imported("", "__Host-x", "example.com", true);
        assert!(skip_reason(&client, prefixed).is_some());
    }

    #[test]
    fn set_cookies_skips_path_without_leading_slash() {
        let client = Client::new(Chrome::latest()).unwrap();
        let mut cookie = imported("a", "1", "example.com", true);
        cookie.path = "no-leading-slash".to_string();
        assert!(skip_reason(&client, cookie).unwrap().contains("path"));
    }

    #[test]
    fn set_cookies_enforces_host_prefix() {
        let client = Client::new(Chrome::latest()).unwrap();

        let mut not_secure = imported("__Host-a", "1", "example.com", true);
        not_secure.secure = false;
        assert!(skip_reason(&client, not_secure).is_some());

        let has_domain = imported("__Host-b", "1", "example.com", false);
        assert!(skip_reason(&client, has_domain).is_some());

        let mut wrong_path = imported("__Host-c", "1", "example.com", true);
        wrong_path.path = "/app".to_string();
        assert!(skip_reason(&client, wrong_path).is_some());

        let valid = imported("__Host-d", "1", "example.com", true);
        assert_eq!(skip_reason(&client, valid), None);
        assert_eq!(client.cookies().len(), 1);
    }

    #[test]
    fn set_cookies_enforces_secure_prefix() {
        let client = Client::new(Chrome::latest()).unwrap();

        let mut not_secure = imported("__Secure-a", "1", "example.com", true);
        not_secure.secure = false;
        assert!(skip_reason(&client, not_secure).is_some());

        let valid = imported("__Secure-b", "1", "example.com", true);
        assert_eq!(skip_reason(&client, valid), None);
        assert_eq!(client.cookies().len(), 1);
    }

    #[test]
    fn set_cookies_deletes_on_past_expiry() {
        let client = Client::new(Chrome::latest()).unwrap();
        client
            .set_cookies(vec![imported("a", "1", "example.com", true)])
            .unwrap();
        assert_eq!(client.cookies().len(), 1);

        let mut expire_it = imported("a", "1", "example.com", true);
        expire_it.expires = Some(SystemTime::UNIX_EPOCH);
        assert!(client.set_cookies(vec![expire_it]).unwrap().is_empty());
        assert!(client.cookies().is_empty());
    }

    #[test]
    fn cookies_returns_empty_vec_when_jar_disabled() {
        let client = Client::builder(Chrome::latest())
            .cookie_jar(false)
            .build()
            .unwrap();
        assert!(client.cookies().is_empty());
        assert!(client.cookie_params().is_empty());
    }

    #[test]
    fn set_cookie_params_imports_and_exports() {
        let client = Client::new(Chrome::latest()).unwrap();
        let skipped = client
            .set_cookie_params(vec![
                CookieParams {
                    name: "domain".into(),
                    value: "1".into(),
                    domain: Some(".example.com".into()),
                    ..CookieParams::default()
                },
                CookieParams {
                    name: "host".into(),
                    value: "2".into(),
                    url: Some("https://www.example.com/app/page".into()),
                    ..CookieParams::default()
                },
            ])
            .unwrap();
        assert!(skipped.is_empty());

        let mut exported = client.cookie_params();
        exported.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(exported[0].domain.as_deref(), Some(".example.com"));
        assert_eq!(exported[0].host_only, Some(false));
        assert_eq!(exported[1].domain.as_deref(), Some("www.example.com"));
        assert_eq!(exported[1].path.as_deref(), Some("/app/"));
        assert!(exported[1].secure);
        assert_eq!(exported[1].host_only, Some(true));

        // The export feeds straight back in.
        let other = Client::new(Chrome::latest()).unwrap();
        assert!(
            other
                .set_cookie_params(exported.clone())
                .unwrap()
                .is_empty()
        );
        let mut again = other.cookie_params();
        again.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(again, exported);
    }

    #[test]
    fn set_cookie_params_reports_cookies_that_do_not_convert() {
        let client = Client::new(Chrome::latest()).unwrap();
        let skipped = client
            .set_cookie_params(vec![
                CookieParams {
                    name: "good".into(),
                    domain: Some("example.com".into()),
                    value: "1".into(),
                    ..CookieParams::default()
                },
                CookieParams {
                    name: "bad".into(),
                    value: "1".into(),
                    domain: Some("example.com".into()),
                    expires: Some(f64::NAN),
                    ..CookieParams::default()
                },
                CookieParams {
                    name: "invalid".into(),
                    value: "a;b".into(),
                    domain: Some("example.com".into()),
                    ..CookieParams::default()
                },
            ])
            .unwrap();
        let reported: Vec<(usize, &str)> =
            skipped.iter().map(|s| (s.index, s.name.as_str())).collect();
        assert_eq!(reported, [(1, "bad"), (2, "invalid")]);
        assert!(skipped[0].reason.contains("expires"), "{skipped:?}");
        let names: Vec<String> = client.cookies().into_iter().map(|c| c.name).collect();
        assert_eq!(names, ["good"]);
    }

    /// Both import paths reject a CRLF-injected name or value: `set_cookies`' own
    /// `validate_and_normalize` for a raw `Cookie`, `CookieParams::into_cookie`'s validation for
    /// `set_cookie_params` — each exactly once, not the other's job too.
    #[test]
    fn both_import_paths_reject_crlf_in_name_or_value() {
        let client = Client::new(Chrome::latest()).unwrap();
        assert!(
            skip_reason(
                &client,
                imported("a\r\nX-Injected: 1", "1", "example.com", true)
            )
            .is_some()
        );
        assert!(
            skip_reason(
                &client,
                imported("a", "1\r\nX-Injected: 1", "example.com", true)
            )
            .is_some()
        );
        assert!(client.cookies().is_empty());

        let base = CookieParams {
            value: "1".to_string(),
            domain: Some("example.com".to_string()),
            ..CookieParams::default()
        };
        let skipped = client
            .set_cookie_params(vec![
                CookieParams {
                    name: "a\r\nX-Injected: 1".to_string(),
                    ..base.clone()
                },
                CookieParams {
                    name: "a".to_string(),
                    value: "1\r\nX-Injected: 1".to_string(),
                    ..base
                },
            ])
            .unwrap();
        assert_eq!(skipped.len(), 2, "{skipped:?}");
        assert!(client.cookies().is_empty());
    }

    /// Both import paths reject an invalid `__Host-` prefix (here: a `Domain` set at all, which
    /// `__Host-` forbids).
    #[test]
    fn both_import_paths_reject_a_bad_host_prefix() {
        let client = Client::new(Chrome::latest()).unwrap();
        let raw = imported("__Host-a", "1", "example.com", false);
        assert!(skip_reason(&client, raw).is_some());

        let skipped = client
            .set_cookie_params(vec![CookieParams {
                name: "__Host-b".to_string(),
                value: "1".to_string(),
                domain: Some("example.com".to_string()),
                secure: true,
                host_only: Some(false),
                ..CookieParams::default()
            }])
            .unwrap();
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        assert!(client.cookies().is_empty());
    }
}
