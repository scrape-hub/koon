use crate::cookie::{Cookie, CookieParams, SkippedCookie, validate_imported};
use crate::error::Error;

use super::Client;

impl Client {
    /// Insert or replace cookies from an external source (e.g. a browser's cookie jar, imported via
    /// Playwright/CDP `cookies()`/`addCookies()`). An invalid cookie is skipped rather than failing
    /// the whole import; returns the skipped ones with their position in `cookies` (0-based), name
    /// and reason. A cookie whose `expires` is already in the past deletes the matching stored
    /// cookie instead, as a live `Set-Cookie` response would. Validation shares its name/value and
    /// prefix rules with the jar's own `Set-Cookie` parser (see [`crate::cookie`]); `domain` must be
    /// a host name and is stored as the URL parser writes it (lowercase, IDNA as punycode).
    ///
    /// # Errors
    /// [`Error::CookieJarDisabled`] for a client built without a jar.
    pub fn set_cookies(&self, cookies: Vec<Cookie>) -> Result<Vec<SkippedCookie>, Error> {
        self.import_cookies(cookies.into_iter().map(|mut cookie| {
            match validate_imported(&mut cookie) {
                Ok(()) => Ok(cookie),
                Err(reason) => Err((cookie.name, reason.to_string())),
            }
        }))
    }

    /// [`set_cookies`](Self::set_cookies) from the Playwright/CDP shape (see [`CookieParams`]), with
    /// the same checks and the same deletion by a past `expires`; a cookie whose fields don't
    /// convert (e.g. both `url` and `domain`) is skipped too, and so is a partitioned (CHIPS) one
    /// with a cross-site ancestor or an opaque key, which browsers send only in frames below
    /// another site. Fails as `set_cookies` does.
    pub fn set_cookie_params(
        &self,
        cookies: Vec<CookieParams>,
    ) -> Result<Vec<SkippedCookie>, Error> {
        self.import_cookies(cookies.into_iter().map(|params| {
            let name = params.name.clone();
            params.into_cookie().map_err(|reason| (name, reason))
        }))
    }

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
    /// Returns an empty `Vec` if the cookie jar is disabled, same as an empty jar: there's nothing
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
