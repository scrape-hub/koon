//! TLS key logging for traffic analysis, opt-in through the `SSLKEYLOGFILE` environment variable
//! (as in Chrome, Firefox and curl): when set, the secrets of every TLS handshake (TCP and QUIC)
//! are appended to it in the NSS key log format, for Wireshark and similar tools to decrypt the
//! traffic. **Anyone who can read that file can decrypt every connection it covers**, including
//! cookies, credentials and response bodies: set it only for debugging, never in production. Read
//! once, when the first TLS context of the process is built; on Unix the file is created readable
//! by its owner only.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::{Mutex, OnceLock};

use btls::ssl::SslContextBuilder;

/// Name of the environment variable.
pub const ENV_VAR: &str = "SSLKEYLOGFILE";

/// The key log file of the process, if `SSLKEYLOGFILE` names one that can be opened for appending.
fn file() -> Option<&'static Mutex<File>> {
    static FILE: OnceLock<Option<Mutex<File>>> = OnceLock::new();
    FILE.get_or_init(|| {
        let path = std::env::var_os(ENV_VAR).filter(|p| !p.is_empty())?;
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path).ok().map(Mutex::new)
    })
    .as_ref()
}

/// Log the secrets of the context's handshakes when key logging is on.
pub(crate) fn install(builder: &mut SslContextBuilder) {
    if file().is_none() {
        return;
    }
    builder.set_keylog_callback(|_, line| {
        if let Some(file) = file() {
            let mut file = crate::util::lock_recover(file);
            // One write per line keeps concurrent handshakes from interleaving within a line.
            let _ = file.write_all(format!("{line}\n").as_bytes());
        }
    });
}
