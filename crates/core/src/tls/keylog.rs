use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::{Mutex, OnceLock};

use btls::ssl::SslContextBuilder;

/// Name of the environment variable.
pub const ENV_VAR: &str = "SSLKEYLOGFILE";

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

pub(crate) fn install(builder: &mut SslContextBuilder) {
    if file().is_none() {
        return;
    }
    builder.set_keylog_callback(|_, line| {
        if let Some(file) = file() {
            let mut file = crate::util::lock_recover(file);
            let _ = file.write_all(format!("{line}\n").as_bytes());
        }
    });
}
