use std::sync::OnceLock;

use btls::ex_data::Index;
use btls::hpke::HpkeAead;
use btls::ssl::{
    ExtensionType, KeyShare, Ssl, SslConnector, SslConnectorBuilder, SslContextBuilder, SslMethod,
    SslOptions, SslRef, SslSessionCacheMode, SslVerifyMode, SslVersion,
};
use btls::x509::X509;

use super::cert_compression::{BrotliCertCompressor, ZlibCertCompressor, ZstdCertCompressor};
use super::config::{
    AlpnProtocol, AlpsCodepoint, CertCompression, EchGrease, ExtensionOrder, TlsConfig, TlsVersion,
    TrustAnchorId, TrustAnchorOrder,
};
use super::ech_grease::{self, OfferedPsk};
use super::session_cache::SessionCache;
use super::{root_store, sigalgs};
use crate::Error;

// BoringSSL FFI. btls's safe `add_application_settings()` passes no settings payload, but Chrome
// sends SETTINGS_NO_RFC7540_PRIORITIES (6 bytes) as its h2 ALPS data, so the C function is declared
// directly.
unsafe extern "C" {
    fn SSL_add_application_settings(
        ssl: *mut std::ffi::c_void,
        proto: *const u8,
        proto_len: usize,
        settings: *const u8,
        settings_len: usize,
    ) -> std::ffi::c_int;

    // Not wrapped by btls. `ids` is the wire format: 8-bit length-prefixed trust anchor IDs.
    fn SSL_CTX_set1_requested_trust_anchors(
        ctx: *mut std::ffi::c_void,
        ids: *const u8,
        ids_len: usize,
    ) -> std::ffi::c_int;
    fn SSL_set1_requested_trust_anchors(
        ssl: *mut std::ffi::c_void,
        ids: *const u8,
        ids_len: usize,
    ) -> std::ffi::c_int;

    // Not wrapped by btls: the ticket and cipher suite of a session, which size the pre_shared_key
    // extension offering it.
    fn SSL_SESSION_get0_ticket(
        session: *const std::ffi::c_void,
        out_ticket: *mut *const u8,
        out_len: *mut usize,
    );
    fn SSL_SESSION_get0_cipher(session: *const std::ffi::c_void) -> *const std::ffi::c_void;
    fn SSL_CIPHER_get_protocol_id(cipher: *const std::ffi::c_void) -> u16;

    // Not wrapped by btls: the server's ALPS data.
    fn SSL_has_application_settings(ssl: *const std::ffi::c_void) -> std::ffi::c_int;
    fn SSL_get0_peer_application_settings(
        ssl: *const std::ffi::c_void,
        out_data: *mut *const u8,
        out_len: *mut usize,
    );
}

/// The application settings (ALPS) the server sent, if ALPS was negotiated.
pub fn peer_application_settings(ssl: &SslRef) -> Option<Vec<u8>> {
    // In the foreign-types pattern, &SslRef is the SSL pointer.
    let ptr = ssl as *const SslRef as *const std::ffi::c_void;
    let mut data: *const u8 = std::ptr::null();
    let mut len = 0usize;
    // SAFETY: `ssl` is a live SSL; both calls only read it, and the data
    // stays valid while it does (copied before returning).
    unsafe {
        if SSL_has_application_settings(ptr) != 1 {
            return None;
        }
        SSL_get0_peer_application_settings(ptr, &mut data, &mut len);
        if data.is_null() {
            return Some(Vec::new());
        }
        Some(std::slice::from_raw_parts(data, len).to_vec())
    }
}

/// Trust anchor IDs in wire format: each behind an 8-bit length.
fn trust_anchors_wire<'a>(ids: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    let mut wire = Vec::new();
    for id in ids {
        // A TrustAnchorId has at most 255 bytes.
        wire.push(id.len() as u8);
        wire.extend_from_slice(id);
    }
    wire
}

/// For [`TrustAnchorOrder::ShuffledPerConnection`]: give this connection's ClientHello the trust
/// anchor IDs in an order of its own. The context carries them in listed order.
fn shuffle_connection_trust_anchors(ssl: &mut SslRef, config: &TlsConfig) -> Result<(), Error> {
    use rand::seq::SliceRandom;

    let Some(ids) = config
        .trust_anchor_ids
        .as_ref()
        .filter(|_| config.trust_anchor_order == TrustAnchorOrder::ShuffledPerConnection)
    else {
        return Ok(());
    };
    let mut ids: Vec<&[u8]> = ids.iter().map(TrustAnchorId::as_bytes).collect();
    ids.shuffle(&mut rand::rng());
    let wire = trust_anchors_wire(ids);
    // SAFETY: in the foreign-types pattern, &mut SslRef is the SSL pointer;
    // BoringSSL copies `wire`.
    let ret = unsafe {
        SSL_set1_requested_trust_anchors(
            ssl as *mut SslRef as *mut std::ffi::c_void,
            wire.as_ptr(),
            wire.len(),
        )
    };
    if ret != 1 {
        return Err(Error::Config("rejected trust anchor IDs".into(), None));
    }
    Ok(())
}

/// Ex-data slot carrying the session cache key of a connection, so the new-session callback knows
/// where to store tickets.
fn session_key_index() -> Index<Ssl, String> {
    static INDEX: OnceLock<Index<Ssl, String>> = OnceLock::new();
    *INDEX.get_or_init(|| Ssl::new_ex_index().expect("allocating an SSL ex-data index"))
}

/// Apply the fingerprint-relevant TLS settings of a profile to a context. Shared by the TCP
/// connector and the QUIC client config, so both ClientHellos come from the same configuration.
pub fn apply_fingerprint(builder: &mut SslContextBuilder, config: &TlsConfig) -> Result<(), Error> {
    // Must precede set_cipher_list(): keeps the TLS 1.3 cipher order from the list instead of
    // BoringSSL's hardware-dependent one (Firefox).
    if config.preserve_tls13_cipher_order {
        builder.set_preserve_tls13_cipher_list(true);
    }
    builder.set_cipher_list(&config.cipher_list)?;
    builder.set_curves_list(&config.curves)?;

    // Signing prefs only cover what BoringSSL can actually produce for a client certificate; the
    // advertised list may contain more (ML-DSA on Chromium 150+), so it is set separately from raw
    // code points.
    let signable = sigalgs::signable_subset(&config.sigalgs);
    if !signable.is_empty() {
        builder.set_sigalgs_list(&signable)?;
    }
    builder.set_advertised_verify_algorithm_prefs(&sigalgs::parse(&config.sigalgs)?)?;

    builder.set_grease_enabled(config.grease);
    builder.set_grease_sigalgs_enabled(config.grease_sigalgs);

    // Chrome shuffles its extensions on every handshake; Firefox emits a fixed order that differs
    // from BoringSSL's internal one over TCP, and a permutation with a fixed tail in QUIC.
    let ids = |types: &[u16]| -> Vec<ExtensionType> {
        types.iter().copied().map(ExtensionType::from).collect()
    };
    match &config.extension_order {
        ExtensionOrder::Default => {}
        ExtensionOrder::Permuted => builder.set_permute_extensions(true),
        ExtensionOrder::Fixed(order) => builder.set_extension_permutation(&ids(order))?,
        ExtensionOrder::PermutedWithTail { tail, .. } => {
            builder.set_permute_extensions(true);
            builder.set_extension_order_tail(&ids(tail))?;
        }
    }
    if config.legacy_extensions_in_tls13 {
        builder.set_tls13_legacy_extensions(true);
    }

    if config.ocsp_stapling {
        builder.enable_ocsp_stapling();
    }
    if config.signed_cert_timestamps {
        builder.enable_signed_cert_timestamps();
    }
    // The btls fork's SSL_OP_NO_PSK_DHE_KE omits psk_key_exchange_modes.
    if !config.psk_key_exchange_modes {
        builder.set_options(SslOptions::NO_PSK_DHE_KE);
    }
    if !config.session_ticket {
        builder.set_options(SslOptions::NO_TICKET);
    }

    for algo in &config.cert_compression {
        match algo {
            CertCompression::Brotli => {
                builder.add_certificate_compression_algorithm(BrotliCertCompressor)?;
            }
            CertCompression::Zlib => {
                builder.add_certificate_compression_algorithm(ZlibCertCompressor)?;
            }
            CertCompression::Zstd => {
                builder.add_certificate_compression_algorithm(ZstdCertCompressor)?;
            }
        }
    }

    if let Some(ref dc_sigalgs) = config.delegated_credentials {
        // By code point, so the ML-DSA schemes Firefox announces in QUIC go out although BoringSSL
        // cannot verify them.
        builder.set_delegated_credential_algorithm_prefs(&sigalgs::parse(dc_sigalgs)?)?;
    }
    if let Some(limit) = config.record_size_limit {
        builder.set_record_size_limit(limit);
    }

    if let Some(ids) = &config.trust_anchor_ids {
        let wire = trust_anchors_wire(ids.iter().map(TrustAnchorId::as_bytes));
        // SAFETY: in the foreign-types pattern, SslContextBuilder::as_ptr() is the SSL_CTX
        // pointer; BoringSSL copies `wire`.
        let ret = unsafe {
            SSL_CTX_set1_requested_trust_anchors(
                builder.as_ptr() as *mut std::ffi::c_void,
                wire.as_ptr(),
                wire.len(),
            )
        };
        if ret != 1 {
            return Err(Error::Config("rejected trust anchor IDs".into(), None));
        }
    }

    if config.danger_accept_invalid_certs {
        builder.set_verify(SslVerifyMode::NONE);
    } else {
        builder.set_verify(SslVerifyMode::PEER);
        root_store::load(builder)?;
        // Browsers verify certificates on a worker thread. Besides keeping the runtime free, this
        // shapes the QUIC handshake: the Handshake ACK goes out while the chain is verified, the
        // Finished right after.
        builder.set_async_default_verify(spawn_verification);
    }
    super::keylog::install(builder);
    Ok(())
}

/// Runs a certificate verification on tokio's blocking pool, or right away outside a runtime.
fn spawn_verification(job: btls::ssl::VerifyJob) {
    match tokio::runtime::Handle::try_current() {
        Ok(runtime) => {
            runtime.spawn_blocking(job);
        }
        Err(_) => job(),
    }
}

/// Two-phase TLS connector for browser fingerprint impersonation:
/// [`build_connector`](Self::build_connector) builds a reusable `SslConnector` with context-level
/// settings (ciphers, curves, ALPN, cert compression);
/// [`configure_connection`](Self::configure_connection) then builds a per-connection `Ssl` (ECH
/// GREASE, ALPS, SNI, session).
pub struct TlsConnector;

impl TlsConnector {
    /// Build a reusable SslConnector (once per Client).
    pub fn build_connector(
        config: &TlsConfig,
        session_cache: Option<SessionCache>,
    ) -> Result<SslConnector, Error> {
        let mut builder = Self::builder(config)?;

        if let Some(cache) = session_cache {
            builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);
            builder.set_new_session_callback(move |ssl, session| {
                if let Some(key) = ssl.ex_data(session_key_index()) {
                    cache.insert(key, session);
                }
            });
        }

        Ok(builder.build())
    }

    /// The connector for TLS to HTTPS proxies: the profile's ClientHello, with the proxy's
    /// certificate verified against koon's root store plus `extra_roots`, unless `config` turns
    /// verification off. Sessions with proxies are not resumed.
    pub fn build_proxy_connector(
        config: &TlsConfig,
        extra_roots: &[X509],
    ) -> Result<SslConnector, Error> {
        let mut builder = Self::builder(config)?;
        if !config.danger_accept_invalid_certs && !extra_roots.is_empty() {
            builder.set_verify_cert_store(root_store::with_extra(extra_roots)?)?;
        }
        Ok(builder.build())
    }

    /// A connector builder with the context-level settings of `config`.
    fn builder(config: &TlsConfig) -> Result<SslConnectorBuilder, Error> {
        let mut builder = SslConnector::builder(SslMethod::tls())?;
        apply_fingerprint(&mut builder, config)?;

        builder.set_min_proto_version(Some(to_ssl_version(config.min_version)))?;
        builder.set_max_proto_version(Some(to_ssl_version(config.max_version)))?;
        builder.set_alpn_protos(&build_alpn_wire(&config.alpn))?;
        Ok(builder)
    }

    /// Configure a per-connection SSL object. `session` names the cache and key used for
    /// resumption: a cached session is offered, and new tickets from this connection are stored
    /// under that key.
    pub fn configure_connection(
        connector: &SslConnector,
        config: &TlsConfig,
        host: &str,
        force_h1_only: bool,
        session: Option<(&SessionCache, &str)>,
        ech_config_list: Option<&[u8]>,
    ) -> Result<Ssl, Error> {
        let mut cfg = connector.configure()?;

        // ALPN: for WebSocket, only advertise http/1.1 (no h2)
        let alpn: &[AlpnProtocol] = if force_h1_only {
            &[AlpnProtocol::Http11]
        } else {
            &config.alpn
        };
        cfg.set_alpn_protos(&build_alpn_wire(alpn))?;

        // ECH: real ECH from DNS HTTPS record, or GREASE (set up below, once the session to offer
        // is known).
        if let Some(ech_bytes) = ech_config_list {
            cfg.set_ech_config_list(ech_bytes).map_err(|e| {
                let message = format!("ECH config failed: {e}");
                Error::ConnectionFailed(message, crate::error::boxed(e))
            })?;
        }

        // ALPS (h2-specific, skip when forcing h1)
        if let Some(codepoint) = config.alps.filter(|_| !force_h1_only) {
            cfg.set_alps_use_new_codepoint(codepoint == AlpsCodepoint::New);

            // Chrome sends SETTINGS_NO_RFC7540_PRIORITIES (id=9, value=1) as ALPS client data. H2
            // SETTINGS frame payload: 2-byte id + 4-byte value.
            let alps_settings: [u8; 6] = [0x00, 0x09, 0x00, 0x00, 0x00, 0x01];
            let proto = b"h2";
            // In the foreign-types pattern, &SslRef has the same memory representation as *mut SSL.
            // ConnectConfiguration derefs to SslRef.
            let ssl_ptr = &*cfg as *const btls::ssl::SslRef as *mut std::ffi::c_void;
            let ret = unsafe {
                SSL_add_application_settings(
                    ssl_ptr,
                    proto.as_ptr(),
                    proto.len(),
                    alps_settings.as_ptr(),
                    alps_settings.len(),
                )
            };
            if ret != 1 {
                return Err(Error::ConnectionFailed(
                    "Failed to set ALPS application settings".into(),
                    None,
                ));
            }
        }

        if config.danger_accept_invalid_certs {
            cfg.set_verify_hostname(false);
        }

        let mut ssl = cfg.into_ssl(host)?;
        set_key_shares(&mut ssl, config)?;
        shuffle_connection_trust_anchors(&mut ssl, config)?;
        if let Some(bytes) = config.server_padding {
            ssl.set_server_padding_request(bytes);
        }

        if let Some((cache, key)) = session {
            ssl.set_ex_data(session_key_index(), key.to_string());
            if let Some(session) = cache.take(key) {
                unsafe {
                    ssl.set_session(&session)?;
                }
                // NSS drops session_ticket when offering a TLS 1.3 PSK. On the client,
                // SSL_OP_NO_TICKET only suppresses that extension and TLS 1.2 ticket resumption;
                // the PSK and NewSessionTicket processing are unaffected.
                if config.omit_session_ticket_on_resumption
                    && session.protocol_version() == SslVersion::TLS1_3
                {
                    ssl.set_options(SslOptions::NO_TICKET);
                }
            }
        }
        if ech_config_list.is_none() {
            set_ech_grease(&mut ssl, config, host, false)?;
        }

        Ok(ssl)
    }
}

/// The profile's ECH GREASE. NSS's payload length depends on the session the ClientHello offers, so
/// this runs after the session is set.
fn set_ech_grease(
    ssl: &mut SslRef,
    config: &TlsConfig,
    host: &str,
    quic: bool,
) -> Result<(), Error> {
    ssl.set_enable_ech_grease(config.ech_grease != EchGrease::Off);
    if let EchGrease::Nss {
        name_len,
        legacy_padding,
    } = config.ech_grease
    {
        // NSS picks the AEAD on one random bit.
        ssl.set_ech_grease_aead(if rand::random() {
            HpkeAead::AES_128_GCM
        } else {
            HpkeAead::CHACHA20_POLY1305
        })?;
        let psk = offered_psk(ssl, quic);
        let padding = ech_grease::Padding {
            name_len,
            legacy: legacy_padding,
        };
        if let Some(len) = ech_grease::padded_inner_hello_len(config, host, quic, psk, padding) {
            ssl.set_ech_grease_payload_len(len);
        }
    }
    Ok(())
}

/// The TLS 1.3 session the ClientHello offers as a pre-shared key. QUIC sessions are only cached
/// when they allow early data, which the ClientHello then offers too.
fn offered_psk(ssl: &SslRef, quic: bool) -> Option<OfferedPsk> {
    let session = ssl
        .session()
        .filter(|s| s.protocol_version() == SslVersion::TLS1_3)?;
    // In the foreign-types pattern, &SslSessionRef is the SSL_SESSION pointer.
    let ptr = session as *const btls::ssl::SslSessionRef as *const std::ffi::c_void;
    let mut ticket: *const u8 = std::ptr::null();
    let mut ticket_len = 0usize;
    // SAFETY: `session` is a live SSL_SESSION; both calls only read it.
    let cipher = unsafe {
        SSL_SESSION_get0_ticket(ptr, &mut ticket, &mut ticket_len);
        let cipher = SSL_SESSION_get0_cipher(ptr);
        (!cipher.is_null()).then(|| SSL_CIPHER_get_protocol_id(cipher))
    };
    if ticket_len == 0 {
        return None;
    }
    Some(OfferedPsk {
        ticket_len,
        // TLS_AES_256_GCM_SHA384 hashes with SHA-384, the others SHA-256.
        binder_len: if cipher == Some(0x1302) { 48 } else { 32 },
        early_data: quic,
    })
}

/// Key shares: by default BoringSSL offers one for the first group and one for the first later
/// group of the other kind (post-quantum or classical), if any; Firefox sends three
/// (X25519MLKEM768, X25519, P-256).
fn set_key_shares(ssl: &mut SslRef, config: &TlsConfig) -> Result<(), Error> {
    if let Some(limit) = config.key_shares_limit {
        let shares: Vec<KeyShare> = config
            .curves
            .split(':')
            .filter_map(key_share_for)
            .take(limit as usize)
            .collect();
        if !shares.is_empty() {
            ssl.set_client_key_shares(&shares)?;
        }
    }
    Ok(())
}

/// The part of a QUIC ClientHello that BoringSSL takes only per SSL object: ECH (real, from the DNS
/// HTTPS record, or GREASE with none), ALPS for `h3` (Chrome's application_settings extension, with
/// the empty client settings it sends in QUIC), the number of key shares, the server padding
/// request and a per-connection order of the trust anchor IDs. quinn-btls calls it for every
/// connection, once the server name and the session to offer are set, as `configure_connection`
/// does for TCP.
pub fn configure_quic_ssl(
    ssl: &mut SslRef,
    config: &TlsConfig,
    host: &str,
    ech_config_list: Option<&[u8]>,
) -> Result<(), Error> {
    if let Some(codepoint) = config.alps {
        ssl.set_alps_use_new_codepoint(codepoint == AlpsCodepoint::New);
        ssl.add_application_settings(b"h3")?;
    }
    set_key_shares(ssl, config)?;
    if let Some(bytes) = config.server_padding {
        ssl.set_server_padding_request(bytes);
    }
    shuffle_connection_trust_anchors(ssl, config)?;
    if let Some(ech_bytes) = ech_config_list {
        ssl.set_ech_config_list(ech_bytes).map_err(|e| {
            let message = format!("ECH config failed: {e}");
            Error::ConnectionFailed(message, crate::error::boxed(e))
        })?;
    } else {
        set_ech_grease(ssl, config, host, true)?;
    }
    Ok(())
}

/// For [`TrustAnchorOrder::ShuffledPerClient`]: fix the order of the trust anchor IDs for the
/// client that `config` is built into.
pub fn shuffle_client_trust_anchors(config: &mut TlsConfig) {
    use rand::seq::SliceRandom;

    if config.trust_anchor_order == TrustAnchorOrder::ShuffledPerClient {
        if let Some(ids) = &mut config.trust_anchor_ids {
            ids.shuffle(&mut rand::rng());
        }
    }
}

/// For [`ServerPaddingTrial`](super::config::ServerPaddingTrial): draw the padding of the client
/// that `profile` is built into, once, from the TCP configuration's trial, and set it on the TCP
/// and QUIC ClientHello configurations that carry a trial, which the profile then loses. A QUIC
/// configuration with a trial of its own, beside a TCP one without, draws its own.
pub fn draw_server_padding(profile: &mut crate::BrowserProfile) {
    let mut rng = rand::rng();
    let drawn = profile
        .tls
        .server_padding_trial
        .take()
        .map(|trial| trial.draw(&mut rng));
    if let Some(padding) = drawn {
        profile.tls.server_padding = padding;
    }
    if let Some(tls) = profile.quic.as_mut().and_then(|q| q.tls.as_mut()) {
        if let Some(trial) = tls.server_padding_trial.take() {
            tls.server_padding = drawn.unwrap_or_else(|| trial.draw(&mut rng));
        }
    }
}

/// Key share for a group name of the curves list; `None` for groups that cannot carry a key share
/// (finite-field groups).
fn key_share_for(name: &str) -> Option<KeyShare> {
    match name.trim() {
        "X25519MLKEM768" => Some(KeyShare::X25519_MLKEM768),
        "X25519" => Some(KeyShare::X25519),
        "P-256" => Some(KeyShare::P256),
        "P-384" => Some(KeyShare::P384),
        "P-521" => Some(KeyShare::P521),
        _ => None,
    }
}

fn to_ssl_version(v: TlsVersion) -> SslVersion {
    match v {
        TlsVersion::Tls10 => SslVersion::TLS1,
        TlsVersion::Tls11 => SslVersion::TLS1_1,
        TlsVersion::Tls12 => SslVersion::TLS1_2,
        TlsVersion::Tls13 => SslVersion::TLS1_3,
    }
}

/// Build the ALPN wire format: each protocol is preceded by its length byte.
fn build_alpn_wire(protocols: &[AlpnProtocol]) -> Vec<u8> {
    let mut wire = Vec::new();
    for proto in protocols {
        let name = match proto {
            AlpnProtocol::Http2 => b"h2" as &[u8],
            AlpnProtocol::Http11 => b"http/1.1",
        };
        wire.push(name.len() as u8);
        wire.extend_from_slice(name);
    }
    wire
}

#[cfg(test)]
mod tests {
    use std::io::{self, Read, Write};

    use super::*;
    use crate::profile::{Chrome, Firefox, Os};

    /// A transport that keeps what the client writes and has nothing to read, so a handshake stops
    /// after the ClientHello.
    #[derive(Default)]
    struct Capture(Vec<u8>);

    impl Read for Capture {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    impl Write for Capture {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Extensions of the TLS 1.3-only ClientHello an SSL configured by `configure_quic_ssl` sends
    /// (over TLS here, which carries the same extensions apart from quic_transport_parameters).
    fn quic_hello_extensions(tls: &TlsConfig) -> Vec<(u16, Vec<u8>)> {
        quic_connection_hello(&quic_context(tls), tls)
    }

    fn quic_context(tls: &TlsConfig) -> btls::ssl::SslContext {
        let mut builder = SslContextBuilder::new(SslMethod::tls()).unwrap();
        apply_fingerprint(&mut builder, tls).unwrap();
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        builder.set_alpn_protos(b"\x02h3").unwrap();
        builder.build()
    }

    /// Extensions of the ClientHello of one connection from `ctx`.
    fn quic_connection_hello(ctx: &btls::ssl::SslContext, tls: &TlsConfig) -> Vec<(u16, Vec<u8>)> {
        let mut ssl = Ssl::new(ctx).unwrap();
        ssl.set_hostname("example.com").unwrap();
        configure_quic_ssl(&mut ssl, tls, "example.com", None).unwrap();
        let Err(btls::ssl::HandshakeError::WouldBlock(mid)) = ssl.connect(Capture::default())
        else {
            panic!("the handshake should wait for the server");
        };
        let record = &mid.get_ref().0;
        let u16_at = |p: usize| u16::from_be_bytes([record[p], record[p + 1]]);
        // record header, handshake header, legacy_version, random
        let mut p = 5 + 4 + 2 + 32;
        p += 1 + record[p] as usize;
        p += 2 + u16_at(p) as usize;
        p += 1 + record[p] as usize;
        let end = p + 2 + u16_at(p) as usize;
        p += 2;
        let mut exts = Vec::new();
        while p < end {
            let len = u16_at(p + 2) as usize;
            exts.push((u16_at(p), record[p + 4..p + 4 + len].to_vec()));
            p += 4 + len;
        }
        exts
    }

    fn payload(exts: &[(u16, Vec<u8>)], ty: u16) -> Option<&[u8]> {
        exts.iter()
            .find(|(t, _)| *t == ty)
            .map(|(_, d)| d.as_slice())
    }

    #[test]
    fn quic_ssl_settings_complete_chromes_hello() {
        let tls = Chrome::latest().quic.unwrap().tls.unwrap();
        let exts = quic_hello_extensions(&tls);
        // ALPS lists h3 under the new codepoint.
        assert_eq!(payload(&exts, 0x44cd), Some(&b"\x00\x03\x02h3"[..]));
        assert!(payload(&exts, 0xfe0d).is_some(), "ECH GREASE");
        // No GREASE anywhere in Chrome's QUIC ClientHello.
        assert!(exts.iter().all(|(t, _)| t & 0x0f0f != 0x0a0a));
    }

    /// Chrome 153 orders its trust anchor IDs anew on every QUIC connection; Chrome 154 sends them
    /// sorted.
    #[test]
    fn quic_trust_anchor_order_by_version() {
        let ids = |exts: &[(u16, Vec<u8>)]| payload(exts, 0xca34).unwrap().to_vec();
        let tls = Chrome::version(153, Os::Windows)
            .unwrap()
            .quic
            .unwrap()
            .tls
            .unwrap();
        assert_eq!(
            tls.trust_anchor_order,
            TrustAnchorOrder::ShuffledPerConnection
        );
        let ctx = quic_context(&tls);
        let first = ids(&quic_connection_hello(&ctx, &tls));
        let second = ids(&quic_connection_hello(&ctx, &tls));
        assert_eq!(first.len(), 186);
        assert_ne!(first, second, "a new order per connection");
        // The list without its length, IDs sorted bytewise.
        let sorted = |wire: &[u8]| -> Vec<u8> {
            let mut ids: Vec<&[u8]> = Vec::new();
            let mut p = 2;
            while p < wire.len() {
                ids.push(&wire[p + 1..p + 1 + wire[p] as usize]);
                p += 1 + wire[p] as usize;
            }
            ids.sort_unstable();
            ids.iter()
                .flat_map(|id| std::iter::once(id.len() as u8).chain(id.iter().copied()))
                .collect()
        };
        assert_eq!(sorted(&first), sorted(&second));

        let tls = Chrome::latest().quic.unwrap().tls.unwrap();
        assert_eq!(tls.trust_anchor_order, TrustAnchorOrder::Listed);
        let ctx = quic_context(&tls);
        let first = ids(&quic_connection_hello(&ctx, &tls));
        assert_eq!(first, ids(&quic_connection_hello(&ctx, &tls)));
        assert_eq!(sorted(&first), first[2..]);
    }

    #[test]
    fn quic_ssl_settings_give_firefox_three_key_shares() {
        let tls = Firefox::latest().quic.unwrap().tls.unwrap();
        let exts = quic_hello_extensions(&tls);
        let shares = payload(&exts, 0x0033).unwrap();
        let mut groups = Vec::new();
        let mut p = 2;
        while p + 4 <= shares.len() {
            groups.push(u16::from_be_bytes([shares[p], shares[p + 1]]));
            p += 4 + u16::from_be_bytes([shares[p + 2], shares[p + 3]]) as usize;
        }
        assert_eq!(groups, [0x11ec, 0x001d, 0x0017]);
        assert!(payload(&exts, 0x44cd).is_none());
        assert!(payload(&exts, 0xfe0d).is_some(), "ECH GREASE");
    }

    /// The trial's draw sets the same padding for TCP and QUIC and leaves no trial behind; outside
    /// the trial neither asks for padding.
    #[test]
    fn server_padding_is_drawn_once_for_tcp_and_quic() {
        let quic_padding = |profile: &crate::BrowserProfile| {
            profile
                .quic
                .as_ref()
                .unwrap()
                .tls
                .as_ref()
                .unwrap()
                .server_padding
        };
        for (enrolled, expected) in [(100, Some(9000)), (0, None)] {
            let mut profile = Chrome::latest();
            let trial = profile.tls.server_padding_trial.as_mut().unwrap();
            trial.enrolled_slots = enrolled;
            trial.groups.retain(|g| g.bytes == 9000);
            draw_server_padding(&mut profile);
            assert_eq!(profile.tls.server_padding, expected);
            assert_eq!(quic_padding(&profile), expected);
            assert_eq!(profile.tls.server_padding_trial, None);
            let quic = profile.quic.as_ref().unwrap().tls.as_ref().unwrap();
            assert_eq!(quic.server_padding_trial, None);
        }
        // Many clients: some in the trial, TCP and QUIC always alike.
        let mut padded = 0;
        for _ in 0..2000 {
            let mut profile = Chrome::latest();
            draw_server_padding(&mut profile);
            assert_eq!(profile.tls.server_padding, quic_padding(&profile));
            padded += usize::from(profile.tls.server_padding.is_some());
        }
        assert!((40..=240).contains(&padded), "{padded} of 2000");
    }
}
