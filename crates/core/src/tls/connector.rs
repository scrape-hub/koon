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

unsafe extern "C" {
    fn SSL_add_application_settings(
        ssl: *mut std::ffi::c_void,
        proto: *const u8,
        proto_len: usize,
        settings: *const u8,
        settings_len: usize,
    ) -> std::ffi::c_int;

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

    fn SSL_SESSION_get0_ticket(
        session: *const std::ffi::c_void,
        out_ticket: *mut *const u8,
        out_len: *mut usize,
    );
    fn SSL_SESSION_get0_cipher(session: *const std::ffi::c_void) -> *const std::ffi::c_void;
    fn SSL_CIPHER_get_protocol_id(cipher: *const std::ffi::c_void) -> u16;

    fn SSL_has_application_settings(ssl: *const std::ffi::c_void) -> std::ffi::c_int;
    fn SSL_get0_peer_application_settings(
        ssl: *const std::ffi::c_void,
        out_data: *mut *const u8,
        out_len: *mut usize,
    );
}

pub fn peer_application_settings(ssl: &SslRef) -> Option<Vec<u8>> {
    let ptr = ssl as *const SslRef as *const std::ffi::c_void;
    let mut data: *const u8 = std::ptr::null();
    let mut len = 0usize;
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

fn trust_anchors_wire<'a>(ids: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    let mut wire = Vec::new();
    for id in ids {
        wire.push(id.len() as u8);
        wire.extend_from_slice(id);
    }
    wire
}

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

fn session_key_index() -> Index<Ssl, String> {
    static INDEX: OnceLock<Index<Ssl, String>> = OnceLock::new();
    *INDEX.get_or_init(|| Ssl::new_ex_index().expect("allocating an SSL ex-data index"))
}

pub fn apply_fingerprint(builder: &mut SslContextBuilder, config: &TlsConfig) -> Result<(), Error> {
    if config.preserve_tls13_cipher_order {
        builder.set_preserve_tls13_cipher_list(true);
    }
    builder.set_aes_hw_override(true);
    builder.set_cipher_list(&config.cipher_list)?;
    builder.set_curves_list(&config.curves)?;

    let signable = sigalgs::signable_subset(&config.sigalgs);
    if !signable.is_empty() {
        builder.set_sigalgs_list(&signable)?;
    }
    builder.set_advertised_verify_algorithm_prefs(&sigalgs::parse(&config.sigalgs)?)?;

    builder.set_grease_enabled(config.grease);
    builder.set_grease_sigalgs_enabled(config.grease_sigalgs);

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
        builder.set_delegated_credential_algorithm_prefs(&sigalgs::parse(dc_sigalgs)?)?;
    }
    if let Some(limit) = config.record_size_limit {
        builder.set_record_size_limit(limit);
    }

    if let Some(ids) = &config.trust_anchor_ids {
        let wire = trust_anchors_wire(ids.iter().map(TrustAnchorId::as_bytes));
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
        builder.set_async_default_verify(spawn_verification);
    }
    super::keylog::install(builder);
    Ok(())
}

fn spawn_verification(job: btls::ssl::VerifyJob) {
    match tokio::runtime::Handle::try_current() {
        Ok(runtime) => {
            runtime.spawn_blocking(job);
        }
        Err(_) => job(),
    }
}

pub struct TlsConnector;

impl TlsConnector {
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

    fn builder(config: &TlsConfig) -> Result<SslConnectorBuilder, Error> {
        let mut builder = SslConnector::builder(SslMethod::tls())?;
        apply_fingerprint(&mut builder, config)?;

        builder.set_min_proto_version(Some(to_ssl_version(config.min_version)))?;
        builder.set_max_proto_version(Some(to_ssl_version(config.max_version)))?;
        builder.set_alpn_protos(&build_alpn_wire(&config.alpn))?;
        Ok(builder)
    }

    pub fn configure_connection(
        connector: &SslConnector,
        config: &TlsConfig,
        host: &str,
        force_h1_only: bool,
        session: Option<(&SessionCache, &str)>,
        ech_config_list: Option<&[u8]>,
    ) -> Result<Ssl, Error> {
        let mut cfg = connector.configure()?;

        let alpn: &[AlpnProtocol] = if force_h1_only {
            &[AlpnProtocol::Http11]
        } else {
            &config.alpn
        };
        cfg.set_alpn_protos(&build_alpn_wire(alpn))?;

        if let Some(ech_bytes) = ech_config_list {
            cfg.set_ech_config_list(ech_bytes).map_err(|e| {
                let message = format!("ECH config failed: {e}");
                Error::ConnectionFailed(message, crate::error::boxed(e))
            })?;
        }

        if let Some(codepoint) = config.alps.filter(|_| !force_h1_only) {
            cfg.set_alps_use_new_codepoint(codepoint == AlpsCodepoint::New);

            let alps_settings: [u8; 6] = [0x00, 0x09, 0x00, 0x00, 0x00, 0x01];
            let proto = b"h2";
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

fn offered_psk(ssl: &SslRef, quic: bool) -> Option<OfferedPsk> {
    let session = ssl
        .session()
        .filter(|s| s.protocol_version() == SslVersion::TLS1_3)?;
    let ptr = session as *const btls::ssl::SslSessionRef as *const std::ffi::c_void;
    let mut ticket: *const u8 = std::ptr::null();
    let mut ticket_len = 0usize;
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
        binder_len: if cipher == Some(0x1302) { 48 } else { 32 },
        early_data: quic,
    })
}

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

pub fn shuffle_client_trust_anchors(config: &mut TlsConfig) {
    use rand::seq::SliceRandom;

    if config.trust_anchor_order == TrustAnchorOrder::ShuffledPerClient {
        if let Some(ids) = &mut config.trust_anchor_ids {
            ids.shuffle(&mut rand::rng());
        }
    }
}

pub fn draw_server_padding(profile: &mut crate::BrowserProfile) {
    let mut rng = rand::rng();
    let now = std::time::SystemTime::now();
    let drawn = profile
        .tls
        .server_padding_trial
        .take()
        .map(|trial| trial.draw(&mut rng, now));
    if let Some(padding) = drawn {
        profile.tls.server_padding = padding;
    }
    if let Some(tls) = profile.quic.as_mut().and_then(|q| q.tls.as_mut()) {
        if let Some(trial) = tls.server_padding_trial.take() {
            tls.server_padding = drawn.unwrap_or_else(|| trial.draw(&mut rng, now));
        }
    }
}

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
