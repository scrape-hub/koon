//! QUIC connections with a profile's fingerprint (see [`QuicConfig`]).
//!
//! Each connection gets its own UDP socket and quinn endpoint (matching real browsers);
//! [`QuicSetup`] holds what connections share: transport config, TLS context, tokens and per-host
//! 0-RTT state.
//!
//! What each [`QuicStack`] does differently, driven from `fingerprint()` and
//! `parameter_layout()`:
//! - **Packet numbering**: Chromium (quiche) shares one number space across all three spaces,
//!   starting at 1; Neqo starts its first Initial at a small random number (1-1024, below 33 seven
//!   times out of eight: `neqo_first_initial`); Apple starts every space at a fixed 0.
//! - **Initial padding**: Chromium and Apple pad the first flight with PADDING frames up to the
//!   configured datagram size; Neqo instead trails zero bytes after the record
//!   (`InitialPadding::TrailingZeros`).
//! - **Crypto framing**: Chromium's CRYPTO frames use chaos protection (reordered, overlapping
//!   fragments); Neqo slices at the SNI boundary; Apple chunks the ClientHello into
//!   `APPLE_CRYPTO_CHUNK`-byte frames, one per Initial.
//! - **Transport-parameter order**: Chromium randomizes it on every handshake and GREASEs one
//!   extra parameter; Neqo writes a fixed order (`NEQO_PARAMETER_ORDER`) with no GREASE; Apple
//!   cycles a fixed rotation (`APPLE_PARAMETER_CYCLE`) from a random start each connection, also
//!   with no GREASE. Only Chromium sends `google_connection_options`/`google_initial_rtt`; only
//!   Neqo sends `min_ack_delay` and, when enabled, `reset_stream_at`; only Apple sets
//!   `connection_id_limit_with_empty_cid`.
//! - **ACK policy**: Chromium acks every datagram under quiche's policy plus ack decimation; Neqo
//!   and Apple ack every datagram too, under the RFC 9000 standard policy, with no decimation.
//! - **Coalescing**: Chromium and Neqo coalesce everything that can go out in one flight (e.g. the
//!   reply to a resumed handshake); Apple never coalesces: a handshake ACK, the Finished and the
//!   first 1-RTT data each go in a datagram of their own.
//! - **Connection IDs**: Chromium and Apple use a fixed 8-byte length; Neqo's own length varies
//!   (`5 + (v & (v >> 4))`, floored at 8), and it alone offers 0-length client IDs and, from
//!   Firefox 155, QUIC v2 alongside v1.
//!
//! All keep a connection alive only while a request is open, do no path MTU discovery and do not
//! update keys early. The Apple column follows Safari captures from macOS 14.7 to 27.0 and iOS
//! 17.0.1 to 27.0; its ACK timing and handling of a Retry or a lost packet are not modeled.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use btls::ssl::{SslContextBuilder, SslMethod};
use bytes::Bytes;
use quinn::{
    AckDecimation, ClientConfig, ConnectionId, ConnectionIdGenerator, Endpoint, EndpointConfig,
    FingerprintConfig, TokenMemoryCache, TokenStore, TransportConfig, TransportParameterLayout,
    TransportParameterOrder, VarInt,
};
use quinn_btls::{
    ClientConfig as QuicBtlsConfig, NoSessionCache, PerConnectionConfig, SessionCache, SimpleCache,
};
use rand::{Rng, RngCore};

use h3::fingerprint as h3fp;

use super::config::{QuicConfig, QuicStack};
use crate::error::Error;
use crate::http2::config::PseudoHeader;
use crate::tls::config::TlsConfig;

/// TLS sessions kept for resumption, keyed by server name (quinn-btls).
const SESSION_CACHE_SIZE: usize = 256;

/// Largest `max_udp_payload_size` (RFC 9000 §18.2) and quinn's "not sent" value.
const MAX_UDP_PAYLOAD: u16 = 65_527;

/// The max_ack_delay that is not sent (RFC 9000 §18.2).
const DEFAULT_MAX_ACK_DELAY_MS: u64 = 25;

/// google_connection_options (0x3128): `ORIG`, sent by Chrome/Edge/Opera on page loads.
const CHROMIUM_CONNECTION_OPTIONS: (u64, &[u8]) = (0x3128, b"ORIG");

/// google_initial_rtt (0x3127): the last connection's smoothed RTT in microseconds, sent on the
/// next one.
const CHROMIUM_INITIAL_RTT: u64 = 0x3127;

/// RTT assumed before any sample: quiche's `kInitialRttMs`, neqo's `DEFAULT_INITIAL_RTT` (quinn's
/// default is 333 ms).
const DEFAULT_INITIAL_RTT: Duration = Duration::from_millis(100);

/// Bounds quiche clamps a cached RTT to when starting from it.
const CHROMIUM_CACHED_RTT: (Duration, Duration) =
    (Duration::from_millis(10), Duration::from_secs(1));

/// reset_stream_at (draft-ietf-quic-reliable-stream-reset), empty
/// ([`QuicConfig::reset_stream_at`]); quinn delivers it as a plain RESET_STREAM.
const NEQO_RESET_STREAM_AT: (u64, &[u8]) = (0x1d, b"");

/// min_ack_delay of draft-ietf-quic-ack-frequency-02, as Firefox sends it. koon does not implement
/// that draft's IMMEDIATE_ACK frame.
const NEQO_MIN_ACK_DELAY: u64 = 0xff02_de1a;

/// Safari's transport parameters, in this cyclic order from a random start; its private parameter
/// (`0xff080808`) follows them.
const APPLE_PARAMETER_CYCLE: &[u64] = &[0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0e, 0x0f];

/// Most ClientHello bytes Safari puts in one Initial packet.
const APPLE_CRYPTO_CHUNK: u16 = 999;

/// Transport parameters in the order neqo writes them (its parameter enum); the others follow in
/// ascending order of their ids.
const NEQO_PARAMETER_ORDER: &[u64] = &[
    0x01,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
    0x09,
    0x0b,
    0x0e,
    0x0f,
    0x11,
    0x1d,
    NEQO_MIN_ACK_DELAY,
    0x20,
];

/// HTTP/3 settings (RFC 9114 §7.2.4.1 and extensions) the stacks send besides the profile's values.
mod setting {
    pub const QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
    pub const MAX_FIELD_SECTION_SIZE: u64 = 0x06;
    pub const QPACK_BLOCKED_STREAMS: u64 = 0x07;
    pub const ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
    pub const H3_DATAGRAM: u64 = 0x33;
    pub const H3_DATAGRAM_DRAFT04: u64 = 0xff_d277;
    pub const ENABLE_WEBTRANSPORT_DRAFT02: u64 = 0x2b60_3742;
}

/// What the QUIC connections of a client share. Built on first use.
pub struct QuicSetup {
    config: QuicConfig,
    endpoint: EndpointConfig,
    token_store: Arc<dyn TokenStore>,
    transport: Arc<TransportConfig>,
    /// Shared by every connection; ECH is set per connection (see [`Self::client_config`]), not
    /// per context.
    crypto: Arc<QuicBtlsConfig>,
    /// The profile's ClientHello, applied per connection (see [`Self::client_config`]) with that
    /// connection's own ECH config instead of a host-keyed lookup in shared state, which two
    /// in-flight connections to the same host (or a GREASE and a real-ECH one racing) could
    /// otherwise overwrite or clear early.
    tls: Arc<TlsConfig>,
    /// The profile's HTTP/3 layer, as h3 takes it.
    http3: h3fp::ClientFingerprint,
    /// The server's last HTTP/3 settings per name, for 0-RTT requests.
    peer_settings: Mutex<HashMap<String, h3fp::PeerSettings>>,
    /// TLS sessions for resumption; `None` without resumption.
    tickets: Option<Arc<TicketCache>>,
    /// Smoothed RTT of the last connection per origin, which the next one starts from (Chromium's
    /// `ServerNetworkStats`, neqo's ticket RTT).
    server_rtts: Mutex<HashMap<(String, u16), Duration>>,
}

impl QuicSetup {
    /// `tcp_tls` supplies the ClientHello when the profile has none, and the cert-verification
    /// setting either way.
    pub(crate) fn new(
        config: &QuicConfig,
        tcp_tls: &TlsConfig,
        session_resumption: bool,
    ) -> Result<Self, Error> {
        let mut tls = config.tls.clone().unwrap_or_else(|| tcp_tls.clone());
        tls.danger_accept_invalid_certs = tcp_tls.danger_accept_invalid_certs;
        let tls = Arc::new(tls);
        let tickets = (session_resumption && config.session_resumption)
            .then(|| Arc::new(TicketCache::default()));
        let session_cache: Arc<dyn SessionCache> = match &tickets {
            Some(tickets) => tickets.clone(),
            None => Arc::new(NoSessionCache),
        };
        Ok(Self {
            config: config.clone(),
            endpoint: endpoint_config(config)?,
            // Chrome and Firefox both present NEW_TOKEN tokens when they reconnect.
            token_store: Arc::new(TokenMemoryCache::default()),
            transport: Arc::new(transport_config(config, None)?),
            crypto: Arc::new(crypto_config(&tls, session_cache)?),
            tls,
            http3: client_fingerprint(config),
            peer_settings: Mutex::default(),
            tickets,
            server_rtts: Mutex::default(),
        })
    }

    /// The HTTP/3 fingerprint of the connections.
    pub(crate) fn http3(&self) -> &h3fp::ClientFingerprint {
        &self.http3
    }

    /// The order h3 writes the pseudo-headers in.
    pub(crate) fn pseudo_header_order(&self) -> &'static [PseudoHeader] {
        match self.config.stack {
            QuicStack::Chromium => &[
                PseudoHeader::Method,
                PseudoHeader::Authority,
                PseudoHeader::Scheme,
                PseudoHeader::Path,
            ],
            QuicStack::Neqo | QuicStack::Apple => &[
                PseudoHeader::Method,
                PseudoHeader::Scheme,
                PseudoHeader::Authority,
                PseudoHeader::Path,
            ],
        }
    }

    /// Whether each cookie goes as a field of its own (quiche, Safari; RFC 9114 §4.2.1).
    pub(crate) fn splits_cookies(&self) -> bool {
        matches!(self.config.stack, QuicStack::Chromium | QuicStack::Apple)
    }

    /// Whether requests go out as 0-RTT data (Safari sends only SETTINGS early).
    pub(crate) fn sends_early_requests(&self) -> bool {
        self.config.stack != QuicStack::Apple
    }

    /// Client config for a new connection to `host`:`port`; `ech_config_list` comes from its DNS
    /// HTTPS record if reachable (`None` GREASEs). Chromium starts from the origin's last RTT, neqo
    /// resumes its newest ticket's QUIC version and RTT.
    pub(crate) fn client_config(
        &self,
        host: &str,
        port: u16,
        ech_config_list: Option<&[u8]>,
    ) -> Result<ClientConfig, Error> {
        let rtt = crate::util::lock_recover(&self.server_rtts)
            .get(&(host.to_string(), port))
            .copied();
        let (version, rtt) = match self.config.stack {
            QuicStack::Chromium => (1, rtt),
            QuicStack::Apple => (1, None),
            QuicStack::Neqo => match self.tickets.as_ref().and_then(|t| t.resumable(host)) {
                Some(version) => {
                    let millis = rtt.map(|rtt| {
                        Duration::from_millis(u64::try_from(rtt.as_millis()).unwrap_or(u64::MAX))
                    });
                    (
                        version,
                        millis.filter(|rtt| *rtt >= Duration::from_millis(1)),
                    )
                }
                None => (1, None),
            },
        };
        let transport = match rtt {
            Some(rtt) => Arc::new(transport_config(&self.config, Some(rtt))?),
            None => self.transport.clone(),
        };
        // `crypto` is the SSL_CTX shared by every connection; this connection's own ECH config
        // (or its absence, which GREASEs) is carried into quinn-btls as this connection's own
        // configuration instead of shared, per-client state, which two in-flight connections to
        // the same host (or a GREASE and a real-ECH one racing) could otherwise overwrite or
        // clear early.
        let tls = self.tls.clone();
        let stack = self.config.stack;
        let ech_config_list = ech_config_list.map(<[u8]>::to_vec);
        let per_connection =
            PerConnectionConfig::new(self.crypto.clone(), move |ssl, host, params| {
                crate::tls::connector::configure_quic_ssl(
                    ssl,
                    &tls,
                    host,
                    ech_config_list.as_deref(),
                )
                .map_err(|e| {
                    quinn_btls::Error::IoError(std::io::Error::other(format!(
                        "configuring the QUIC ClientHello: {e}"
                    )))
                })?;
                // Firefox's ECH ClientHelloOuter carries a reduced transport-parameter set (Chrome's
                // outer keeps the full set); only with a real ECH config, since GREASE ECH never
                // splits the hello.
                if stack == QuicStack::Neqo && ech_config_list.is_some() {
                    let mut outer = Vec::new();
                    params.write_ech_outer(&mut outer);
                    ssl.set_quic_transport_params_outer(&outer).map_err(|e| {
                        quinn_btls::Error::IoError(std::io::Error::other(format!(
                            "configuring the QUIC ClientHelloOuter transport parameters: {e}"
                        )))
                    })?;
                }
                Ok(())
            });
        let mut client = ClientConfig::new(Arc::new(per_connection));
        client.version(version);
        client.transport_config(transport);
        client.token_store(self.token_store.clone());
        client.initial_dst_cid_provider(Arc::new(move || initial_dcid(stack)));
        Ok(client)
    }

    /// Remember the smoothed RTT of a connection that ends, or forget it with `None` (handshake
    /// never confirmed).
    pub(crate) fn remember_rtt(&self, host: &str, port: u16, rtt: Option<Duration>) {
        let mut rtts = crate::util::lock_recover(&self.server_rtts);
        let key = (host.to_string(), port);
        match rtt {
            Some(rtt) => {
                if rtts.len() >= SESSION_CACHE_SIZE && !rtts.contains_key(&key) {
                    rtts.clear();
                }
                rtts.insert(key, rtt);
            }
            None => {
                rtts.remove(&key);
            }
        }
    }

    /// An endpoint for one connection, on a new UDP socket bound to `bind`; it lives as long as its
    /// connection.
    pub(crate) fn endpoint(&self, bind: SocketAddr) -> Result<Endpoint, Error> {
        let socket = std::net::UdpSocket::bind(bind).map_err(|e| {
            let message = format!("Failed to bind UDP socket: {e}");
            Error::Quic(message, crate::error::boxed(e))
        })?;
        Endpoint::new(
            self.endpoint.clone(),
            None,
            socket,
            quinn::default_runtime()
                .ok_or_else(|| Error::Quic("No async runtime available".into(), None))?,
        )
        .map_err(|e| {
            let message = format!("Failed to create QUIC endpoint: {e}");
            Error::Quic(message, crate::error::boxed(e))
        })
    }

    /// The HTTP/3 settings `host` sent last time, for 0-RTT.
    pub(crate) fn peer_settings(&self, host: &str) -> Option<h3fp::PeerSettings> {
        crate::util::lock_recover(&self.peer_settings)
            .get(host)
            .cloned()
    }

    /// Remember the HTTP/3 settings of `host`.
    pub(crate) fn remember_peer_settings(&self, host: &str, settings: h3fp::PeerSettings) {
        let mut remembered = crate::util::lock_recover(&self.peer_settings);
        if remembered.len() >= SESSION_CACHE_SIZE && !remembered.contains_key(host) {
            remembered.clear();
        }
        remembered.insert(host.to_string(), settings);
    }
}

/// The TLS context shared by every QUIC connection of a client: the profile's ClientHello, minus
/// the per-connection parts (ALPS, ECH, key shares), which [`QuicSetup::client_config`] attaches
/// through quinn-btls's [`PerConnectionConfig`] instead: real ECH does not need its own context,
/// only its own `Ssl` (see [`crate::tls::connector::configure_quic_ssl`]).
fn crypto_config(
    tls: &TlsConfig,
    session_cache: Arc<dyn SessionCache>,
) -> Result<QuicBtlsConfig, Error> {
    let mut builder = SslContextBuilder::new(SslMethod::tls())?;
    crate::tls::connector::apply_fingerprint(&mut builder, tls)?;
    // from_builder() enforces TLS 1.3, sets ALPN `h3` and enables early data; it leaves peer
    // verification as the builder configured it (none, here), so this sets the default itself.
    let mut crypto = QuicBtlsConfig::from_builder(builder).map_err(|e| {
        let message = format!("QUIC crypto error: {e}");
        Error::Quic(message, crate::error::boxed(e))
    })?;
    crypto.verify_peer(!tls.danger_accept_invalid_certs);
    crypto.set_session_cache(session_cache);
    Ok(crypto)
}

/// The HTTP/3 layer of the stack (h3's browser presets), with the profile's SETTINGS values.
fn client_fingerprint(config: &QuicConfig) -> h3fp::ClientFingerprint {
    let capacity = (config.qpack_max_table_capacity > 0).then_some((
        setting::QPACK_MAX_TABLE_CAPACITY,
        config.qpack_max_table_capacity,
    ));
    let field_section = config
        .max_field_section_size
        .map(|size| (setting::MAX_FIELD_SECTION_SIZE, size));
    let blocked = (config.qpack_blocked_streams > 0)
        .then_some((setting::QPACK_BLOCKED_STREAMS, config.qpack_blocked_streams));
    let (mut fingerprint, extra) = match config.stack {
        // quiche sorts its settings by identifier.
        QuicStack::Chromium => (
            h3fp::ClientFingerprint::chrome(),
            &[(setting::H3_DATAGRAM, 1)][..],
        ),
        QuicStack::Neqo => (
            h3fp::ClientFingerprint::firefox(),
            &[
                (setting::ENABLE_WEBTRANSPORT_DRAFT02, 0),
                (setting::H3_DATAGRAM_DRAFT04, 1),
                (setting::H3_DATAGRAM, 1),
                (setting::ENABLE_CONNECT_PROTOCOL, 1),
            ][..],
        ),
        QuicStack::Apple => (h3fp::ClientFingerprint::safari(), &[][..]),
    };
    fingerprint.settings = [capacity, field_section, blocked]
        .into_iter()
        .flatten()
        .chain(extra.iter().copied())
        .collect();
    fingerprint
}

/// Endpoint settings: the client's own connection IDs, and the transport parameters quinn takes
/// from the endpoint.
fn endpoint_config(config: &QuicConfig) -> Result<EndpointConfig, Error> {
    let mut endpoint = quinn_btls::helpers::default_endpoint_config();
    endpoint.grease_quic_bit(false);
    // quinn omits the parameter at its maximum: Firefox does not send it.
    let max_udp_payload = config.max_udp_payload_size.map_or(MAX_UDP_PAYLOAD, |v| {
        v.clamp(1200, u64::from(MAX_UDP_PAYLOAD)) as u16
    });
    endpoint
        .max_udp_payload_size(max_udp_payload)
        .map_err(|e| {
            let message = format!("Invalid max_udp_payload_size: {e}");
            Error::Quic(message, crate::error::boxed(e))
        })?;
    // `len`: the client's own connection ID length (0 for Chromium/Apple, 3 for Firefox).
    let (versions, len) = match config.stack {
        QuicStack::Chromium => (vec![1], 0),
        // Firefox ≥155 also offers QUIC v2 (RFC 9368); quinn keeps ≤154 on v1 only.
        QuicStack::Neqo if config.quic_v2 => (vec![1, quinn::QUIC_VERSION_2], 3),
        QuicStack::Neqo => (vec![1], 3),
        QuicStack::Apple => (vec![1], 0),
    };
    endpoint.supported_versions(versions);
    endpoint.cid_generator(move || Box::new(RandomCids { len }));
    Ok(endpoint)
}

fn varint(value: u64) -> VarInt {
    VarInt::from_u64(value).unwrap_or(VarInt::MAX)
}

fn invalid(what: &str) -> impl Fn(quinn::ConfigError) -> Error + '_ {
    move |e| {
        let message = format!("QUIC {what}: {e}");
        Error::Config(message, crate::error::boxed(e))
    }
}

/// Transport settings of the connections of a client. `cached_rtt` is the RTT of the origin's last
/// connection that a new one starts from.
fn transport_config(
    config: &QuicConfig,
    cached_rtt: Option<Duration>,
) -> Result<TransportConfig, Error> {
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(
        (config.max_idle_timeout_ms > 0).then(|| varint(config.max_idle_timeout_ms).into()),
    );
    transport.receive_window(varint(config.initial_max_data));
    transport.stream_receive_window(varint(config.initial_max_stream_data_bidi_local));
    transport
        .stream_receive_window_bidi_local(Some(varint(config.initial_max_stream_data_bidi_local)));
    transport.stream_receive_window_bidi_remote(Some(varint(
        config.initial_max_stream_data_bidi_remote,
    )));
    transport.stream_receive_window_uni(Some(varint(config.initial_max_stream_data_uni)));
    transport.max_concurrent_bidi_streams(varint(config.initial_max_streams_bidi));
    transport.max_concurrent_uni_streams(varint(config.initial_max_streams_uni));
    if let Some(ms) = config
        .max_ack_delay_ms
        .filter(|ms| *ms != DEFAULT_MAX_ACK_DELAY_MS)
    {
        transport.max_ack_delay(Duration::from_millis(ms));
    }
    transport.active_connection_id_limit(
        config
            .active_connection_id_limit
            .map(|n| u32::try_from(n).unwrap_or(u32::MAX)),
    );
    // The receive buffer holds at least one frame of the advertised size.
    transport.datagram_receive_buffer_size(
        config
            .max_datagram_frame_size
            .map(|size| usize::try_from(size).unwrap_or(usize::MAX)),
    );
    transport.max_datagram_frame_size(config.max_datagram_frame_size.map(varint));
    transport.transport_parameter_layout(parameter_layout(config, cached_rtt)?);
    // quiche clamps a cached RTT to bounds; neqo takes its resumption token's RTT as is.
    let initial_rtt = match (config.stack, cached_rtt) {
        (QuicStack::Chromium, Some(rtt)) => rtt.clamp(CHROMIUM_CACHED_RTT.0, CHROMIUM_CACHED_RTT.1),
        (QuicStack::Neqo | QuicStack::Apple, Some(rtt)) => rtt,
        (_, None) => DEFAULT_INITIAL_RTT,
    };
    transport.initial_rtt(initial_rtt);

    // The first flight is padded to this size and, without MTU discovery, no datagram grows beyond
    // it; a larger Initial would be dropped on small-MTU paths, stalling the handshake until a
    // probe timeout.
    transport.initial_mtu(config.max_datagram_size);
    transport.mtu_discovery_config(None);
    // Safari spins the latency bit (RFC 9000 §17.4), the others do not.
    transport.allow_spin(config.stack == QuicStack::Apple);
    transport.fingerprint(fingerprint(config.stack, config.max_datagram_size));

    // Segmentation offload pads datagrams beyond what browsers send; on Windows it can drop a split
    // first flight until a ~1s retransmission, well after TCP would win the race.
    transport.enable_segmentation_offload(false);
    // Browsers PING only while a request is open, letting an idle connection end at its idle
    // timeout.
    transport.keep_alive_interval(config.keep_alive_ms.map(Duration::from_millis));
    transport.keep_alive_only_with_open_bidi_streams(true);
    Ok(transport)
}

/// Which optional transport parameters are sent, and in which order.
fn parameter_layout(
    config: &QuicConfig,
    cached_rtt: Option<Duration>,
) -> Result<TransportParameterLayout, Error> {
    let mut layout = TransportParameterLayout::default();
    let (versions, extra) = match config.stack {
        QuicStack::Chromium => {
            layout.order(TransportParameterOrder::Random);
            layout.grease(true);
            layout
                .min_ack_delay(None)
                .map_err(invalid("min_ack_delay"))?;
            // quiche inserts the reserved version at a random index.
            let mut versions = quinn::VersionInformation::new(vec![1]);
            versions.grease(quinn::GreaseVersion::Random);
            (Some(versions), Some(CHROMIUM_CONNECTION_OPTIONS))
        }
        QuicStack::Neqo => {
            layout.order(TransportParameterOrder::Fixed(
                NEQO_PARAMETER_ORDER.iter().copied().map(varint).collect(),
            ));
            layout.grease(false);
            layout
                .min_ack_delay(Some(varint(NEQO_MIN_ACK_DELAY)))
                .map_err(invalid("min_ack_delay"))?;
            // GREASE, v2, v1 from Firefox 155 on; GREASE, v1 before.
            let offered = if config.quic_v2 {
                vec![quinn::QUIC_VERSION_2, 1]
            } else {
                vec![1]
            };
            let mut versions = quinn::VersionInformation::new(offered);
            versions.grease(quinn::GreaseVersion::At(0));
            (
                Some(versions),
                config.reset_stream_at.then_some(NEQO_RESET_STREAM_AT),
            )
        }
        QuicStack::Apple => {
            // Unlisted parameters, the private one included, follow the cycle.
            layout.order(TransportParameterOrder::Rotated(
                APPLE_PARAMETER_CYCLE.iter().copied().map(varint).collect(),
            ));
            layout.grease(false);
            layout.connection_id_limit_with_empty_cid(true);
            layout
                .min_ack_delay(None)
                .map_err(invalid("min_ack_delay"))?;
            (None, None)
        }
    };
    if let Some(versions) = versions {
        layout
            .version_information(Some(versions))
            .map_err(invalid("version_information"))?;
    }
    if let Some((id, value)) = extra {
        layout
            .extra_parameter(varint(id), value.to_vec())
            .map_err(invalid("transport parameter"))?;
    }
    if let (QuicStack::Chromium, Some(rtt)) = (config.stack, cached_rtt) {
        let micros = u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX);
        layout
            .extra_parameter(varint(CHROMIUM_INITIAL_RTT), encode_varint(micros))
            .map_err(invalid("google_initial_rtt"))?;
    }
    for (id, value) in &config.extra_transport_parameters {
        layout
            .extra_parameter(varint(*id), value.clone())
            .map_err(invalid("transport parameter"))?;
    }
    Ok(layout)
}

/// `value` as a QUIC variable-length integer of the shortest length (RFC 9000 §16).
fn encode_varint(value: u64) -> Vec<u8> {
    match value {
        0..=0x3f => vec![value as u8],
        0x40..=0x3fff => (value as u16 | 0x4000).to_be_bytes().to_vec(),
        0x4000..=0x3fff_ffff => (value as u32 | 0x8000_0000).to_be_bytes().to_vec(),
        _ => (value.min(0x3fff_ffff_ffff_ffff) | 0xc000_0000_0000_0000)
            .to_be_bytes()
            .to_vec(),
    }
}

/// Wire behaviour of the packet layer.
fn fingerprint(stack: QuicStack, size: u16) -> FingerprintConfig {
    let mut fingerprint = FingerprintConfig::default();
    // Both coalesce what goes out at once, e.g. the reply to a resumed handshake's flight.
    fingerprint.early_key_update(false).coalesce_packets(true);
    match stack {
        QuicStack::Chromium => fingerprint
            .packet_numbering(quinn::PacketNumbering::Shared { first: 1 })
            .initial_padding(quinn::InitialPadding::Frames { size })
            .crypto_framing(quinn::CryptoFraming::ChaosProtection)
            .spin_bit(quinn::SpinBit::Zero)
            .grease_fixed_bit(false)
            .ack_decimation(Some(AckDecimation::default()))
            .ack_policy(quinn::AckPolicy::Quiche)
            .ack_each_datagram(true)
            .early_connection_ids(false)
            .packet_padding(quinn::PacketPadding::Leading)
            .trailing_ping(true)
            .buffered_packet_processing(quinn::BufferedPacketProcessing::AfterFirst1rttData)
            // quiche writes the control stream on 1-RTT keys, sharing the Finished's datagram.
            .finished_with_first_data(true),
        QuicStack::Neqo => fingerprint
            .packet_numbering(quinn::PacketNumbering::Sequential {
                first_initial: quinn::FirstPacketNumber::Random(Arc::new(neqo_first_initial)),
            })
            .initial_padding(quinn::InitialPadding::TrailingZeros { size })
            .crypto_framing(quinn::CryptoFraming::SniSlicing)
            .spin_bit(quinn::SpinBit::Random)
            .grease_fixed_bit(true)
            .ack_decimation(None)
            .ack_policy(quinn::AckPolicy::Standard)
            .ack_each_datagram(true)
            .early_connection_ids(true)
            .packet_padding(quinn::PacketPadding::Standard)
            .trailing_ping(true)
            .buffered_packet_processing(quinn::BufferedPacketProcessing::Immediate),
        QuicStack::Apple => fingerprint
            .packet_numbering(quinn::PacketNumbering::Sequential {
                first_initial: quinn::FirstPacketNumber::Fixed(0),
            })
            .initial_padding(quinn::InitialPadding::Frames { size })
            .crypto_framing(quinn::CryptoFraming::Chunked {
                max: APPLE_CRYPTO_CHUNK,
            })
            .spin_bit(quinn::SpinBit::Standard)
            .grease_fixed_bit(false)
            .ack_decimation(None)
            .ack_policy(quinn::AckPolicy::Standard)
            .ack_each_datagram(true)
            .early_connection_ids(false)
            .packet_padding(quinn::PacketPadding::Standard)
            // Every packet in a datagram of its own (handshake ACKs, Finished, first 1-RTT data).
            .coalesce_packets(false)
            .buffered_packet_processing(quinn::BufferedPacketProcessing::Immediate),
    };
    fingerprint
}

/// neqo's first Initial packet number: 1-1024, below 33 seven times out of eight.
fn neqo_first_initial(rng: &mut dyn RngCore) -> u64 {
    let mut r = [0u8; 2];
    rng.fill_bytes(&mut r);
    1 + u64::from(r[0] & 0x1f) + (u64::from(r[1].saturating_sub(224)) << 5)
}

/// quinn-btls's session cache, which also remembers the QUIC version of the newest session ticket
/// per server name.
struct TicketCache {
    sessions: SimpleCache,
    newest: Mutex<HashMap<String, u32>>,
}

impl Default for TicketCache {
    fn default() -> Self {
        Self {
            sessions: SimpleCache::new(SESSION_CACHE_SIZE),
            newest: Mutex::default(),
        }
    }
}

impl TicketCache {
    /// The QUIC version of the newest ticket of `host`, if a ticket of that version is left to
    /// offer.
    fn resumable(&self, host: &str) -> Option<u32> {
        let version = *crate::util::lock_recover(&self.newest).get(host)?;
        self.sessions
            .get(quinn_btls::session_cache_key(host, version))
            .map(|_| version)
    }
}

/// The server name and QUIC version of a key of `quinn_btls::session_cache_key`.
fn ticket_key(key: &[u8]) -> Option<(&str, u32)> {
    let (name, version) = match key.len().checked_sub(5) {
        Some(at) if key[at] == 0 => {
            let version = u32::from_be_bytes(key[at + 1..].try_into().ok()?);
            (&key[..at], version)
        }
        _ => (key, 1),
    };
    Some((std::str::from_utf8(name).ok()?, version))
}

impl SessionCache for TicketCache {
    fn put(&self, key: Bytes, value: Bytes) {
        if let Some((host, version)) = ticket_key(&key) {
            let mut newest = crate::util::lock_recover(&self.newest);
            if newest.len() >= SESSION_CACHE_SIZE && !newest.contains_key(host) {
                newest.clear();
            }
            newest.insert(host.to_string(), version);
        }
        self.sessions.put(key, value);
    }

    fn get(&self, key: Bytes) -> Option<Bytes> {
        self.sessions.get(key)
    }

    fn take(&self, key: Bytes) -> Option<Bytes> {
        self.sessions.take(key)
    }

    fn remove(&self, key: Bytes) {
        self.sessions.remove(key);
    }

    fn clear(&self) {
        crate::util::lock_recover(&self.newest).clear();
        self.sessions.clear();
    }
}

/// Longest connection ID (RFC 9000 §17.2).
const MAX_CID_LEN: usize = 20;

/// The destination connection ID of a connection's first Initial: 8 bytes (quiche), or neqo's
/// `ConnectionId::generate_initial`.
fn initial_dcid(stack: QuicStack) -> ConnectionId {
    let mut rng = rand::rng();
    let len = match stack {
        QuicStack::Chromium | QuicStack::Apple => 8,
        QuicStack::Neqo => {
            let v: u8 = rng.random();
            usize::from((5 + (v & (v >> 4))).max(8))
        }
    };
    let mut bytes = [0u8; MAX_CID_LEN];
    rng.fill_bytes(&mut bytes[..len]);
    ConnectionId::new(&bytes[..len])
}

/// Random connection IDs of a fixed length, zero included.
struct RandomCids {
    len: usize,
}

impl ConnectionIdGenerator for RandomCids {
    fn generate_cid(&mut self) -> ConnectionId {
        let mut bytes = [0u8; MAX_CID_LEN];
        rand::rng().fill_bytes(&mut bytes[..self.len]);
        ConnectionId::new(&bytes[..self.len])
    }

    fn cid_len(&self) -> usize {
        self.len
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neqo_dcid_lengths_follow_its_formula() {
        let mut seen = [0usize; MAX_CID_LEN + 1];
        for _ in 0..4000 {
            seen[initial_dcid(QuicStack::Neqo).len()] += 1;
        }
        assert!(seen[..8].iter().all(|n| *n == 0), "{seen:?}");
        assert!(seen[8] > 2000 && seen[8] < 2500, "{seen:?}");
        assert!(seen[9..].iter().sum::<usize>() > 500, "{seen:?}");
        assert_eq!(initial_dcid(QuicStack::Chromium).len(), 8);
    }

    #[test]
    fn neqo_first_initial_packet_numbers_follow_its_formula() {
        let mut rng = rand::rng();
        let numbers: Vec<u64> = (0..4000).map(|_| neqo_first_initial(&mut rng)).collect();
        assert!(numbers.iter().all(|n| (1..=1024).contains(n)));
        let small = numbers.iter().filter(|n| **n < 33).count();
        assert!(small > 3300 && small < 3700, "{small}");
    }

    #[test]
    fn ticket_keys_name_server_and_version() {
        let v1 = quinn_btls::session_cache_key("example.com", 1);
        assert_eq!(ticket_key(&v1), Some(("example.com", 1)));
        let v2 = quinn_btls::session_cache_key("example.com", quinn::QUIC_VERSION_2);
        assert_eq!(
            ticket_key(&v2),
            Some(("example.com", quinn::QUIC_VERSION_2))
        );
    }

    #[test]
    fn varints_take_the_shortest_length() {
        assert_eq!(encode_varint(37), [0x25]);
        assert_eq!(encode_varint(15_437), [0x7c, 0x4d]);
        assert_eq!(encode_varint(16_812), [0x80, 0x00, 0x41, 0xac]);
        assert_eq!(encode_varint(1 << 30).len(), 8);
    }

    #[test]
    fn http3_layers_match_the_h3_presets() {
        let http3 =
            |profile: crate::profile::BrowserProfile| client_fingerprint(&profile.quic.unwrap());
        assert_eq!(
            http3(crate::profile::Chrome::latest()),
            h3fp::ClientFingerprint::chrome()
        );
        assert_eq!(
            http3(crate::profile::Firefox::latest()),
            h3fp::ClientFingerprint::firefox()
        );
        // Every Safari release with HTTP/3 at all sends the same HTTP/3 layer (macOS 12 has no
        // QUIC support whatsoever).
        for profile in crate::profile::BrowserProfile::names()
            .filter(|p| p.browser == crate::profile::Browser::Safari)
        {
            let Some(quic) = crate::profile::BrowserProfile::resolve(&profile.name)
                .unwrap()
                .quic
            else {
                continue;
            };
            assert_eq!(
                client_fingerprint(&quic),
                h3fp::ClientFingerprint::safari(),
                "{}",
                profile.name
            );
        }
    }

    #[test]
    fn every_built_in_profile_builds_a_transport() {
        for profile in [
            crate::profile::Chrome::latest(),
            crate::profile::Firefox::latest(),
            crate::profile::Edge::latest(),
            crate::profile::Opera::latest(),
        ] {
            let quic = profile.quic.clone().unwrap();
            QuicSetup::new(&quic, &profile.tls, true).unwrap();
        }
        for name in crate::profile::BrowserProfile::names()
            .filter(|p| p.browser == crate::profile::Browser::Safari)
        {
            let profile = crate::profile::BrowserProfile::resolve(&name.name).unwrap();
            // macOS 12 has no QUIC support whatsoever.
            let Some(quic) = profile.quic.clone() else {
                continue;
            };
            let setup = QuicSetup::new(&quic, &profile.tls, true).unwrap();
            assert_eq!(setup.tickets.is_some(), quic.session_resumption);
        }
    }

    /// `into_0rtt` only succeeds when the offered ticket allows early data (Google's do); the
    /// acceptance future resolves `true` only if taken.
    #[tokio::test]
    #[ignore = "network: QUIC to www.google.com"]
    async fn test_second_connection_resumes_the_quic_session() {
        for profile in [
            crate::profile::Chrome::latest(),
            crate::profile::Firefox::latest(),
        ] {
            let quic = profile.quic.clone().expect("the profile speaks QUIC");
            let setup = QuicSetup::new(&quic, &profile.tls, true).unwrap();
            let addr = tokio::net::lookup_host(("www.google.com", 443))
                .await
                .unwrap()
                .find(std::net::SocketAddr::is_ipv4)
                .unwrap();
            let bind: SocketAddr = "0.0.0.0:0".parse().unwrap();

            let first = setup
                .endpoint(bind)
                .unwrap()
                .connect_with(
                    setup.client_config("www.google.com", 443, None).unwrap(),
                    addr,
                    "www.google.com",
                )
                .unwrap();
            let Err(first) = first.into_0rtt() else {
                panic!("no session to resume yet");
            };
            let first = first.await.unwrap();
            // The server sends its session tickets after the handshake.
            tokio::time::sleep(Duration::from_millis(500)).await;
            first.close(VarInt::from_u32(0), b"");

            let second = setup
                .endpoint(bind)
                .unwrap()
                .connect_with(
                    setup.client_config("www.google.com", 443, None).unwrap(),
                    addr,
                    "www.google.com",
                )
                .unwrap();
            let Ok((second, accepted)) = second.into_0rtt() else {
                panic!("the second connection offers no session");
            };
            assert!(accepted.await, "the server did not take the early data");
            second.close(VarInt::from_u32(0), b"");
        }
    }
}
