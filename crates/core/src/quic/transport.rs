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

const SESSION_CACHE_SIZE: usize = 256;

const MAX_UDP_PAYLOAD: u16 = 65_527;

const DEFAULT_MAX_ACK_DELAY_MS: u64 = 25;

const CHROMIUM_CONNECTION_OPTIONS: (u64, &[u8]) = (0x3128, b"ORIG");

const CHROMIUM_INITIAL_RTT: u64 = 0x3127;

const DEFAULT_INITIAL_RTT: Duration = Duration::from_millis(100);

const CHROMIUM_CACHED_RTT: (Duration, Duration) =
    (Duration::from_millis(10), Duration::from_secs(1));

const NEQO_RESET_STREAM_AT: (u64, &[u8]) = (0x1d, b"");

const NEQO_MIN_ACK_DELAY: u64 = 0xff02_de1a;

const APPLE_PARAMETER_CYCLE: &[u64] = &[0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0e, 0x0f];

const APPLE_CRYPTO_CHUNK: u16 = 999;

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

mod setting {
    pub const QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
    pub const MAX_FIELD_SECTION_SIZE: u64 = 0x06;
    pub const QPACK_BLOCKED_STREAMS: u64 = 0x07;
    pub const ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
    pub const H3_DATAGRAM: u64 = 0x33;
    pub const H3_DATAGRAM_DRAFT04: u64 = 0xff_d277;
    pub const ENABLE_WEBTRANSPORT_DRAFT02: u64 = 0x2b60_3742;
}

pub struct QuicSetup {
    config: QuicConfig,
    endpoint: EndpointConfig,
    token_store: Arc<dyn TokenStore>,
    transport: Arc<TransportConfig>,
    crypto: Arc<QuicBtlsConfig>,
    tls: Arc<TlsConfig>,
    http3: h3fp::ClientFingerprint,
    peer_settings: Mutex<HashMap<String, h3fp::PeerSettings>>,
    tickets: Option<Arc<TicketCache>>,
    server_rtts: Mutex<HashMap<(String, u16), Duration>>,
}

impl QuicSetup {
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

    pub(crate) fn http3(&self) -> &h3fp::ClientFingerprint {
        &self.http3
    }

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

    pub(crate) fn splits_cookies(&self) -> bool {
        matches!(self.config.stack, QuicStack::Chromium | QuicStack::Apple)
    }

    pub(crate) fn sends_early_requests(&self) -> bool {
        self.config.stack != QuicStack::Apple
    }

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

    pub(crate) fn peer_settings(&self, host: &str) -> Option<h3fp::PeerSettings> {
        crate::util::lock_recover(&self.peer_settings)
            .get(host)
            .cloned()
    }

    pub(crate) fn remember_peer_settings(&self, host: &str, settings: h3fp::PeerSettings) {
        let mut remembered = crate::util::lock_recover(&self.peer_settings);
        if remembered.len() >= SESSION_CACHE_SIZE && !remembered.contains_key(host) {
            remembered.clear();
        }
        remembered.insert(host.to_string(), settings);
    }
}

fn crypto_config(
    tls: &TlsConfig,
    session_cache: Arc<dyn SessionCache>,
) -> Result<QuicBtlsConfig, Error> {
    let mut builder = SslContextBuilder::new(SslMethod::tls())?;
    crate::tls::connector::apply_fingerprint(&mut builder, tls)?;
    let mut crypto = QuicBtlsConfig::from_builder(builder).map_err(|e| {
        let message = format!("QUIC crypto error: {e}");
        Error::Quic(message, crate::error::boxed(e))
    })?;
    crypto.verify_peer(!tls.danger_accept_invalid_certs);
    crypto.set_session_cache(session_cache);
    Ok(crypto)
}

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

fn endpoint_config(config: &QuicConfig) -> Result<EndpointConfig, Error> {
    let mut endpoint = quinn_btls::helpers::default_endpoint_config();
    endpoint.grease_quic_bit(false);
    let max_udp_payload = config.max_udp_payload_size.map_or(MAX_UDP_PAYLOAD, |v| {
        v.clamp(1200, u64::from(MAX_UDP_PAYLOAD)) as u16
    });
    endpoint
        .max_udp_payload_size(max_udp_payload)
        .map_err(|e| {
            let message = format!("Invalid max_udp_payload_size: {e}");
            Error::Quic(message, crate::error::boxed(e))
        })?;
    let (versions, len) = match config.stack {
        QuicStack::Chromium => (vec![1], 0),
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
    transport.datagram_receive_buffer_size(
        config
            .max_datagram_frame_size
            .map(|size| usize::try_from(size).unwrap_or(usize::MAX)),
    );
    transport.max_datagram_frame_size(config.max_datagram_frame_size.map(varint));
    transport.transport_parameter_layout(parameter_layout(config, cached_rtt)?);
    let initial_rtt = match (config.stack, cached_rtt) {
        (QuicStack::Chromium, Some(rtt)) => rtt.clamp(CHROMIUM_CACHED_RTT.0, CHROMIUM_CACHED_RTT.1),
        (QuicStack::Neqo | QuicStack::Apple, Some(rtt)) => rtt,
        (_, None) => DEFAULT_INITIAL_RTT,
    };
    transport.initial_rtt(initial_rtt);

    transport.initial_mtu(config.max_datagram_size);
    transport.mtu_discovery_config(None);
    transport.allow_spin(config.stack == QuicStack::Apple);
    transport.fingerprint(fingerprint(config.stack, config.max_datagram_size));

    transport.enable_segmentation_offload(false);
    transport.keep_alive_interval(config.keep_alive_ms.map(Duration::from_millis));
    transport.keep_alive_only_with_open_bidi_streams(true);
    Ok(transport)
}

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

fn fingerprint(stack: QuicStack, size: u16) -> FingerprintConfig {
    let mut fingerprint = FingerprintConfig::default();
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
            .coalesce_packets(false)
            .buffered_packet_processing(quinn::BufferedPacketProcessing::Immediate),
    };
    fingerprint
}

fn neqo_first_initial(rng: &mut dyn RngCore) -> u64 {
    let mut r = [0u8; 2];
    rng.fill_bytes(&mut r);
    1 + u64::from(r[0] & 0x1f) + (u64::from(r[1].saturating_sub(224)) << 5)
}

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
    fn resumable(&self, host: &str) -> Option<u32> {
        let version = *crate::util::lock_recover(&self.newest).get(host)?;
        self.sessions
            .get(quinn_btls::session_cache_key(host, version))
            .map(|_| version)
    }
}

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

const MAX_CID_LEN: usize = 20;

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
