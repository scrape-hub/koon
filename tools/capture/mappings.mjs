// IANA → BoringSSL name mappings for TLS fingerprint conversion.
// These mappings cover all cipher suites, curves, and signature algorithms
// used by modern browsers (Chrome, Firefox, Safari, Edge).

// Cipher suites: IANA hex value → BoringSSL name
export const CIPHER_MAP = {
  // TLS 1.3 ciphers
  '1301': 'TLS_AES_128_GCM_SHA256',
  '1302': 'TLS_AES_256_GCM_SHA384',
  '1303': 'TLS_CHACHA20_POLY1305_SHA256',
  // TLS 1.2 ECDHE ciphers
  'c02b': 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
  'c02f': 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
  'c02c': 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
  'c030': 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
  'cca9': 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
  'cca8': 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
  'c009': 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
  'c00a': 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
  'c013': 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
  'c014': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
  // TLS 1.2 RSA ciphers
  '009c': 'TLS_RSA_WITH_AES_128_GCM_SHA256',
  '009d': 'TLS_RSA_WITH_AES_256_GCM_SHA384',
  '002f': 'TLS_RSA_WITH_AES_128_CBC_SHA',
  '0035': 'TLS_RSA_WITH_AES_256_CBC_SHA',
  // Aliases (some tools report with leading zeros stripped)
  '9c': 'TLS_RSA_WITH_AES_128_GCM_SHA256',
  '9d': 'TLS_RSA_WITH_AES_256_GCM_SHA384',
  '2f': 'TLS_RSA_WITH_AES_128_CBC_SHA',
  '35': 'TLS_RSA_WITH_AES_256_CBC_SHA',
};

// Named groups / curves: IANA decimal → BoringSSL name
// These come from JA3 text (decimal) and JA4_ro (hex)
export const CURVE_MAP_DECIMAL = {
  '4588': 'X25519MLKEM768',  // 0x11EC (final IANA assignment)
  '25497': 'X25519Kyber768Draft00', // 0x6399 (old draft, Chrome 124-130)
  '29': 'X25519',            // 0x001d
  '23': 'P-256',             // 0x0017
  '24': 'P-384',             // 0x0018
  '25': 'P-521',             // 0x0019
  '256': 'ffdhe2048',        // 0x0100
  '257': 'ffdhe3072',        // 0x0101
};

export const CURVE_MAP_HEX = {
  '11ec': 'X25519MLKEM768',
  '6399': 'X25519Kyber768Draft00',
  '001d': 'X25519',
  '0017': 'P-256',
  '0018': 'P-384',
  '0019': 'P-521',
  '0100': 'ffdhe2048',
  '0101': 'ffdhe3072',
  '1d': 'X25519',
  '17': 'P-256',
  '18': 'P-384',
  '19': 'P-521',
};

// Signature algorithms: IANA hex → BoringSSL name
export const SIGALG_MAP = {
  '0403': 'ecdsa_secp256r1_sha256',
  '0503': 'ecdsa_secp384r1_sha384',
  '0603': 'ecdsa_secp521r1_sha512',
  '0804': 'rsa_pss_rsae_sha256',
  '0805': 'rsa_pss_rsae_sha384',
  '0806': 'rsa_pss_rsae_sha512',
  '0401': 'rsa_pkcs1_sha256',
  '0501': 'rsa_pkcs1_sha384',
  '0601': 'rsa_pkcs1_sha512',
  '0203': 'ecdsa_sha1',
  '0201': 'rsa_pkcs1_sha1',
  // Short forms
  '403': 'ecdsa_secp256r1_sha256',
  '503': 'ecdsa_secp384r1_sha384',
  '603': 'ecdsa_secp521r1_sha512',
  '804': 'rsa_pss_rsae_sha256',
  '805': 'rsa_pss_rsae_sha384',
  '806': 'rsa_pss_rsae_sha512',
  '401': 'rsa_pkcs1_sha256',
  '501': 'rsa_pkcs1_sha384',
  '601': 'rsa_pkcs1_sha512',
  '203': 'ecdsa_sha1',
  '201': 'rsa_pkcs1_sha1',
};

// TLS extension IDs → feature flag implications
export const EXTENSION_FLAGS = {
  0:     'sni',                       // Server Name Indication
  5:     'ocsp_stapling',             // OCSP Status Request
  10:    'supported_groups',          // Elliptic curves
  11:    'ec_point_formats',          // EC point formats
  13:    'signature_algorithms',      // Signature algorithms
  16:    'alpn',                      // Application-Layer Protocol Negotiation
  17:    'extended_master_secret',    // (TLS 1.2)
  18:    'signed_cert_timestamps',    // Certificate Transparency (SCT)
  23:    'extended_master_secret',    // Extended Master Secret
  27:    'compress_certificate',      // Certificate Compression
  34:    'delegated_credentials',     // Delegated Credentials
  35:    'session_ticket',            // Session Ticket
  41:    'pre_shared_key',            // Pre-Shared Key
  43:    'supported_versions',        // Supported Versions
  45:    'psk_key_exchange_modes',    // PSK Key Exchange Modes
  51:    'key_share',                 // Key Share
  17513: 'alps_old',                   // Application-Layer Protocol Settings (old codepoint, 0x4469)
  17613: 'alps_new',                   // Application-Layer Protocol Settings (new codepoint, 0x44CD)
  65037: 'ech',                       // Encrypted Client Hello
  65281: 'renegotiation_info',        // Renegotiation Indication
};

// H2 SETTINGS IDs
export const H2_SETTINGS = {
  1: 'header_table_size',
  2: 'enable_push',
  3: 'max_concurrent_streams',
  4: 'initial_window_size',
  5: 'max_frame_size',
  6: 'max_header_list_size',
  8: 'enable_connect_protocol',
  9: 'no_rfc7540_priorities',
};

// Pseudo-header order mapping
export const PSEUDO_MAP = {
  'm': 'method',
  'a': 'authority',
  's': 'scheme',
  'p': 'path',
};

// GREASE values (RFC 8701) — filter these out from real fingerprint data
const GREASE_HEX = new Set([
  '0a0a', '1a1a', '2a2a', '3a3a', '4a4a', '5a5a', '6a6a', '7a7a',
  '8a8a', '9a9a', 'aaaa', 'baba', 'caca', 'dada', 'eaea', 'fafa',
]);

const GREASE_DECIMAL = new Set([
  2570, 6682, 10794, 14906, 19018, 23130, 27242, 31354,
  35466, 39578, 43690, 47802, 51914, 56026, 60138, 64250,
]);

export function isGreaseHex(value) {
  return GREASE_HEX.has(value.toLowerCase());
}

export function isGreaseDecimal(value) {
  return GREASE_DECIMAL.has(parseInt(value));
}
