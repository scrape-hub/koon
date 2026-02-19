import {
  CIPHER_MAP, CURVE_MAP_DECIMAL, SIGALG_MAP, EXTENSION_FLAGS,
  H2_SETTINGS, PSEUDO_MAP, isGreaseHex, isGreaseDecimal,
} from './mappings.mjs';

// Convert raw browserleaks JSON to a koon BrowserProfile.
export function convertToKoonProfile(rawData, browserInfo) {
  const tls = convertTls(rawData);
  const http2 = convertHttp2(rawData);
  const headers = convertHeaders(rawData, browserInfo);

  return {
    tls,
    http2,
    // QUIC config can't be captured from fingerprint endpoints — use known defaults
    headers,
    _meta: {
      capturedAt: rawData._capturedAt,
      browser: browserInfo.browser,
      version: browserInfo.version,
      platform: browserInfo.platform,
      ja3Hash: rawData.ja3_hash,
      ja4: rawData.ja4,
      akamaiHash: rawData.akamai_hash,
      notes: [],
    },
  };
}

function convertTls(rawData) {
  // Parse JA4_ro (original order): header_ciphers_extensions_sigalgs
  const ja4ro = rawData.ja4_ro || '';
  const ja4roParts = ja4ro.split('_');

  // Parse ciphers from JA4_ro (hex, original order)
  let cipherList = '';
  if (ja4roParts.length >= 2) {
    const cipherHexes = ja4roParts[1].split(',').filter(c => c && !isGreaseHex(c));
    const mapped = cipherHexes.map(hex => {
      const name = CIPHER_MAP[hex.toLowerCase()];
      if (!name) console.warn(`    Unknown cipher: 0x${hex}`);
      return name || `UNKNOWN_0x${hex}`;
    });
    cipherList = mapped.join(':');
  }

  // Parse curves from JA3 text (decimal, original order)
  // JA3 format: "TLSVersion,Ciphers,Extensions,Curves,PointFormats"
  let curves = '';
  const ja3Text = rawData.ja3_text || '';
  const ja3Parts = ja3Text.split(',');
  if (ja3Parts.length >= 4) {
    const curveDecimals = ja3Parts[3].split('-').filter(c => c && !isGreaseDecimal(c));
    const mapped = curveDecimals.map(dec => {
      const name = CURVE_MAP_DECIMAL[dec];
      if (!name) console.warn(`    Unknown curve: ${dec}`);
      return name || `UNKNOWN_${dec}`;
    });
    curves = mapped.join(':');
  }

  // Parse sigalgs from JA4_ro (hex, original order — 4th section)
  let sigalgs = '';
  if (ja4roParts.length >= 4) {
    const sigHexes = ja4roParts[3].split(',').filter(s => s);
    const mapped = sigHexes.map(hex => {
      const name = SIGALG_MAP[hex.toLowerCase()];
      if (!name) console.warn(`    Unknown sigalg: 0x${hex}`);
      return name || `UNKNOWN_0x${hex}`;
    });
    sigalgs = mapped.join(':');
  }

  // Parse extensions from JA3 text (decimal) for feature flags
  const extensionIds = new Set();
  let hasGrease = false;
  if (ja3Parts.length >= 3) {
    ja3Parts[2].split('-').forEach(ext => {
      const id = parseInt(ext);
      if (isGreaseDecimal(ext)) {
        hasGrease = true;
      } else if (!isNaN(id)) {
        extensionIds.add(id);
      }
    });
  }

  // Determine TLS feature flags from extensions
  const hasAlpsOld = extensionIds.has(17513); // 0x4469 — old ALPS codepoint
  const hasAlpsNew = extensionIds.has(17613); // 0x44CD — new ALPS codepoint
  const hasAlps = hasAlpsOld || hasAlpsNew;
  const hasEch = extensionIds.has(65037);
  const hasSct = extensionIds.has(18);
  const hasOcsp = extensionIds.has(5);
  const hasSessionTicket = extensionIds.has(35);
  const hasPsk = extensionIds.has(41);
  const hasCertCompress = extensionIds.has(27);
  const hasDelegatedCreds = extensionIds.has(34);

  // Detect ALPS codepoint:
  // - 17513 (0x4469) = old codepoint → alps_use_new_codepoint: false
  // - 17613 (0x44CD) = new codepoint → alps_use_new_codepoint: true
  // Chrome 131 uses old (17513), Chrome 145 uses new (17613)
  const alpsUseNewCodepoint = hasAlpsNew;

  // TLS version
  const tlsVersion = ja3Parts[0];
  const minVersion = 'tls12';
  const maxVersion = tlsVersion === '771' || ja4ro.startsWith('t13') ? 'tls13' : 'tls12';

  // Determine key_shares_limit from JA4 header
  // The 'o' in the header position indicates cipher/ext count; key shares are harder to detect
  // Default: null for Chrome (sends 2), Some(3) for Firefox (sends 3)

  return {
    cipher_list: cipherList,
    curves,
    sigalgs,
    alpn: extensionIds.has(16) ? ['h2', 'http/1.1'] : ['http/1.1'],
    alps: hasAlps ? 'h2' : null,
    alps_use_new_codepoint: alpsUseNewCodepoint,
    min_version: minVersion,
    max_version: maxVersion,
    grease: hasGrease,
    ech_grease: hasEch,
    permute_extensions: false, // Can't detect from single capture — set based on browser
    ocsp_stapling: hasOcsp,
    signed_cert_timestamps: hasSct,
    cert_compression: hasCertCompress ? ['brotli'] : [], // Default, real value needs deeper inspection
    pre_shared_key: hasPsk,
    session_ticket: hasSessionTicket,
    key_shares_limit: null,
    delegated_credentials: hasDelegatedCreds ? 'NEEDS_MANUAL_CONFIG' : null,
    danger_accept_invalid_certs: false,
  };
}

function convertHttp2(rawData) {
  const akamaiText = rawData.akamai_text || '';

  if (!akamaiText) {
    return {
      _note: 'No Akamai fingerprint captured (HTTP/1.1 was used?)',
      header_table_size: null,
      enable_push: null,
      max_concurrent_streams: null,
      initial_window_size: 65535,
      max_frame_size: null,
      max_header_list_size: null,
      initial_conn_window_size: 65535,
      pseudo_header_order: ['method', 'authority', 'scheme', 'path'],
      settings_order: [],
      headers_stream_dependency: null,
      priorities: [],
      no_rfc7540_priorities: null,
      enable_connect_protocol: null,
    };
  }

  // Akamai fingerprint format: SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADERS
  const parts = akamaiText.split('|');

  // Parse SETTINGS
  const settingsStr = parts[0] || '';
  const settings = {};
  const settingsOrder = [];

  for (const pair of settingsStr.split(';')) {
    if (!pair.includes(':')) continue;
    const [idStr, valStr] = pair.split(':');
    const id = parseInt(idStr);
    const val = parseInt(valStr);
    const name = H2_SETTINGS[id];
    if (name) {
      settings[name] = val;
      settingsOrder.push(name);
    }
  }

  // Parse WINDOW_UPDATE (connection-level window increment).
  // RFC 7540: default connection window is 65535. WINDOW_UPDATE adds to it.
  // So initial_conn_window_size = 65535 + WINDOW_UPDATE increment.
  const windowUpdateIncrement = parseInt(parts[1]) || 0;
  const initialConnWindowSize = windowUpdateIncrement > 0
    ? 65535 + windowUpdateIncrement
    : 65535;

  // Parse PRIORITY / stream dependency
  // Format varies: could be "stream_id:weight:exclusive" or just "0"
  let streamDep = null;
  if (parts[2] && parts[2] !== '0') {
    const depParts = parts[2].split(':');
    if (depParts.length >= 3) {
      streamDep = {
        stream_id: parseInt(depParts[0]),
        weight: parseInt(depParts[1]),
        exclusive: depParts[2] === '1',
      };
    }
  }

  // Parse pseudo-header order
  const pseudoOrder = [];
  if (parts[3]) {
    for (const ch of parts[3].split(',')) {
      const name = PSEUDO_MAP[ch.trim()];
      if (name) pseudoOrder.push(name);
    }
  }

  return {
    header_table_size: settings.header_table_size ?? null,
    enable_push: settings.enable_push !== undefined ? settings.enable_push === 0 ? false : true : null,
    max_concurrent_streams: settings.max_concurrent_streams ?? null,
    initial_window_size: settings.initial_window_size ?? 65535,
    max_frame_size: settings.max_frame_size ?? null,
    max_header_list_size: settings.max_header_list_size ?? null,
    initial_conn_window_size: initialConnWindowSize,
    pseudo_header_order: pseudoOrder.length > 0 ? pseudoOrder : ['method', 'authority', 'scheme', 'path'],
    settings_order: settingsOrder,
    headers_stream_dependency: streamDep,
    priorities: [], // Can't capture PRIORITY frames from Akamai fingerprint
    no_rfc7540_priorities: settings.no_rfc7540_priorities !== undefined
      ? (settings.no_rfc7540_priorities === 1) : null,
    enable_connect_protocol: settings.enable_connect_protocol !== undefined
      ? (settings.enable_connect_protocol === 1) : null,
  };
}

function convertHeaders(rawData, browserInfo) {
  // The user-agent from the capture is the real browser UA
  const ua = rawData.user_agent || rawData._navigator?.userAgent || '';

  // Build headers based on browser type
  if (browserInfo.browser === 'chrome') {
    return buildChromeHeaders(ua, browserInfo);
  } else if (browserInfo.browser === 'firefox') {
    return buildFirefoxHeaders(ua);
  }

  // Generic fallback
  return [
    ['user-agent', ua],
    ['accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'],
    ['accept-encoding', 'gzip, deflate, br'],
    ['accept-language', 'en-US,en;q=0.9'],
  ];
}

function buildChromeHeaders(ua, browserInfo) {
  // Extract Chrome major version from UA
  const chromeMatch = ua.match(/Chrome\/(\d+)/);
  const major = chromeMatch ? chromeMatch[1] : browserInfo.version;

  // Build sec-ch-ua (varies by version)
  // Chrome rotates the "Not A Brand" string periodically
  const brandStrings = {
    '116': '"Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"',
    '120': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    '124': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    '131': '"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"',
    '136': '"Chromium";v="136", "Not/A)Brand";v="24", "Google Chrome";v="136"',
    '145': '"Chromium";v="145", "Not/A)Brand";v="24", "Google Chrome";v="145"',
  };
  const secChUa = brandStrings[major] ||
    `"Chromium";v="${major}", "Not_A Brand";v="24", "Google Chrome";v="${major}"`;

  // Detect platform from UA
  let platform = '"Windows"';
  let mobile = '?0';
  if (ua.includes('Macintosh')) platform = '"macOS"';
  else if (ua.includes('Linux') && !ua.includes('Android')) platform = '"Linux"';
  else if (ua.includes('Android')) { platform = '"Android"'; mobile = '?1'; }

  return [
    ['sec-ch-ua', secChUa],
    ['sec-ch-ua-mobile', mobile],
    ['sec-ch-ua-platform', platform],
    ['upgrade-insecure-requests', '1'],
    ['user-agent', ua],
    ['accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'],
    ['sec-fetch-site', 'none'],
    ['sec-fetch-mode', 'navigate'],
    ['sec-fetch-user', '?1'],
    ['sec-fetch-dest', 'document'],
    ['accept-encoding', 'gzip, deflate, br, zstd'],
    ['accept-language', 'en-US,en;q=0.9'],
    ['priority', 'u=0, i'],
  ];
}

function buildFirefoxHeaders(ua) {
  return [
    ['te', 'trailers'],
    ['user-agent', ua],
    ['accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'],
    ['accept-language', 'en-US,en;q=0.5'],
    ['accept-encoding', 'gzip, deflate, br, zstd'],
    ['sec-fetch-dest', 'document'],
    ['sec-fetch-mode', 'navigate'],
    ['sec-fetch-site', 'none'],
    ['priority', 'u=0, i'],
  ];
}

// Apply browser-specific adjustments that can't be detected from capture
export function applyBrowserDefaults(profile, browserInfo) {
  const { browser, version } = browserInfo;
  const majorVer = parseInt(version);

  if (browser === 'chrome') {
    // Chrome-specific TLS adjustments
    profile.tls.grease = true; // Always true since Chrome 58 (browserleaks strips GREASE from JA3)
    profile.tls.permute_extensions = majorVer >= 110;
    // alps_use_new_codepoint is detected from capture (17513=old, 17613=new)
    // Only override if ALPS wasn't detected at all
    if (profile.tls.alps === null && majorVer >= 100) {
      profile.tls.alps = 'h2';
      profile.tls.alps_use_new_codepoint = majorVer >= 140; // Approximate boundary
    }
    profile.tls.pre_shared_key = true; // Not in initial capture (only on resumed), but Chrome supports it

    // Cert compression: Chrome uses brotli only
    if (profile.tls.cert_compression?.length > 0) {
      profile.tls.cert_compression = ['brotli'];
    }

    // Chrome doesn't use delegated credentials
    if (profile.tls.delegated_credentials === 'NEEDS_MANUAL_CONFIG') {
      profile.tls.delegated_credentials = null;
    }

    // Chrome H2: full settings_order (browserleaks may not capture all)
    if (profile.http2.settings_order.length <= 4) {
      profile.http2.settings_order = [
        'header_table_size',
        'enable_push',
        'max_concurrent_streams',
        'initial_window_size',
        'max_frame_size',
        'max_header_list_size',
        'enable_connect_protocol',
        'no_rfc7540_priorities',
      ];
    }

    // Chrome H2: stream dependency (not captured from Akamai text)
    if (!profile.http2.headers_stream_dependency) {
      profile.http2.headers_stream_dependency = {
        stream_id: 0,
        weight: 219,
        exclusive: true,
      };
    }

    // Chrome 131+: no RFC 7540 priorities
    if (majorVer >= 131 && profile.http2.no_rfc7540_priorities === null) {
      profile.http2.no_rfc7540_priorities = true;
    }

    // Chrome QUIC defaults
    profile.quic = {
      initial_max_data: 15728640,
      initial_max_stream_data_bidi_local: 6291456,
      initial_max_stream_data_bidi_remote: 6291456,
      initial_max_stream_data_uni: 6291456,
      initial_max_streams_bidi: 100,
      initial_max_streams_uni: 100,
      max_idle_timeout_ms: 30000,
      max_udp_payload_size: 1350,
      ack_delay_exponent: 3,
      max_ack_delay_ms: 25,
      active_connection_id_limit: 4,
      disable_active_migration: true,
      grease_quic_bit: true,
      qpack_max_table_capacity: 0,
      qpack_blocked_streams: 0,
      max_field_section_size: null,
    };

  } else if (browser === 'firefox') {
    // Firefox-specific TLS adjustments
    profile.tls.permute_extensions = false;
    profile.tls.alps = null;
    profile.tls.alps_use_new_codepoint = false;
    profile.tls.grease = false;
    profile.tls.pre_shared_key = true; // Firefox supports PSK (not in initial capture)
    profile.tls.key_shares_limit = 3;

    // Firefox uses zlib, brotli, zstd for cert compression
    if (profile.tls.cert_compression?.length > 0) {
      profile.tls.cert_compression = ['zlib', 'brotli', 'zstd'];
    }

    // Firefox delegated credentials sigalgs
    if (profile.tls.delegated_credentials === 'NEEDS_MANUAL_CONFIG') {
      profile.tls.delegated_credentials = 'ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:ecdsa_sha1';
    }

    // Firefox PRIORITY frames (priority tree)
    if (profile.http2.priorities.length === 0) {
      profile.http2.priorities = [
        { stream_id: 3,  dependency: 0, weight: 200, exclusive: false },
        { stream_id: 5,  dependency: 0, weight: 100, exclusive: false },
        { stream_id: 7,  dependency: 0, weight: 0,   exclusive: false },
        { stream_id: 9,  dependency: 7, weight: 0,   exclusive: false },
        { stream_id: 11, dependency: 3, weight: 0,   exclusive: false },
      ];
    }

    // Firefox QUIC defaults
    profile.quic = {
      initial_max_data: 12582912,
      initial_max_stream_data_bidi_local: 1048576,
      initial_max_stream_data_bidi_remote: 1048576,
      initial_max_stream_data_uni: 1048576,
      initial_max_streams_bidi: 16,
      initial_max_streams_uni: 16,
      max_idle_timeout_ms: 30000,
      max_udp_payload_size: 1472,
      ack_delay_exponent: 3,
      max_ack_delay_ms: 25,
      active_connection_id_limit: 2,
      disable_active_migration: false,
      grease_quic_bit: false,
      qpack_max_table_capacity: 0,
      qpack_blocked_streams: 0,
      max_field_section_size: null,
    };
  }

  return profile;
}

// Format the profile for display / review
export function formatProfileSummary(profile) {
  const lines = [];
  lines.push('=== TLS Config ===');
  lines.push(`  Ciphers: ${countItems(profile.tls.cipher_list, ':')} suites`);
  lines.push(`  Curves: ${profile.tls.curves}`);
  lines.push(`  Sigalgs: ${countItems(profile.tls.sigalgs, ':')} algorithms`);
  lines.push(`  GREASE: ${profile.tls.grease}, ECH: ${profile.tls.ech_grease}`);
  lines.push(`  ALPS: ${profile.tls.alps || 'none'}, Permute: ${profile.tls.permute_extensions}`);

  lines.push('\n=== HTTP/2 Config ===');
  lines.push(`  Window: ${profile.http2.initial_window_size}, Conn: ${profile.http2.initial_conn_window_size}`);
  lines.push(`  Pseudo order: ${profile.http2.pseudo_header_order.join(', ')}`);
  lines.push(`  Settings order: ${profile.http2.settings_order.join(', ')}`);
  if (profile.http2.no_rfc7540_priorities !== null) {
    lines.push(`  No RFC7540 priorities: ${profile.http2.no_rfc7540_priorities}`);
  }
  if (profile.http2.priorities?.length > 0) {
    lines.push(`  PRIORITY frames: ${profile.http2.priorities.length}`);
  }

  lines.push('\n=== Headers ===');
  for (const [k, v] of profile.headers) {
    const display = v.length > 60 ? v.substring(0, 60) + '...' : v;
    lines.push(`  ${k}: ${display}`);
  }

  if (profile.quic) {
    lines.push('\n=== QUIC Config ===');
    lines.push(`  Max data: ${profile.quic.initial_max_data}`);
    lines.push(`  Bidi streams: ${profile.quic.initial_max_streams_bidi}`);
  }

  return lines.join('\n');
}

function countItems(str, sep) {
  if (!str) return 0;
  return str.split(sep).filter(s => s).length;
}
