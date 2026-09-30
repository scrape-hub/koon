/**
 * Browser profile name for impersonation.
 *
 * Format: `{browser}{version?}{-os?}`
 * - browser: chrome, firefox, safari, edge, opera, brave, samsung, chrome-mobile, firefox-mobile,
 *   safari-mobile, edge-mobile, brave-mobile, opera-mobile, okhttp
 * - version: optional number (e.g. 145, 148)
 * - os: optional suffix with dash (e.g. -windows, -macos, -linux, -android, -ios)
 *
 * Without a version, the latest one; without an OS, Windows (Safari: macOS).
 *
 * Examples: "chrome", "chrome152", "chrome152-macos", "firefox154-linux",
 *           "chrome-mobile152", "firefox-mobile154", "safari-mobile266", "okhttp5"
 */
export type Browser =
  // Desktop browsers (common values for autocomplete)
  | 'chrome' | 'firefox' | 'safari' | 'edge' | 'opera' | 'brave'
  // Mobile browsers
  | 'chrome-mobile' | 'firefox-mobile' | 'safari-mobile' | 'edge-mobile' | 'brave-mobile'
  | 'samsung' | 'opera-mobile'
  // OkHttp (Android apps)
  | 'okhttp' | 'okhttp4' | 'okhttp5'
  // Any other valid profile string (version, OS suffix, etc.)
  | (string & {});

/** A header as a `{ name, value }` object; an array of these keeps duplicates (e.g. multiple Set-Cookie). */
export interface KoonHeaderEntry {
  name: string;
  value: string;
}

/**
 * The bot protection that answered instead of the page. `javascript` is a JavaScript
 * challenge and `block-page` a block page of no known vendor, `consent` a cookie consent page.
 */
export type KoonBlockedBy =
  | 'cloudflare'
  | 'akamai'
  | 'datadome'
  | 'perimeterx'
  | 'aws-waf'
  | 'imperva'
  | 'kasada'
  | 'baleen'
  | 'google'
  | 'amazon'
  | 'javascript'
  | 'block-page'
  | 'consent';

/**
 * Headers to send, in order: an object (insertion order), or `[name, value]`
 * pairs: an array, a `Map`, a fetch `Headers` or any other iterable of pairs.
 * A name given more than once is sent once, with the last value, at the
 * position of its first occurrence. A pair that is not two strings throws
 * `INVALID_ARGUMENT`.
 */
export type KoonHeadersInit = Record<string, string> | Iterable<readonly [string, string]>;

/**
 * Hook called before each HTTP request (including redirects). If it throws,
 * the request is not sent and rejects with the thrown value itself.
 * Hooks are synchronous: a returned Promise is not awaited.
 */
export type OnRequestHook = (method: string, url: string) => void;
/**
 * Hook called after each HTTP response (including redirects), once its
 * cookies are stored. If it throws, the request rejects with the thrown value
 * itself. Hooks are synchronous: a returned Promise is not awaited.
 */
export type OnResponseHook = (status: number, url: string, headers: KoonHeaderEntry[]) => void;
/**
 * Hook called before following a redirect. Return `false` to stop redirecting
 * and get the 3xx response as-is; any other return value follows the redirect.
 * If it throws, the redirect is not followed and the request rejects with the
 * thrown value itself. The hook is synchronous: a returned Promise is not
 * awaited (the redirect is followed and a one-time warning with code
 * `KOON_ASYNC_HOOK` is emitted; a rejection of that Promise is reported as a
 * process warning).
 */
export type OnRedirectHook = (status: number, url: string, headers: KoonHeaderEntry[]) => boolean | void;

export interface KoonOptions {
  /** Browser profile to impersonate. Default: "chrome" (latest Chrome on Windows). */
  browser?: Browser;
  /** Custom browser profile as JSON string (see `exportProfile()`). Overrides `browser`. */
  profileJson?: string;
  /**
   * Proxy URL (http://, https://, socks5://). An `https://` proxy is reached over TLS and
   * its certificate is verified (see `proxyCaCerts`).
   */
  proxy?: string;
  /** Array of proxy URLs for round-robin rotation. Takes priority over `proxy`. */
  proxies?: string[];
  /** Request timeout in seconds, fractions allowed. 0 means no timeout. Default: 30. */
  timeout?: number;
  /** Skip TLS certificate verification of origins. `https://` proxies are still verified (see `ignoreProxyTlsErrors`). */
  ignoreTlsErrors?: boolean;
  /**
   * Certificates (PEM, one or more) trusted for the TLS connection to `https://` proxies, in
   * addition to the built-in roots, like curl's `--proxy-cacert`: for a proxy with a
   * self-signed certificate or one from a private CA. Origins are still verified against the
   * built-in roots only. Invalid PEM throws `INVALID_ARGUMENT`.
   */
  proxyCaCerts?: string | Buffer;
  /**
   * Skip certificate verification of `https://` proxies, like curl's `--proxy-insecure`.
   * The connection stays encrypted, but anyone on the way to the proxy can pose as it and
   * read the proxy credentials and the hosts requested. Origins are still verified. Prefer
   * `proxyCaCerts`. Default: false.
   */
  ignoreProxyTlsErrors?: boolean;
  /** Default headers to send with every request, in order. */
  headers?: KoonHeadersInit;
  /** Follow redirects. Default: true. */
  followRedirects?: boolean;
  /** Maximum redirects to follow (a whole number). Default: 10. */
  maxRedirects?: number;
  /** Enable cookie jar. Default: true. */
  cookieJar?: boolean;
  /** Enable TLS session resumption. Default: true. */
  sessionResumption?: boolean;
  /** DNS-over-HTTPS provider, case-insensitive: "cloudflare" or "google". */
  doh?: string;
  /** Bind outgoing connections to a specific local IP address. */
  localAddress?: string;
  /** Hook called before each HTTP request (including redirects); throwing fails the request before it is sent. */
  onRequest?: OnRequestHook;
  /** Hook called after each HTTP response (including redirects); throwing fails the request. */
  onResponse?: OnResponseHook;
  /** Hook called before following a redirect. Return false to stop redirecting and return the 3xx response; throwing fails the request. */
  onRedirect?: OnRedirectHook;
  /** Number of automatic retries on transport errors (a whole number). With proxy rotation, each retry uses the next proxy. Default: 0. */
  retries?: number;
  /** Locale for Accept-Language header generation. Overrides the profile's Accept-Language to match proxy geography. Examples: "fr-FR", "de", "ja-JP". */
  locale?: string;
  /** Custom headers to send in the HTTP CONNECT tunnel request, in order. Useful for proxy session IDs, geo-targeting, or authentication. */
  proxyHeaders?: KoonHeadersInit;
  /** Restrict DNS resolution to IPv4 (4) or IPv6 (6). Useful when residential proxies only support IPv4. */
  ipVersion?: 4 | 6;
  /**
   * Entries in curl's `--resolve` format, `"host:port:address[,address...]"` (IPv6 in
   * brackets): requests to that host and port connect to the address instead of resolving
   * the host. The TLS server name, Host header and cookies stay the host's. An invalid entry
   * throws `INVALID_ARGUMENT`.
   */
  resolve?: string[];
  /**
   * Maximum response body size in bytes, decompressed: past it, a response fails with
   * `BODY_ERROR` instead of growing the buffer further (also covers a compressed body that
   * decodes past the cap). Reading a streaming response chunk by chunk without decoding it is
   * not capped. `0` disables it. Default: 100 MiB.
   */
  maxResponseBody?: number;
  /**
   * Pins Chrome/Edge/Opera 151+'s `PqcBandwidthExperiment` server-padding field trial group
   * instead of drawing one when the client is built: `"none"` (not in the study, like 94% of
   * real Chrome) or the bytes of padding the group asks for (e.g. `"6000"`). No effect on a
   * profile that does not run the trial. Default: drawn per client.
   */
  serverPadding?: string;
}

/**
 * Machine-readable error codes koon throws, exposed as `err.code`.
 * `err.message` also carries the code as a `[CODE] ...` prefix.
 */
export type KoonErrorCode =
  | 'TLS_ERROR'
  | 'HTTP2_ERROR'
  | 'QUIC_ERROR'
  | 'HTTP3_ERROR'
  | 'IO_ERROR'
  /** A URL that does not parse, or a scheme koon does not speak (also on a redirect). */
  | 'INVALID_URL'
  | 'PROXY_ERROR'
  | 'INVALID_HEADER'
  /**
   * The request body could not be sent (again), or a streaming response body was
   * read again after `collect()`.
   */
  | 'BODY_ERROR'
  | 'CONNECTION_FAILED'
  | 'PROTOCOL_ERROR'
  | 'JSON_ERROR'
  | 'WEBSOCKET_ERROR'
  | 'DNS_ERROR'
  | 'CONFIG_ERROR'
  | 'TIMEOUT'
  | 'TOO_MANY_REDIRECTS'
  | 'COOKIE_JAR_DISABLED'
  | 'INVALID_COOKIE'
  /**
   * An option or argument koon does not accept: an unknown browser profile,
   * HTTP method, header mode, IP version or DoH provider, a negative or
   * fractional count, a value of the wrong type, ...
   */
  | 'INVALID_ARGUMENT';

export interface KoonError extends Error {
  code: KoonErrorCode;
}

export class KoonResponse {
  /** Responses come from `Koon` requests only. */
  private constructor();

  /** HTTP status code. */
  readonly status: number;
  /** Alias for `status` (compatibility with fetch/axios conventions). */
  readonly statusCode: number;
  /** Response headers as `{ name, value }` objects, in wire order. The same array on every access. */
  readonly headers: KoonHeaderEntry[];
  /** Headers of the request as actually sent, in wire order and casing (HTTP/2 and HTTP/3 pseudo-headers first). */
  readonly requestHeaders: KoonHeaderEntry[];
  /** Response body (decompressed). The same Buffer on every access, sharing the response's memory without a copy. */
  readonly body: Buffer;
  /** HTTP version string (e.g., "h2"). */
  readonly version: string;
  /** Final URL after redirects. */
  readonly url: string;
  /** Whether the status code is 2xx (success). */
  readonly ok: boolean;
  /** Approximate bytes sent for this request (headers + body). */
  readonly bytesSent: number;
  /** Approximate bytes received for this response (headers + body, pre-decompression). */
  readonly bytesReceived: number;
  /** Whether TLS session resumption was used for this connection. */
  readonly tlsResumed: boolean;
  /** Whether an existing pooled connection was reused. */
  readonly connectionReused: boolean;
  /** Remote IP address of the peer (the proxy when one is used), or null if unknown. */
  readonly remoteAddress: string | null;
  /** Content-Type header value (e.g. "text/html; charset=utf-8"), or null if absent. */
  readonly contentType: string | null;
  /** The bot protection that answered instead of the page, or null for the page itself. A plain error status gives null. */
  readonly blockedBy: KoonBlockedBy | null;

  /** Decode the body as text with the charset of its Content-Type header, else UTF-8. */
  text(): string;
  /** `JSON.parse()` of `text()`. */
  json(): any;
  /** Look up a response header by name (case-insensitive). */
  header(name: string): string | null;
}

export interface KoonWsMessage {
  /** Whether the message is text (true) or binary (false). */
  isText: boolean;
  /** Message data. */
  data: Buffer;
}

export interface KoonRequestOptions {
  /** Additional headers for this request, in order. Override client-level headers. */
  headers?: KoonHeadersInit;
  /** Per-request timeout in seconds, fractions allowed. 0 means no timeout. Overrides client-level timeout. */
  timeout?: number;
  /** Per-request proxy URL (http://, https://, socks5://). Overrides client-level proxy. */
  proxy?: string;
  /** Follow redirects for this request only. Overrides the client-level default. */
  followRedirects?: boolean;
  /** Maximum redirects to follow for this request only (a whole number). Overrides the client-level default. */
  maxRedirects?: number;
  /** Hook called before each request of this call (including redirects), in place of the client's. */
  onRequest?: OnRequestHook;
  /** Hook called after each response of this call (including redirects), in place of the client's. */
  onResponse?: OnResponseHook;
  /** Hook called before following a redirect of this call, in place of the client's. Return false to stop redirecting. */
  onRedirect?: OnRedirectHook;
}

export interface KoonStreamingOptions extends KoonRequestOptions {
  /**
   * Decode the body's Content-Encoding (gzip, deflate, br, zstd and stacked codings) as it
   * is read; a coding koon does not know arrives as it is. `false` gives the bytes as sent.
   * The headers stay as received either way, Content-Encoding and Content-Length included.
   * Default: true.
   */
  decode?: boolean;
}

export interface KoonMultipartField {
  /** Field name. */
  name: string;
  /** Text value (for form fields). Exactly one of `value`/`fileData` is required. */
  value?: string;
  /** Binary data (for file uploads). Exactly one of `value`/`fileData` is required. */
  fileData?: Buffer;
  /** Filename (for file uploads). */
  filename?: string;
  /** MIME type (for file uploads). */
  contentType?: string;
}

/**
 * A cookie for `setCookies()`/`cookies()`, in the shape of Playwright's
 * `addCookies()`/`cookies()` and the Chrome DevTools Protocol.
 *
 * A cookie has either a `url` or a `domain` (with an optional `path`).
 */
export interface KoonCookie {
  /** Cookie name. */
  name: string;
  /** Cookie value. */
  value: string;
  /**
   * Cookie domain. A leading dot means a domain cookie (also sent to
   * subdomains); without one, it's host-only. Not allowed together with `url`.
   * `cookies()` always reports it.
   */
  domain?: string;
  /** URL path scope. Defaults to "/". Not allowed together with `url`. */
  path?: string;
  /**
   * Derive a host-only cookie from this URL (like Playwright's
   * `addCookies`): its host, the URL path up to and including the last "/",
   * and `secure` from the scheme (https). Not allowed together with `domain`
   * or `path`. Never reported by `cookies()`.
   */
  url?: string;
  /** Unix timestamp in seconds, up to 253402300799. Omit or pass -1 for a session cookie. */
  expires?: number;
  /** Only send over HTTPS. Defaults to false; ignored with `url`. */
  secure?: boolean;
  /** Not accessible via JavaScript. Defaults to false. */
  httpOnly?: boolean;
  /** SameSite policy, case-insensitive. Defaults to 'Lax'. */
  sameSite?: 'Strict' | 'Lax' | 'None' | 'strict' | 'lax' | 'none';
  /** Only send to the exact domain. Defaults to whether `domain` has no leading dot (true with `url`). */
  hostOnly?: boolean;
  /**
   * CHIPS partition key. `setCookies()` skips (and reports) partitioned cookies: browsers
   * send them only in a third-party context, never with top-level requests.
   */
  partitionKey?: unknown;
  /** Opaque CHIPS partition key. `true` makes `setCookies()` skip the cookie like `partitionKey`. */
  partitionKeyOpaque?: boolean;
}

/** A cookie `setCookies()` did not import, and why. */
export interface KoonSkippedCookie {
  /** Position of the cookie in the array given to `setCookies()` (0-based). */
  index: number;
  /** The cookie's name. */
  name: string;
  /** Why it was not imported, e.g. an invalid value or domain, or a partitioned cookie. */
  reason: string;
}

/** A fingerprint field `Koon.verify()` compares. */
export type KoonVerifyField =
  | 'ja4'
  | 'ja3n_hash'
  | 'ja3_hash'
  | 'akamai_hash'
  | 'akamai_text'
  | 'quic_ja4';

/** The result of one field of a `Koon.verify()` report. */
export type KoonVerifyFieldCheck =
  | { field: KoonVerifyField; status: 'match'; value: string }
  | { field: KoonVerifyField; status: 'mismatch'; expected: string; actual: string }
  | {
      field: KoonVerifyField;
      status: 'not_checked';
      /**
       * `no_reference`: the real browser's value is not known; `not_reported`: the service does
       * not report the field; `no_http3`: HTTP/3 was not used (UDP blocked, or a proxy);
       * `skipped`: the HTTP/3 check was turned off; `unreachable`: no service answered.
       */
      reason: 'no_reference' | 'not_reported' | 'no_http3' | 'skipped' | 'unreachable';
      /** What the service saw, if anything. */
      actual?: string;
    };

/** The report of `Koon.verify()`. */
export interface KoonVerifyReport {
  /** The profile checked, e.g. `"chrome154-windows"`. */
  profile: string;
  /** The koon version that produced the fingerprint. */
  koon_version: string;
  /** `no_reference`: no capture covers this browser version (Safari releases without a capture of their own, Firefox on Android before 146). */
  outcome: 'match' | 'mismatch' | 'no_reference' | 'unreachable';
  /** The references compared with: their name and where the values come from. */
  references: { id: string; source: string }[];
  /** The TLS fingerprint service that answered. */
  service: string | null;
  /** The HTTP/3 service that answered over HTTP/3. */
  http3_service: string | null;
  /** Every field, in a fixed order. */
  fields: KoonVerifyFieldCheck[];
  /** Services that failed, in the order they were tried. */
  errors: { service: string; code: string; message: string }[];
}

export class Koon {
  constructor(options?: KoonOptions);

  /**
   * Every built-in browser profile name, one per profile: every browser version on every OS
   * it has a profile for, e.g. `"chrome154-windows"`, `"safari266-ios"`, `"okhttp5"`. Names
   * without a version select the latest one; without an OS, desktop profiles impersonate
   * Windows (Safari: macOS).
   */
  static browsers(): string[];

  /**
   * Check that the installed koon still produces the real browser's fingerprint for the
   * profile `browser` (default `"chrome"`). Connects to tls.browserleaks.com (tls.peet.ws as
   * fallback) and, where a QUIC reference exists, over HTTP/3 to quic.browserleaks.com, and
   * compares JA4, JA3N, JA3, the Akamai HTTP/2 fingerprint and the QUIC JA4 with the values
   * captured from the real browser. `options.proxy` routes the check through a proxy (HTTP/3
   * is then not used). Rejects with `INVALID_ARGUMENT` for an unknown profile; unreachable
   * services are part of the report (`outcome: "unreachable"`).
   */
  static verify(browser?: string, options?: { proxy?: string }): Promise<KoonVerifyReport>;

  /** The User-Agent string from the browser profile. Useful for Puppeteer/Playwright. */
  readonly userAgent: string | null;

  get(url: string, options?: KoonRequestOptions): Promise<KoonResponse>;
  post(url: string, body?: string | Buffer, options?: KoonRequestOptions): Promise<KoonResponse>;
  put(url: string, body?: string | Buffer, options?: KoonRequestOptions): Promise<KoonResponse>;
  delete(url: string, options?: KoonRequestOptions): Promise<KoonResponse>;
  patch(url: string, body?: string | Buffer, options?: KoonRequestOptions): Promise<KoonResponse>;
  head(url: string, options?: KoonRequestOptions): Promise<KoonResponse>;
  /** `method` is matched case-insensitively and always sent uppercase on the wire. The methods above call this one. */
  request(method: string, url: string, body?: string | Buffer, options?: KoonRequestOptions): Promise<KoonResponse>;
  postMultipart(url: string, fields: KoonMultipartField[], options?: KoonRequestOptions): Promise<KoonResponse>;
  /**
   * Resolves once the response head has arrived; the body is read with the returned
   * response. Follows redirects like the buffered methods above. The body is decoded
   * (gzip, deflate, br, zstd) unless `decode: false`.
   */
  requestStreaming(method: string, url: string, body?: string | Buffer, options?: KoonStreamingOptions): Promise<KoonStreamingResponse>;

  /** Opens a `ws://` or `wss://` connection. */
  websocket(url: string, headers?: KoonHeadersInit): Promise<KoonWebSocket>;

  /** Get the total number of bytes sent across all requests. */
  totalBytesSent(): number;
  /** Get the total number of bytes received across all requests. */
  totalBytesReceived(): number;
  /** Reset both cumulative byte counters to zero. */
  resetCounters(): void;

  /** Clear all cookies from the cookie jar. Keeps TLS sessions and connection pool. */
  clearCookies(): void;
  /**
   * Insert or replace cookies imported from an external source (e.g. a
   * browser's cookie jar via Playwright/CDP `cookies()`). Every valid cookie
   * is imported; the others, e.g. one with an invalid value or domain or a
   * partitioned cookie, are skipped and returned, so one odd cookie does not
   * cost a whole browser export. An empty array means all were imported.
   * Throws `COOKIE_JAR_DISABLED` if the client was created with
   * `cookieJar: false`, and `INVALID_ARGUMENT` for an array element that is
   * not a cookie object (e.g. one without `name`).
   */
  setCookies(cookies: KoonCookie[]): KoonSkippedCookie[];
  /**
   * Export every cookie currently stored in the jar (e.g. for Playwright/CDP
   * `addCookies()`, or straight back into `setCookies()`).
   */
  cookies(): KoonCookie[];

  /**
   * Close all pooled connections and release resources, without waiting. The client can still be used after: new connections open on demand.
   * Idle HTTP/3 connections end as the browser ends them at shutdown; one with a response still being read ends
   * as when the pool drops it once the response is done: Chrome-family profiles discard it without sending
   * anything, as Chromium does; Firefox profiles close it with H3_NO_ERROR. `shutdown()` ends everything at once.
   */
  close(): void;
  /**
   * Shut the client down as a browser does, e.g. before the process exits: every HTTP/3 connection
   * ends at once with the browser's close, and the promise resolves once the closes have been sent
   * (after at most 300 ms), so they are not lost when the process exits right after. HTTP/3
   * responses still being read fail, as browsers abort them; HTTP/1.1 and HTTP/2 responses still
   * being read are not affected. The client can still be used afterwards.
   */
  shutdown(): Promise<void>;

  exportProfile(): string;
  saveSession(): string;
  loadSession(json: string): void;
  saveSessionToFile(path: string): void;
  loadSessionFromFile(path: string): void;
}

export class KoonStreamingResponse {
  /** Streaming responses come from `Koon.requestStreaming()` only. */
  private constructor();

  readonly status: number;
  /** Alias for `status`. */
  readonly statusCode: number;
  /** Response headers as `{ name, value }` objects, in wire order. The same array on every access. */
  readonly headers: KoonHeaderEntry[];
  /** Headers of the request as actually sent, in wire order and casing (HTTP/2 and HTTP/3 pseudo-headers first). */
  readonly requestHeaders: KoonHeaderEntry[];
  readonly version: string;
  readonly url: string;
  /** Approximate bytes sent for this request. */
  readonly bytesSent: number;
  /** Remote IP address of the peer (the proxy when one is used), or null if unknown. */
  readonly remoteAddress: string | null;
  /** Whether TLS session resumption was used for this connection. */
  readonly tlsResumed: boolean;
  /** Whether an existing pooled connection was reused. */
  readonly connectionReused: boolean;

  /** Approximate bytes received so far (headers + body chunks consumed). */
  bytesReceived(): number;
  /**
   * The next body chunk, or null when the body is complete. Decoded unless the request asked
   * for `decode: false`; data that does not decode, or a compressed body that is cut off,
   * rejects with `IO_ERROR`.
   */
  nextChunk(): Promise<Buffer | null>;
  /** The rest of the body as one Buffer. Consumes the stream: later reads throw `BODY_ERROR`. */
  collect(): Promise<Buffer>;
  /**
   * Drop the rest of the body without reading it: the stream is closed (HTTP/1.1) or reset
   * (HTTP/2, HTTP/3) at once. A pending `nextChunk()`/`collect()` and every later read reject
   * with `BODY_ERROR`. Calling it again does nothing.
   */
  cancel(): void;
  /**
   * `for await (const chunk of response)`: the body chunks as `nextChunk()` returns them.
   * Leaving the loop early (`break`, `return`, a throw) calls `cancel()`.
   */
  [Symbol.asyncIterator](): AsyncGenerator<Buffer, void, undefined>;
}

/**
 * A WebSocket connection. Sending and receiving are independent: a pending
 * `receive()` does not hold up `send()` or `close()`.
 */
export class KoonWebSocket {
  /** WebSockets come from `Koon.websocket()` only. */
  private constructor();

  /** Send a string as a text message or a Buffer as a binary message. After `close()` this throws `WEBSOCKET_ERROR`. */
  send(data: string | Buffer): Promise<void>;
  /** The next message, or null once the connection is closed. */
  receive(): Promise<KoonWsMessage | null>;
  /** Send a close frame with an optional close code (0-65535) and reason. */
  close(code?: number, reason?: string): Promise<void>;
}

export interface KoonProxyOptions {
  /** Browser profile. Default: "chrome". */
  browser?: Browser;
  /** Custom profile JSON. */
  profileJson?: string;
  /** Listen address. Default: "127.0.0.1:0". */
  listenAddr?: string;
  /** Header mode, case-insensitive: "impersonate" (default) or "passthrough". Any other value throws `INVALID_ARGUMENT`. */
  headerMode?: 'impersonate' | 'passthrough';
  /** CA certificate directory. Default: "~/.koon/ca/". */
  caDir?: string;
  /**
   * Timeout in seconds, fractions allowed, for a forwarded request's response head and each
   * wait for its body. 0 means no timeout. Default: 30.
   */
  timeout?: number;
  /**
   * Allow `listenAddr` to bind a non-loopback address. Without it, the proxy relays through
   * koon's fingerprinted TLS/HTTP2 stack with no transport encryption of its own between it and
   * its client, so on a reachable interface it would otherwise be an open relay for anyone who
   * can reach the port unless `auth` is also set. Default: false.
   */
  allowNonLoopback?: boolean;
  /** `Proxy-Authorization: Basic` credentials required of every client. Default: none. */
  auth?: KoonProxyAuth;
  /** Connections accepted at once; further ones wait for a slot to free up. Default: 512. */
  maxConnections?: number;

  // How the forwarded requests connect, as for a `Koon` client. The proxy does not follow
  // redirects and keeps no cookies: the proxied client gets each redirect and keeps its own.

  /** Upstream proxy (http://, https://, socks5://), e.g. a residential proxy. See `KoonOptions.proxy`. */
  proxy?: string;
  /** Upstream proxies for round-robin rotation. Takes priority over `proxy`. */
  proxies?: string[];
  /** Skip TLS certificate verification of origins. See `KoonOptions.ignoreTlsErrors`. */
  ignoreTlsErrors?: boolean;
  /** Certificates trusted for an `https://` upstream proxy. See `KoonOptions.proxyCaCerts`. */
  proxyCaCerts?: string | Buffer;
  /** Skip certificate verification of an `https://` upstream proxy. See `KoonOptions.ignoreProxyTlsErrors`. */
  ignoreProxyTlsErrors?: boolean;
  /** Headers for the CONNECT request to the upstream proxy, in order. */
  proxyHeaders?: KoonHeadersInit;
  /** Enable TLS session resumption to origins. Default: true. */
  sessionResumption?: boolean;
  /** DNS-over-HTTPS provider, case-insensitive: "cloudflare" or "google". */
  doh?: string;
  /** Bind outgoing connections to a specific local IP address. */
  localAddress?: string;
  /** Automatic retries of forwarded requests on transport errors (a whole number). Default: 0. */
  retries?: number;
  /** Locale for the Accept-Language header the profile sends (e.g. "de-DE"); in impersonate mode the client's own is dropped. */
  locale?: string;
  /** Restrict DNS resolution to IPv4 (4) or IPv6 (6). */
  ipVersion?: 4 | 6;
  /** Entries in curl's `--resolve` format for the forwarded requests. See `KoonOptions.resolve`. */
  resolve?: string[];
  /** Maximum forwarded response body size in bytes, decompressed. See `KoonOptions.maxResponseBody`. */
  maxResponseBody?: number;
  /** Pins the forwarded requests' server-padding field trial group. See `KoonOptions.serverPadding`. */
  serverPadding?: string;
}

export interface KoonProxyAuth {
  username: string;
  password: string;
}

export class KoonProxy {
  /** Use `KoonProxy.start()`. */
  private constructor();

  static start(options?: KoonProxyOptions): Promise<KoonProxy>;

  readonly port: number;
  /** The proxy URL (e.g. "http://127.0.0.1:12345"). */
  readonly url: string;
  /** Path to the CA certificate PEM file; install it in the browser or system to trust the proxy. */
  readonly caCertPath: string;

  /** The CA certificate as PEM bytes. */
  caCertPem(): Buffer;
  /** Stop accepting and close every open connection. Resolves when done; calling it again does nothing. */
  shutdown(): Promise<void>;
}

/** A `fetch()` that sends through a koon client, as `koonFetch()` returns it. */
export interface KoonFetch {
  (input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  /** The client that sends the requests: its cookies, `userAgent`, `shutdown()`, ... */
  readonly client: Koon;
}

/**
 * A `fetch()` with koon's fingerprint: `const fetch = koonFetch({ browser: 'chrome' })`
 * takes what the global `fetch()` takes (`RequestInfo | URL`, `RequestInit`) and resolves
 * to a standard `Response`. The options are a `Koon` client's; a `Koon` client itself works
 * too and is then shared.
 *
 * - Headers: only the caller's are added to the browser's, as `headers` of a koon request:
 *   a caller header replaces the browser's header of the same name in place, others go where
 *   the browser puts them. Nothing of Node's own fetch is sent (its `user-agent: node`, its
 *   catch-all `accept`, ...). A plain GET looks like a navigation, as with `client.get()`; an
 *   `Accept` without `text/html`, a `Content-Type` or an `Origin` makes it a fetch() call.
 *   A body gets the Content-Type fetch gives it, unless the caller sets one; a `referrer`
 *   URL is sent as Referer. A name repeated in pairs is joined, as `Headers` joins it.
 * - Bodies: a string, `URLSearchParams`, `Blob`, `ArrayBuffer`, typed array or `DataView`,
 *   a `FormData` (multipart with the boundary of the profile's browser), a `ReadableStream`
 *   or another async iterable. Bodies are read into memory and sent with their length.
 * - Redirects: `redirect: 'follow'` (default) lets koon follow them (the client's
 *   `maxRedirects` and `onRedirect` apply); `'manual'` resolves to the 3xx response as it
 *   is, as Node's fetch does; `'error'` rejects.
 * - Cookies: the client's cookie jar, which keeps them as a browser does.
 *   `credentials: 'omit'` rejects: create the client with `cookieJar: false` instead.
 * - Response: the body is read from koon as it is consumed (`body` stream, `text()`,
 *   `json()`, `arrayBuffer()`, ...) and arrives decoded, so the response has no
 *   Content-Encoding and Content-Length. `url` is the final URL and `redirected` whether it
 *   differs from the one requested; a status outside 200-599 (e.g. 999) is kept, with
 *   `ok` false.
 * - `signal`: an abort before the response head cancels the request, one during the body
 *   drops the rest of it and errors the stream; both with the signal's reason.
 * - Timeout: the client's `timeout` (default 30 s, `0` for none), up to the response head
 *   and then for each wait for body data. `signal: AbortSignal.timeout(ms)` limits a whole
 *   request.
 * - Errors: a failed request rejects with `TypeError('fetch failed')`, a failed body read
 *   with `TypeError('terminated')`, as Node's fetch does; `cause` is the koon error, with its
 *   `code`.
 * - `integrity`, `dispatcher` and `cache: 'only-if-cached'` reject. `mode`, `cache`,
 *   `keepalive`, `priority`, `referrerPolicy` and `duplex` change nothing: koon has no HTTP
 *   cache and keeps connections alive anyway.
 */
export function koonFetch(options?: KoonOptions | Koon): KoonFetch;
