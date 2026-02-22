export type Browser =
  | 'chrome' | 'chrome131' | 'chrome132' | 'chrome133' | 'chrome134' | 'chrome135'
  | 'chrome136' | 'chrome137' | 'chrome138' | 'chrome139' | 'chrome140'
  | 'chrome141' | 'chrome142' | 'chrome143' | 'chrome144' | 'chrome145'
  | 'firefox' | 'firefox135' | 'firefox136' | 'firefox137' | 'firefox138'
  | 'firefox139' | 'firefox140' | 'firefox141' | 'firefox142' | 'firefox143'
  | 'firefox144' | 'firefox145' | 'firefox146' | 'firefox147'
  | 'safari' | 'safari156' | 'safari160' | 'safari161' | 'safari170' | 'safari171'
  | 'safari172' | 'safari173' | 'safari180' | 'safari181' | 'safari182' | 'safari183'
  | 'edge' | 'edge131' | 'edge132' | 'edge133' | 'edge134' | 'edge135'
  | 'edge136' | 'edge137' | 'edge138' | 'edge139' | 'edge140'
  | 'edge141' | 'edge142' | 'edge143' | 'edge144' | 'edge145'
  | 'opera' | 'opera124' | 'opera125' | 'opera126' | 'opera127'
  // OS-specific variants
  | `${string}-windows` | `${string}-macos` | `${string}-linux`;

export interface KoonOptions {
  /** Browser profile to impersonate. */
  browser?: Browser;
  /** Custom browser profile as JSON string. */
  profileJson?: string;
  /** Proxy URL (http://, socks5://). */
  proxy?: string;
  /** Request timeout in milliseconds. Default: 30000. */
  timeout?: number;
  /** Skip TLS certificate verification. */
  ignoreTlsErrors?: boolean;
  /** Default headers to send with every request. */
  headers?: Record<string, string>;
  /** Follow redirects. Default: true. */
  followRedirects?: boolean;
  /** Maximum redirects to follow. Default: 10. */
  maxRedirects?: number;
  /** Enable cookie jar. Default: true. */
  cookieJar?: boolean;
  /** Apply slight fingerprint randomization. */
  randomize?: boolean;
  /** Enable TLS session resumption. Default: true. */
  sessionResumption?: boolean;
  /** DNS-over-HTTPS provider ("cloudflare", "google", or URL). */
  doh?: string;
}

export class KoonResponse {
  /** HTTP status code. */
  readonly status: number;
  /** Response headers as [name, value] pairs. */
  readonly headers: Array<{ name: string; value: string }>;
  /** Response body as Buffer. */
  readonly body: Buffer;
  /** HTTP version string (e.g., "HTTP/2.0"). */
  readonly version: string;
  /** Final URL after redirects. */
  readonly url: string;
  /** Whether the status code is 2xx (success). */
  readonly ok: boolean;

  /** Decode response body as UTF-8 string. */
  text(): string;
  /** Parse response body as JSON (via JSON.parse()). */
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
  /** Additional headers for this request. Override constructor-level headers. */
  headers?: Record<string, string>;
  /** Per-request timeout in milliseconds. Overrides constructor-level timeout. */
  timeout?: number;
}

export interface KoonMultipartField {
  /** Field name. */
  name: string;
  /** Text value (for form fields). */
  value?: string;
  /** Binary data (for file uploads). */
  fileData?: Buffer;
  /** Filename (for file uploads). */
  filename?: string;
  /** MIME type (for file uploads). */
  contentType?: string;
}

export class Koon {
  constructor(options?: KoonOptions);

  get(url: string, options?: KoonRequestOptions): Promise<KoonResponse>;
  post(url: string, body?: Buffer, options?: KoonRequestOptions): Promise<KoonResponse>;
  put(url: string, body?: Buffer, options?: KoonRequestOptions): Promise<KoonResponse>;
  delete(url: string, options?: KoonRequestOptions): Promise<KoonResponse>;
  patch(url: string, body?: Buffer, options?: KoonRequestOptions): Promise<KoonResponse>;
  head(url: string, options?: KoonRequestOptions): Promise<KoonResponse>;
  request(method: string, url: string, body?: Buffer, options?: KoonRequestOptions): Promise<KoonResponse>;
  postMultipart(url: string, fields: KoonMultipartField[], options?: KoonRequestOptions): Promise<KoonResponse>;
  requestStreaming(method: string, url: string, body?: Buffer, options?: KoonRequestOptions): Promise<KoonStreamingResponse>;

  websocket(url: string, headers?: Record<string, string>): Promise<KoonWebSocket>;

  exportProfile(): string;
  saveSession(): string;
  loadSession(json: string): void;
  saveSessionToFile(path: string): void;
  loadSessionFromFile(path: string): void;
}

export class KoonStreamingResponse {
  readonly status: number;
  readonly headers: Array<{ name: string; value: string }>;
  readonly version: string;
  readonly url: string;

  nextChunk(): Promise<Buffer | null>;
  collect(): Promise<Buffer>;
}

export class KoonWebSocket {
  send(data: string | Buffer): Promise<void>;
  receive(): Promise<KoonWsMessage | null>;
  close(code?: number, reason?: string): Promise<void>;
}

export interface KoonProxyOptions {
  /** Browser profile. Default: "chrome". */
  browser?: Browser;
  /** Custom profile JSON. */
  profileJson?: string;
  /** Listen address. Default: "127.0.0.1:0". */
  listenAddr?: string;
  /** Header mode: "forward", "replace", or "merge". */
  headerMode?: string;
  /** CA certificate directory. */
  caDir?: string;
  /** Request timeout in milliseconds. Default: 30000. */
  timeout?: number;
  /** Apply fingerprint randomization. */
  randomize?: boolean;
}

export class KoonProxy {
  static start(options?: KoonProxyOptions): Promise<KoonProxy>;

  readonly port: number;
  readonly url: string;
  readonly caCertPath: string;

  caCertPem(): Buffer;
  shutdown(): Promise<void>;
}
