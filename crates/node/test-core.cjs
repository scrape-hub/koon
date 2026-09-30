// Offline tests: the plain request/response path, profile resolution, error
// codes, cookies, hooks and shutdown.
const os = require('node:os');
const { pathToFileURL } = require('node:url');

const {
  INDEX,
  BINARY,
  check,
  expectThrows,
  withTimeout,
  runChild,
  runChildJson,
  listen,
  close,
  startHttpServer,
} = require('./test-helpers.cjs');

const path = require('node:path');
const { Koon, KoonProxy, KoonResponse } = require(INDEX);

async function testEsmNamedImport() {
  console.log('index.js exposes named exports for ESM (cjs-module-lexer)');
  const mod = await import(pathToFileURL(INDEX).href);
  for (const name of ['Koon', 'KoonProxy', 'KoonResponse', 'KoonStreamingResponse', 'KoonWebSocket', 'koonFetch']) {
    check(`named export ${name}`, typeof mod[name] === 'function', typeof mod[name]);
  }
}

async function testLatestProfiles() {
  console.log('latest profile of every browser resolves to the current core version');
  const expected = [
    ['chrome', 'Chrome/155'],
    ['firefox', 'Firefox/157'],
    ['edge', 'Edg/154'],
    ['opera', 'OPR/136'],
    ['safari', 'Version/27.0'],
    ['chrome-mobile', 'Chrome/155'],
    ['firefox-mobile', 'Firefox/157'],
    ['safari-mobile', 'Version/27.0'],
    ['okhttp', 'okhttp/5'],
  ];
  for (const [browser, marker] of expected) {
    const ua = new Koon({ browser }).userAgent;
    check(`${browser} -> ${marker}`, ua.includes(marker), ua);
  }
  check('bare name is Windows', new Koon({ browser: 'chrome' }).userAgent.includes('Windows NT'));
  check('bare safari is macOS', new Koon({ browser: 'safari' }).userAgent.includes('Macintosh'));
  check('-macos selects macOS', new Koon({ browser: 'chrome-macos' }).userAgent.includes('Macintosh'));
}

async function testBrowsers() {
  console.log('Koon.browsers() lists every profile, each of which resolves');
  const names = Koon.browsers();
  check('an array of strings', Array.isArray(names) && names.length > 200 && names.every((n) => typeof n === 'string'), names.length);
  check('names carry version and OS', names.includes('chrome131-windows') && names.includes('okhttp5'), names.slice(0, 3));
  check('no name is listed twice', new Set(names).size === names.length);
  const sample = names.filter((_, i) => i % 25 === 0);
  check('listed names resolve', sample.every((browser) => new Koon({ browser }).userAgent), JSON.stringify(sample));
}

async function testErrorCodes() {
  console.log('err.code is set everywhere, including the constructor');
  const client = new Koon();

  await expectThrows(() => new Koon({ browser: 'chrome999' }), 'unknown profile', 'INVALID_ARGUMENT');
  try {
    new Koon({ browser: 'chrome999' });
  } catch (err) {
    check('unknown profile names the supported range', /131-\d+/.test(err.message), err.message);
    check('message keeps the [CODE] prefix', err.message.startsWith('[INVALID_ARGUMENT] '), err.message);
  }
  await expectThrows(() => new Koon({ profileJson: '{' }), 'malformed profileJson', 'JSON_ERROR');
  await expectThrows(() => new Koon({ proxy: 'ftp://proxy:21' }), 'unsupported proxy scheme', 'PROXY_ERROR');
  await expectThrows(() => new Koon({ proxies: ['nonsense'] }), 'invalid proxy list', 'PROXY_ERROR');
  await expectThrows(() => new Koon({ doh: 'quad9' }), 'unknown DoH provider', 'INVALID_ARGUMENT');
  await expectThrows(() => new Koon({ localAddress: 'nope' }), 'invalid localAddress', 'INVALID_ARGUMENT');
  await expectThrows(() => new Koon({ ipVersion: 5 }), 'ipVersion 5', 'INVALID_ARGUMENT');
  await expectThrows(() => new Koon({ ipVersion: 4.5 }), 'ipVersion 4.5', 'INVALID_ARGUMENT');
  await expectThrows(() => new Koon({ headers: { 'bad header': 'x' } }), 'invalid client header', 'INVALID_HEADER');
  await expectThrows(() => new Koon({ timeout: 'soon' }), 'napi type error in the constructor', 'INVALID_ARGUMENT');
  await expectThrows(() => client.request(42, 'http://127.0.0.1/'), 'napi type error in a method', 'INVALID_ARGUMENT');
  await expectThrows(() => client.request('BAD METHOD', 'http://127.0.0.1/'), 'invalid method', 'INVALID_ARGUMENT');
  await expectThrows(() => client.get('ftp://example.com/'), 'unsupported URL scheme', 'INVALID_URL');
  await expectThrows(() => client.loadSession('not json'), 'loadSession with bad JSON', 'JSON_ERROR');
  await expectThrows(
    () => client.loadSessionFromFile(path.join(os.tmpdir(), 'koon-missing', 'session.json')),
    'loadSessionFromFile of a missing file',
    'IO_ERROR'
  );
  await expectThrows(() => KoonProxy.start({ headerMode: 'bogus' }), 'KoonProxy.start with bad headerMode', 'INVALID_ARGUMENT');

  const profile = client.exportProfile();
  check('exportProfile round-trips', new Koon({ profileJson: profile }).userAgent === client.userAgent);
}

async function testNumericOptions() {
  console.log('numeric options are validated instead of wrapped by ToUint32');
  for (const timeout of [-1, NaN, Infinity]) {
    await expectThrows(() => new Koon({ timeout }), `client timeout ${timeout}`, 'INVALID_ARGUMENT');
    await expectThrows(
      () => new Koon().get('http://127.0.0.1:1/', { timeout }),
      `request timeout ${timeout}`,
      'INVALID_ARGUMENT'
    );
  }
  check('client timeout 0.5 is accepted', new Koon({ timeout: 0.5 }) instanceof Koon);
  check('client timeout 0 (none) is accepted', new Koon({ timeout: 0 }) instanceof Koon);
  await expectThrows(() => new Koon({ maxRedirects: -1 }), 'maxRedirects -1', 'INVALID_ARGUMENT');
  await expectThrows(() => new Koon({ maxRedirects: 1.5 }), 'maxRedirects 1.5', 'INVALID_ARGUMENT');
  await expectThrows(() => new Koon({ retries: -1 }), 'retries -1', 'INVALID_ARGUMENT');
  await expectThrows(() => new Koon({ retries: 2 ** 40 }), 'retries beyond u32', 'INVALID_ARGUMENT');
  await expectThrows(() => KoonProxy.start({ timeout: -1 }), 'proxy timeout -1', 'INVALID_ARGUMENT');
  await expectThrows(() => KoonProxy.start({ retries: 1.5 }), 'proxy retries 1.5', 'INVALID_ARGUMENT');
  await expectThrows(() => new Koon({ maxResponseBody: -1 }), 'maxResponseBody -1', 'INVALID_ARGUMENT');
  await expectThrows(() => new Koon({ maxResponseBody: 1.5 }), 'maxResponseBody 1.5', 'INVALID_ARGUMENT');
  await expectThrows(() => new Koon({ serverPadding: 'bogus' }), 'serverPadding bogus', 'INVALID_ARGUMENT');
  check('serverPadding: none is accepted', new Koon({ serverPadding: 'none' }) instanceof Koon);
  check('serverPadding: bytes is accepted', new Koon({ serverPadding: '9000' }) instanceof Koon);
}

// The extension types (in order) of a raw TLS 1.3 ClientHello record.
function clientHelloExtensionTypes(record) {
  let p = 5 + 4 + 2 + 32; // record header, handshake header, legacy_version, random
  p += 1 + record[p]; // session_id
  p += 2 + record.readUInt16BE(p); // cipher_suites
  p += 1 + record[p]; // compression_methods
  const end = p + 2 + record.readUInt16BE(p);
  p += 2;
  const types = [];
  while (p < end) {
    types.push(record.readUInt16BE(p));
    p += 4 + record.readUInt16BE(p + 2);
  }
  return types;
}

// Captures the first TLS record koon sends when told to connect to
// 127.0.0.1:PORT, where a plain TCP server (no real TLS) is listening: no
// handshake response ever arrives, so the request itself always fails --
// only the raw bytes it sent are of interest.
function captureClientHello(options) {
  const net = require('node:net');
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const server = net.createServer((socket) => {
      socket.on('data', (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        if (buf.length < 5) return;
        const len = 5 + buf.readUInt16BE(3);
        if (buf.length < len) return;
        server.close();
        socket.destroy();
        resolve(clientHelloExtensionTypes(buf.subarray(0, len)));
      });
    });
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      new Koon({ ignoreTlsErrors: true, timeout: 0.3, ...options })
        .get(`https://127.0.0.1:${port}/`)
        .catch(() => {});
    });
  });
}

async function testServerPadding() {
  console.log('serverPadding: none removes extension 0x12e0, pinned bytes send it');
  const SERVER_PADDING = 0x12e0;
  const withNone = await captureClientHello({ browser: 'chrome153', serverPadding: 'none' });
  check('serverPadding: none has no 0x12e0 extension', !withNone.includes(SERVER_PADDING), withNone);
  const withBytes = await captureClientHello({ browser: 'chrome153', serverPadding: '9000' });
  check('serverPadding: bytes sends the 0x12e0 extension', withBytes.includes(SERVER_PADDING), withBytes);
  // Firefox does not run this trial: unaffected either way.
  const firefox = await captureClientHello({ browser: 'firefox156', serverPadding: '9000' });
  check("serverPadding has no effect on a profile without the trial", !firefox.includes(SERVER_PADDING), firefox);
}

async function testMaxResponseBody() {
  console.log('maxResponseBody caps a response body');
  const http = require('node:http');
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('x'.repeat(1000));
  });
  const port = await listen(server);
  const url = `http://127.0.0.1:${port}/`;
  try {
    const small = await new Koon({ maxResponseBody: 100 }).get(url).catch((e) => e);
    check('a body over the cap fails with BODY_ERROR', small.code === 'BODY_ERROR', small.message);
    check('the message names the cap', small.message.includes('100 bytes'), small.message);

    const ok = await new Koon().get(url);
    check('the default cap (100 MiB) allows a 1000-byte body', ok.status === 200 && ok.body.length === 1000);

    const unlimited = await new Koon({ maxResponseBody: 0 }).get(url);
    check('0 disables the cap', unlimited.status === 200 && unlimited.body.length === 1000);
  } finally {
    await close(server);
  }
}

async function testCookies() {
  console.log('cookies go through the core CookieParams conversion');
  const client = new Koon();

  const none = client.setCookies([{ name: 'session', value: 'abc', domain: 'example.com', secure: true, httpOnly: true, sameSite: 'lax' }]);
  check('setCookies returns [] when every cookie is imported', Array.isArray(none) && none.length === 0, JSON.stringify(none));
  let [cookie] = client.cookies();
  check('host-only cookie keeps its domain', cookie.domain === 'example.com', JSON.stringify(cookie));
  check('hostOnly true', cookie.hostOnly === true);
  check('path defaults to /', cookie.path === '/');
  check('expires -1 for a session cookie', cookie.expires === -1, cookie.expires);
  check('sameSite is case-insensitive and exported canonical', cookie.sameSite === 'Lax', cookie.sameSite);
  check('secure and httpOnly kept', cookie.secure === true && cookie.httpOnly === true);
  check('url is not exported', !('url' in cookie));

  client.setCookies(client.cookies());
  check('export feeds straight back into setCookies', client.cookies().length === 1);

  client.setCookies([{ name: 'wide', value: 'v', domain: '.Example.com', expires: 1893456000 }]);
  const wide = client.cookies().find((c) => c.name === 'wide');
  check('domain cookie keeps the leading dot, lowercased', wide.domain === '.example.com', wide.domain);
  check('domain cookie hostOnly false', wide.hostOnly === false);
  check('expires is kept in seconds', wide.expires === 1893456000, wide.expires);

  client.setCookies([{ name: 'fromUrl', value: 'v', url: 'https://Sub.Example.org/a/b?q=1' }]);
  const fromUrl = client.cookies().find((c) => c.name === 'fromUrl');
  check(
    'url gives a host-only cookie with the path up to the last /',
    fromUrl.domain === 'sub.example.org' && fromUrl.path === '/a/' && fromUrl.hostOnly === true,
    JSON.stringify(fromUrl)
  );
  check('url with https gives a secure cookie', fromUrl.secure === true);
  client.setCookies([{ name: 'plain', value: 'v', url: 'http://example.net', secure: true }]);
  const plain = client.cookies().find((c) => c.name === 'plain');
  check('url with http gives a non-secure cookie, path /', plain.secure === false && plain.path === '/', JSON.stringify(plain));

  const copy = new Koon();
  copy.setCookies(client.cookies());
  check('export round trip into another client', JSON.stringify(copy.cookies()) === JSON.stringify(client.cookies()));

  client.setCookies([{ name: 'nullKey', value: 'v', domain: 'example.com', partitionKey: null, partitionKeyOpaque: false }]);
  check('partitionKey null / partitionKeyOpaque false is not partitioned', client.cookies().some((c) => c.name === 'nullKey'));

  const invalid = [
    ['url together with domain', { name: 'x', value: 'v', url: 'https://a.example/', domain: 'a.example' }],
    ['url together with path', { name: 'x', value: 'v', url: 'https://a.example/', path: '/' }],
    ['neither url nor domain', { name: 'x', value: 'v' }],
    ['expires beyond year 9999', { name: 'x', value: 'v', domain: 'a.example', expires: 253402300800 }],
    ['unknown sameSite', { name: 'x', value: 'v', domain: 'a.example', sameSite: 'sometimes' }],
    ['invalid value', { name: 'x', value: 'one; two', domain: 'a.example' }],
  ];
  for (const [what, bad] of invalid) {
    const importing = new Koon();
    const skipped = importing.setCookies([{ name: 'ok', value: 'v', domain: 'a.example' }, bad]);
    check(
      `skips and reports ${what}`,
      skipped.length === 1 && skipped[0].index === 1 && skipped[0].name === 'x' && skipped[0].reason.length > 0,
      JSON.stringify(skipped)
    );
    check(`imports the valid cookie next to ${what}`, JSON.stringify(importing.cookies().map((c) => c.name)) === '["ok"]');
  }

  const skipping = new Koon();
  const partitioned = skipping.setCookies([
    { name: 'kept', value: 'v', domain: 'a.example' },
    { name: 'cdp', value: 'v', domain: 'a.example', partitionKey: { topLevelSite: 'https://a.example' } },
    { name: 'pw', value: 'v', domain: 'a.example', partitionKey: 'https://a.example' },
    { name: 'opaque', value: 'v', domain: 'a.example', partitionKeyOpaque: true },
  ]);
  check(
    'partitioned cookies are skipped, the rest is imported',
    JSON.stringify(skipping.cookies().map((c) => c.name)) === JSON.stringify(['kept']),
    JSON.stringify(skipping.cookies().map((c) => c.name))
  );
  check(
    'partitioned cookies are reported',
    JSON.stringify(partitioned.map((c) => [c.index, c.name])) === JSON.stringify([[1, 'cdp'], [2, 'pw'], [3, 'opaque']]) &&
      partitioned.every((c) => c.reason.includes('partitioned')),
    JSON.stringify(partitioned)
  );

  await expectThrows(
    () => new Koon({ cookieJar: false }).setCookies([{ name: 'a', value: 'b', domain: 'example.com' }]),
    'cookie jar disabled',
    'COOKIE_JAR_DISABLED'
  );
}

async function testLocalHttp() {
  console.log('local HTTP server: verbs, headers, redirects, hooks, timeouts, responses');
  const server = startHttpServer();
  const port = await listen(server);
  const base = `http://127.0.0.1:${port}`;
  try {
    const client = new Koon();

    const resp = await client.get(`${base}/`, { headers: { 'X-Zeta': '1', 'X-Alpha': '2' } });
    check('plain http:// request succeeds', resp.status === 200 && resp.ok && resp.statusCode === 200, resp.status);
    check('response is a KoonResponse', resp instanceof KoonResponse);
    const rawNames = resp.json().rawHeaders.filter((_, i) => i % 2 === 0);
    check(
      'custom headers keep casing and insertion order on the wire',
      rawNames.indexOf('X-Zeta') !== -1 && rawNames.indexOf('X-Zeta') < rawNames.indexOf('X-Alpha'),
      JSON.stringify(rawNames)
    );
    const sent = resp.requestHeaders.map((h) => h.name);
    check('requestHeaders reports the same order', sent.indexOf('X-Zeta') < sent.indexOf('X-Alpha'), JSON.stringify(sent));

    // Values built once per response; byte counters as numbers.
    check('headers is the same array on every access', resp.headers === resp.headers);
    check('requestHeaders is the same array on every access', resp.requestHeaders === resp.requestHeaders);
    check('body is the same Buffer on every access', resp.body === resp.body && Buffer.isBuffer(resp.body));
    check('headers are {name, value} objects', resp.headers.every((h) => typeof h.name === 'string' && typeof h.value === 'string'));
    check('duplicate headers survive', resp.headers.filter((h) => h.name === 'x-dup').length === 2, JSON.stringify(resp.headers));
    check('header() is case-insensitive', resp.header('Content-Type') === 'application/json' && resp.contentType === 'application/json');
    check('header() of a missing header is null', resp.header('x-missing') === null);
    check('text() equals the body', resp.text() === resp.body.toString('utf8'));
    check('bytesSent/bytesReceived are numbers', typeof resp.bytesSent === 'number' && resp.bytesReceived > 0, typeof resp.bytesSent);
    check('client totals are numbers', typeof client.totalBytesSent() === 'number' && client.totalBytesReceived() > 0);
    check(
      'counters serialize to JSON',
      JSON.parse(JSON.stringify({ sent: resp.bytesSent, total: client.totalBytesReceived() })).sent === resp.bytesSent
    );
    check('remoteAddress is the peer', resp.remoteAddress === '127.0.0.1', resp.remoteAddress);
    check('readonly field cannot be assigned', (() => { try { resp.status = 1; } catch { /* strict mode */ } return resp.status === 200; })());

    for (const [verb, body] of [['post', 'abc'], ['put', Buffer.from('xyz')], ['patch', 'p'], ['delete'], ['get']]) {
      const r = body === undefined ? await client[verb](`${base}/`) : await client[verb](`${base}/`, body);
      const echoed = r.json();
      check(`${verb}() sends ${verb.toUpperCase()}`, echoed.method === verb.toUpperCase() && echoed.body === (body === undefined ? '' : String(body)), JSON.stringify(echoed));
    }
    const head = await client.head(`${base}/`);
    check('head() gets an empty body', head.status === 200 && head.body.length === 0);
    const lower = await client.request('get', `${base}/`);
    check('lowercase method is sent uppercase', lower.json().method === 'GET');

    const stopped = await client.get(`${base}/redirect`, { followRedirects: false });
    check('followRedirects:false stops at the 3xx', stopped.status === 302, stopped.status);
    const inherited = Object.create({ followRedirects: false });
    const viaPrototype = await client.get(`${base}/redirect`, inherited);
    check('options without hooks are passed as-is (prototype properties kept)', viaPrototype.status === 302, viaPrototype.status);

    let seen = null;
    const followed = await client.get(`${base}/redirect`, {
      onRedirect: (status, url) => {
        seen = { status, url };
        return true;
      },
    });
    check('per-request onRedirect fires', seen && seen.status === 302, JSON.stringify(seen));
    check('redirect is followed to the target', followed.url.endsWith('/target'), followed.url);

    client.setCookies([{ name: 'local', value: '1', url: `${base}/` }]);
    const withCookie = await client.get(`${base}/`);
    check('an imported cookie is sent', withCookie.json().cookie === 'local=1', withCookie.json().cookie);

    const start = Date.now();
    await expectThrows(
      () => withTimeout(client.get(`${base}/slow`, { timeout: 0.5 }), 5000, 'timeout 0.5'),
      'fractional per-request timeout fires',
      'TIMEOUT'
    );
    check('fractional timeout is not rounded down to "none"', Date.now() - start < 3000, `${Date.now() - start}ms`);

    const streaming = await client.requestStreaming('GET', `${base}/stream`);
    check('streaming status', streaming.status === 200 && streaming.statusCode === 200);
    check('streaming headers are the same array on every access', streaming.headers === streaming.headers);
    check('streaming bytesSent is a number', typeof streaming.bytesSent === 'number' && streaming.bytesSent > 0);
    const chunks = [];
    for (let chunk = await streaming.nextChunk(); chunk !== null; chunk = await streaming.nextChunk()) chunks.push(chunk);
    check('streaming body arrives in full', Buffer.concat(chunks).toString() === 'first,second', Buffer.concat(chunks).toString());
    check('streaming bytesReceived() is a number', typeof streaming.bytesReceived() === 'number' && streaming.bytesReceived() > 0);
    const rest = await streaming.collect();
    check('collect() after the end is empty', rest.length === 0);
    await expectThrows(() => streaming.nextChunk(), 'nextChunk() after collect()', 'BODY_ERROR');
    await expectThrows(() => streaming.collect(), 'collect() after collect()', 'BODY_ERROR');

    const iterated = await client.requestStreaming('GET', `${base}/stream`);
    check('streaming response is async iterable', typeof iterated[Symbol.asyncIterator] === 'function');
    const pieces = [];
    for await (const chunk of iterated) pieces.push(chunk);
    check(
      'for await reads the whole body as Buffers',
      pieces.every(Buffer.isBuffer) && Buffer.concat(pieces).toString() === 'first,second',
      Buffer.concat(pieces).toString()
    );

    // Headers as [name, value] pairs (repeating a name) and as other iterables.
    const pairClient = new Koon({ headers: [['X-Client-B', 'b'], ['X-Client-A', 'a']] });
    const pairs = await pairClient.get(`${base}/`, {
      headers: [['X-Req-Z', 'z'], ['X-Req-Y', 'y1'], ['x-req-y', 'y2']],
    });
    const pairRaw = pairs.json().rawHeaders;
    const pairNames = pairRaw.filter((_, i) => i % 2 === 0);
    check(
      'header pairs keep their order (client and request)',
      pairNames.indexOf('X-Client-B') < pairNames.indexOf('X-Client-A') && pairNames.indexOf('X-Req-Z') < pairNames.indexOf('X-Req-Y'),
      JSON.stringify(pairNames)
    );
    check(
      'a name repeated in pairs is sent once, with the last value',
      pairNames.filter((n) => n.toLowerCase() === 'x-req-y').length === 1 && pairRaw[pairRaw.indexOf('X-Req-Y') + 1] === 'y2',
      JSON.stringify(pairRaw)
    );
    const fromMap = await client.get(`${base}/`, { headers: new Map([['X-From-Map', 'm']]) });
    check('a Map of headers is sent', fromMap.json().rawHeaders.includes('X-From-Map'), JSON.stringify(fromMap.json().rawHeaders));
    const fromHeaders = await client.get(`${base}/`, { headers: new Headers({ 'X-From-Headers': 'h' }) });
    check('a fetch Headers object is sent', fromHeaders.json().rawHeaders.includes('x-from-headers'), JSON.stringify(fromHeaders.json().rawHeaders));
    await expectThrows(() => client.get(`${base}/`, { headers: [['X-Only-Name']] }), 'a pair without a value', 'INVALID_ARGUMENT');
    await expectThrows(() => new Koon({ headers: [['a', 'b', 'c']] }), 'a pair with three elements', 'INVALID_ARGUMENT');
    await expectThrows(() => client.get(`${base}/`, { headers: [['X-A', 1]] }), 'a pair with a number', 'INVALID_ARGUMENT');

    // resolve: a host name that only the entry resolves.
    const resolving = new Koon({ resolve: [`koon.test:${port}:127.0.0.1`] });
    const resolved = await resolving.get(`http://koon.test:${port}/`);
    check('resolve connects to the given address', resolved.status === 200 && resolved.remoteAddress === '127.0.0.1', resolved.remoteAddress);
    await expectThrows(() => new Koon({ resolve: ['koon.test:80'] }), 'an invalid resolve entry', 'INVALID_ARGUMENT');
  } finally {
    await close(server);
  }
}

async function testShutdown() {
  console.log('shutdown() resolves once the connections are closed; the client stays usable');
  const server = startHttpServer();
  const port = await listen(server);
  const base = `http://127.0.0.1:${port}`;
  try {
    const client = new Koon();
    check('request before shutdown', (await client.get(`${base}/`)).status === 200);
    const pending = client.shutdown();
    check('shutdown() returns a promise', pending instanceof Promise);
    check('shutdown() resolves to undefined', (await pending) === undefined);
    check('request after shutdown', (await client.get(`${base}/`)).status === 200);
    await client.shutdown();
  } finally {
    await close(server);
  }
}

async function testHooksAreSafe() {
  console.log('non-boolean or failing onRedirect hooks neither crash nor misbehave');
  const script = `
    const { Koon } = require(${JSON.stringify(INDEX)});
    const http = require('node:http');
    let asyncWarnings = 0;
    let failureWarnings = 0;
    process.on('warning', (w) => {
      if (w.code === 'KOON_ASYNC_HOOK') asyncWarnings++;
      if (w.message.includes("the Promise the 'onRedirect' hook returned rejected")) failureWarnings++;
    });
    const server = http.createServer((req, res) => {
      if (req.url === '/redirect') { res.writeHead(302, { Location: '/target' }); res.end(); return; }
      res.writeHead(200); res.end('ok');
    });
    server.listen(0, '127.0.0.1', async () => {
      const url = 'http://127.0.0.1:' + server.address().port + '/redirect';
      const hooks = {
        undefined: () => {},
        logging: (s, u) => void String(u),
        promise: async () => false,
        rejecting: async () => { throw new Error('async boom'); },
        one: () => 1,
        false: () => false,
      };
      const result = {};
      for (const [name, onRedirect] of Object.entries(hooks)) {
        const resp = await new Koon({ onRedirect }).get(url);
        result[name] = resp.status;
      }
      const boom = new Error('boom');
      try {
        await new Koon({ onRedirect: () => { throw boom; } }).get(url);
        result.throwing = 'resolved';
      } catch (err) {
        result.throwing = err === boom ? 'own error' : String(err);
      }
      const perRequest = await new Koon().get(url, { onRedirect: () => undefined });
      result.perRequest = perRequest.status;
      // The warnings are emitted after the request they came from already
      // resolved; poll for both instead of a fixed sleep.
      for (let i = 0; i < 100 && (asyncWarnings < 1 || failureWarnings < 1); i++) {
        await new Promise((r) => setTimeout(r, 20));
      }
      result.asyncWarnings = asyncWarnings;
      result.failureWarnings = failureWarnings;
      server.close();
      console.log(JSON.stringify(result));
    });
  `;
  const result = runChildJson(script, 'hook child process completed');
  if (result) {
    for (const name of ['undefined', 'logging', 'promise', 'rejecting', 'one', 'perRequest']) {
      check(`onRedirect returning ${name} follows`, result[name] === 200, JSON.stringify(result));
    }
    check('onRedirect returning false stops', result.false === 302, result.false);
    check('a throwing onRedirect fails the request with its own error', result.throwing === 'own error', result.throwing);
    check('a Promise from onRedirect warns once', result.asyncWarnings === 1, result.asyncWarnings);
    check('a rejecting hook is reported', result.failureWarnings === 1, result.failureWarnings);
  }

  // The native layer on its own, without index.js wrapping the hook.
  const raw = `
    const { Koon } = require(${JSON.stringify(BINARY)});
    const http = require('node:http');
    const server = http.createServer((req, res) => {
      if (req.url === '/redirect') { res.writeHead(302, { Location: '/target' }); res.end(); return; }
      res.writeHead(200); res.end('ok');
    });
    server.listen(0, '127.0.0.1', async () => {
      const url = 'http://127.0.0.1:' + server.address().port + '/redirect';
      const followed = await new Koon({ onRedirect: () => undefined }).request('GET', url);
      const stopped = await new Koon({ onRedirect: () => false }).request('GET', url);
      server.close();
      console.log(JSON.stringify([followed.status, stopped.status]));
    });
  `;
  const rawResult = runChildJson(raw, 'native layer survives a non-boolean onRedirect');
  if (rawResult) {
    const [followed, stopped] = rawResult;
    check('native layer: onRedirect returning undefined follows instead of aborting', followed === 200, followed);
    check('native layer: onRedirect returning false stops', stopped === 302, stopped);
  }
}

async function testHooksDontKeepProcessAlive() {
  console.log('client hooks do not keep the process alive');
  const script = `
    const { Koon } = require(${JSON.stringify(INDEX)});
    new Koon({ onRequest: () => {}, onResponse: () => {}, onRedirect: () => true });
  `;
  try {
    runChild(script);
    check('child process exited on its own', true);
  } catch (err) {
    check('child process exited on its own', false, err.message);
  }
}

async function testHookErrorsFailTheRequest() {
  console.log('a hook that throws fails the request with what it threw');
  const script = `
    const { Koon } = require(${JSON.stringify(INDEX)});
    const http = require('node:http');
    let requests = 0;
    const server = http.createServer((req, res) => {
      requests++;
      if (req.url === '/redirect') { res.writeHead(302, { Location: '/target' }); res.end(); return; }
      res.writeHead(200); res.end('ok');
    });
    server.listen(0, '127.0.0.1', async () => {
      const base = 'http://127.0.0.1:' + server.address().port;
      const result = {};
      const outcome = async (name, run, expected) => {
        try {
          await run();
          result[name] = 'resolved';
        } catch (err) {
          result[name] = err === expected ? 'own' : (err && err.message) + ' / ' + (err && err.code);
        }
      };
      const boom = new Error('[FAKE_CODE] boom');
      await outcome('client onRequest', () => new Koon({ onRequest: () => { throw boom; } }).get(base + '/'), boom);
      result.sentAfterOnRequest = requests;
      const perRequest = new TypeError('per request');
      await outcome('per-request onRequest', () => new Koon().get(base + '/', { onRequest: () => { throw perRequest; } }), perRequest);
      result.sentAfterPerRequest = requests;
      const inResponse = new RangeError('response');
      await outcome('onResponse', () => new Koon().get(base + '/', { onResponse: () => { throw inResponse; } }), inResponse);
      result.sentAfterOnResponse = requests;
      const primitive = 'a string';
      await outcome('a thrown string', () => new Koon({ onRequest: () => { throw primitive; } }).get(base + '/'), primitive);
      const inStream = new Error('stream');
      await outcome('requestStreaming', () => new Koon().requestStreaming('GET', base + '/', undefined, { onResponse: () => { throw inStream; } }), inStream);
      const redirect = new Error('redirect');
      await outcome('onRedirect', () => new Koon().get(base + '/redirect', { onRedirect: () => { throw redirect; } }), redirect);
      result.sentAfterRedirect = requests;
      result.codeUntouched = boom.code === undefined && boom.message === '[FAKE_CODE] boom';
      const client = new Koon({ onRequest: () => {} });
      result.stillWorks = (await client.get(base + '/')).status;
      server.close();
      console.log(JSON.stringify(result));
    });
  `;
  const result = runChildJson(script, 'hook error child process completed');
  if (result) {
    for (const name of ['client onRequest', 'per-request onRequest', 'onResponse', 'a thrown string', 'requestStreaming', 'onRedirect']) {
      check(`${name}: rejects with the thrown value itself`, result[name] === 'own', result[name]);
    }
    check('a throwing onRequest sends nothing', result.sentAfterOnRequest === 0 && result.sentAfterPerRequest === 0, JSON.stringify(result));
    check('a throwing onResponse got its response', result.sentAfterOnResponse === 1, result.sentAfterOnResponse);
    check('a throwing onRedirect does not follow', result.sentAfterRedirect === 3, result.sentAfterRedirect);
    check('the thrown error gets no code', result.codeUntouched === true);
    check('hooks that return keep working', result.stillWorks === 200, result.stillWorks);
  }
}

async function run() {
  await testEsmNamedImport();
  await testLatestProfiles();
  await testErrorCodes();
  await testNumericOptions();
  await testCookies();
  await testLocalHttp();
  await testMaxResponseBody();
  await testServerPadding();
  await testShutdown();
  await testHooksAreSafe();
  await testHooksDontKeepProcessAlive();
  await testHookErrorsFailTheRequest();
  await testBrowsers();
}

module.exports = { run };
