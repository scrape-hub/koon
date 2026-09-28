// Offline test: koonFetch, a fetch() with the fingerprint, resolving to a
// standard Response.
const zlib = require('node:zlib');
const http = require('node:http');

const { INDEX, check, withTimeout, caught, closedPort, listen, close, startHttpServer } = require('./test-helpers.cjs');
const { Koon, koonFetch } = require(INDEX);

// A server for koonFetch: echoes requests like startHttpServer, plus a gzip
// body, a body held back until `gate()` is called, a redirect that sets a
// cookie, a status fetch's Response constructor refuses, and a 204.
function startFetchServer() {
  let openGate;
  let gateOpened = new Promise((resolve) => (openGate = resolve));
  // The echo handler of startHttpServer answers everything else.
  const echo = startHttpServer().listeners('request')[0];
  const server = http.createServer((req, res) => {
    if (req.url === '/gzip') {
      const data = zlib.gzipSync(FETCH_TEXT);
      res.writeHead(200, { 'content-type': 'text/plain', 'content-encoding': 'gzip', 'content-length': data.length, 'set-cookie': ['a=1', 'b=2'] });
      res.end(data);
    } else if (req.url === '/gated') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.write('first;');
      gateOpened.then(() => res.end('second'));
    } else if (req.url === '/cookie-redirect') {
      res.writeHead(302, { location: '/echo', 'set-cookie': 'hop=1; Path=/' });
      res.end();
    } else if (req.url === '/odd-status') {
      res.writeHead(999, { 'content-type': 'text/plain' });
      res.end('blocked');
    } else if (req.url === '/no-content') {
      res.writeHead(204);
      res.end();
    } else {
      echo(req, res);
    }
  });
  server.gate = () => {
    openGate();
    gateOpened = new Promise((resolve) => (openGate = resolve));
  };
  return server;
}

const FETCH_TEXT = 'koon decodes this body once. '.repeat(200);

async function testKoonFetch() {
  console.log('koonFetch: a fetch() with the fingerprint, resolving to a standard Response');
  const server = startFetchServer();
  const port = await listen(server);
  const base = `http://127.0.0.1:${port}`;
  const names = (json) => json.rawHeaders.filter((_, i) => i % 2 === 0);
  const received = (json, name) => {
    const i = json.rawHeaders.findIndex((n, j) => j % 2 === 0 && n.toLowerCase() === name);
    return i === -1 ? null : json.rawHeaders[i + 1];
  };
  try {
    const fetch = koonFetch({ browser: 'chrome' });
    check('fetch.client is the Koon client', fetch.client instanceof Koon);
    check('koonFetch(client) uses that client', koonFetch(fetch.client).client === fetch.client);

    // Headers: koon's, in the browser's order; none of Node's fetch.
    const r = await fetch(`${base}/echo`);
    check('a standard Response', r instanceof Response && r.status === 200 && r.ok && r.statusText === 'OK', r.status);
    check('url and redirected', r.url === `${base}/echo` && r.redirected === false, r.url);
    const echoed = await r.json();
    const native = (await fetch.client.get(`${base}/echo`)).json();
    check(
      'the same headers as koon sends itself, in the same order',
      JSON.stringify(echoed.rawHeaders) === JSON.stringify(native.rawHeaders),
      JSON.stringify(names(echoed))
    );
    check('no header of Node\'s own fetch', !echoed.rawHeaders.includes('node') && received(echoed, 'user-agent').includes('Chrome/'), received(echoed, 'user-agent'));

    const custom = await (
      await fetch(`${base}/echo`, { headers: { 'X-Zeta': '1', 'X-Alpha': '2', Accept: 'application/json' } })
    ).json();
    const customNames = names(custom);
    check('caller headers keep their order and casing', customNames.indexOf('X-Zeta') < customNames.indexOf('X-Alpha'), JSON.stringify(customNames));
    check('a caller header replaces the browser one', received(custom, 'accept') === 'application/json', received(custom, 'accept'));
    const fromHeaders = await (await fetch(`${base}/echo`, { headers: new Headers([['X-H', 'h']]) })).json();
    check('headers from a Headers object', received(fromHeaders, 'x-h') === 'h');
    const fromPairs = await (await fetch(`${base}/echo`, { headers: [['X-P', 'a'], ['x-p', 'b']] })).json();
    check('a repeated name is joined as Headers joins it', received(fromPairs, 'x-p') === 'a, b', received(fromPairs, 'x-p'));

    // Bodies and their Content-Type.
    const bodies = [
      ['a string', 'text', 'text', 'text/plain;charset=UTF-8'],
      ['URLSearchParams', new URLSearchParams({ k: 'v' }), 'k=v', 'application/x-www-form-urlencoded;charset=UTF-8'],
      ['a Uint8Array', new Uint8Array([104, 105]), 'hi', null],
      ['an ArrayBuffer', new Uint8Array([104, 105]).buffer, 'hi', null],
      ['a Blob', new Blob(['blob'], { type: 'text/x-blob' }), 'blob', 'text/x-blob'],
      ['a ReadableStream', new Blob(['str', 'eam']).stream(), 'stream', null],
    ];
    for (const [what, body, expected, type] of bodies) {
      const sent = await (await fetch(`${base}/echo`, { method: 'post', body })).json();
      check(`POST with ${what}`, sent.method === 'POST' && sent.body === expected && received(sent, 'content-type') === type, JSON.stringify([sent.body, received(sent, 'content-type')]));
    }
    const form = new FormData();
    form.append('field', 'value');
    form.append('upload', new Blob(['file content'], { type: 'text/plain' }), 'a.txt');
    const multipart = await (await fetch(`${base}/echo`, { method: 'POST', body: form })).json();
    check(
      'a FormData goes as multipart with the browser boundary',
      received(multipart, 'content-type').startsWith('multipart/form-data; boundary=----WebKitFormBoundary') &&
        multipart.body.includes('name="field"\r\n\r\nvalue') &&
        multipart.body.includes('filename="a.txt"') &&
        multipart.body.includes('file content'),
      received(multipart, 'content-type')
    );
    const fromRequest = await (
      await fetch(new Request(`${base}/echo`, { method: 'PUT', body: 'from request', headers: { 'X-R': 'r' } }))
    ).json();
    check('a Request as input', fromRequest.method === 'PUT' && fromRequest.body === 'from request' && received(fromRequest, 'x-r') === 'r', JSON.stringify(fromRequest.method));
    check('a URL as input', (await fetch(new URL(`${base}/echo`))).status === 200);
    check('GET with a body rejects', (await caught(() => fetch(`${base}/echo`, { body: 'x' }))) instanceof TypeError);

    // Responses.
    const gz = await fetch(`${base}/gzip`);
    check('a gzip body is decoded once', (await gz.text()) === FETCH_TEXT);
    check('without Content-Encoding and Content-Length', !gz.headers.has('content-encoding') && !gz.headers.has('content-length'), JSON.stringify([...gz.headers]));
    check('Set-Cookie headers stay apart', JSON.stringify(gz.headers.getSetCookie()) === '["a=1","b=2"]', JSON.stringify(gz.headers.getSetCookie()));
    const bytes = await (await fetch(`${base}/gzip`)).arrayBuffer();
    check('arrayBuffer()', bytes instanceof ArrayBuffer && Buffer.from(bytes).toString() === FETCH_TEXT);
    const head = await fetch(`${base}/echo`, { method: 'HEAD' });
    check('HEAD has no body', head.body === null && head.status === 200);
    const empty = await fetch(`${base}/no-content`);
    check('204 has no body', empty.status === 204 && empty.body === null);
    const odd = await fetch(`${base}/odd-status`);
    check('a status outside 200-599 is kept', odd.status === 999 && odd.ok === false && (await odd.text()) === 'blocked', odd.status);
    const original = await fetch(`${base}/echo`);
    const copy = original.clone();
    check('clone() keeps the url', copy.url === original.url && (await copy.json()).method === 'GET', copy.url);

    // Redirects: koon follows them for redirect 'follow'.
    const followed = await fetch(`${base}/redirect`);
    check("redirect 'follow'", followed.status === 200 && followed.redirected && followed.url === `${base}/target`, followed.url);
    const manual = await fetch(`${base}/redirect`, { redirect: 'manual' });
    check("redirect 'manual' returns the 3xx", manual.status === 302 && manual.headers.get('location') === '/target' && !manual.redirected);
    const error = await caught(() => fetch(`${base}/redirect`, { redirect: 'error' }));
    check("redirect 'error' rejects", error instanceof TypeError && error.message === 'fetch failed', error && error.message);

    // Cookies: the client's jar, as a browser keeps them.
    const jarFetch = koonFetch();
    await (await jarFetch(`${base}/cookie-redirect`, { redirect: 'manual' })).text();
    const withCookie = await (await jarFetch(`${base}/echo`)).json();
    check('a cookie set by a response is sent', received(withCookie, 'cookie') === 'hop=1', received(withCookie, 'cookie'));
    check("credentials 'omit' is refused", (await caught(() => jarFetch(`${base}/echo`, { credentials: 'omit' }))) instanceof TypeError);

    // Streaming: the body arrives as the server sends it.
    const streamed = await fetch(`${base}/gated`);
    const reader = streamed.body.getReader();
    let first = '';
    while (first.length < 'first;'.length) {
      first += Buffer.from((await withTimeout(reader.read(), 5000, 'the first chunk')).value).toString();
    }
    check('the first chunk arrives before the server sends the rest', first === 'first;', first);
    server.gate();
    let rest = '';
    for (let part = await reader.read(); !part.done; part = await reader.read()) rest += Buffer.from(part.value).toString();
    check('the rest follows', rest === 'second', rest);
    const cancelled = await fetch(`${base}/gated`);
    const cancelReader = cancelled.body.getReader();
    await cancelReader.read();
    await cancelReader.cancel();
    server.gate();
    check('after cancel() the client goes on', (await fetch(`${base}/echo`)).status === 200);

    // AbortSignal: before the head, during the body, already aborted.
    const controller = new AbortController();
    const started = Date.now();
    setTimeout(() => controller.abort(), 100);
    const abortedHead = await caught(() => fetch(`${base}/slow`, { signal: controller.signal }));
    check('abort before the response head rejects with AbortError', abortedHead && abortedHead.name === 'AbortError' && Date.now() - started < 3000, abortedHead && abortedHead.name);
    const bodyController = new AbortController();
    const abortedBody = await fetch(`${base}/gated`, { signal: bodyController.signal });
    const bodyReader = abortedBody.body.getReader();
    await bodyReader.read();
    bodyController.abort();
    const readError = await caught(() => bodyReader.read());
    check('abort during the body errors the stream with AbortError', readError && readError.name === 'AbortError', readError && readError.name);
    server.gate();
    const early = await caught(() => fetch(`${base}/echo`, { signal: AbortSignal.abort() }));
    check('an aborted signal rejects at once', early && early.name === 'AbortError');

    // Errors: TypeError('fetch failed') with the koon error as cause.
    const freePort = await closedPort();
    const refused = await caught(() => fetch(`http://127.0.0.1:${freePort}/`));
    check('connection refused', refused instanceof TypeError && refused.message === 'fetch failed' && typeof refused.cause.code === 'string', refused && refused.cause && refused.cause.code);
    const timedOut = await caught(() => koonFetch({ timeout: 0.5 })(`${base}/slow`));
    check("the client's timeout", timedOut instanceof TypeError && timedOut.cause.code === 'TIMEOUT', timedOut && timedOut.cause && timedOut.cause.code);
    check('a relative URL rejects', (await caught(() => fetch('/relative'))) instanceof TypeError);
    check('an unsupported scheme rejects', (await caught(() => fetch('ftp://example.com/'))) instanceof TypeError);
    check('integrity is refused', (await caught(() => fetch(`${base}/echo`, { integrity: 'sha256-x' }))) instanceof TypeError);

    // Client options reach koon: here the proxy.
    const proxied = await (await koonFetch({ proxy: base })('http://example.test/through')).json();
    check('the proxy option is used', proxied.url === 'http://example.test/through', proxied.url);
  } finally {
    server.gate();
    await close(server);
  }
}

async function run() {
  await testKoonFetch();
}

module.exports = { run };
