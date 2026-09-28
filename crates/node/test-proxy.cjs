// Offline tests: KoonProxy (fields, shutdown, the upstream client's
// connection options) and https:// proxies (certificate verification,
// proxyCaCerts, ignoreProxyTlsErrors).
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const https = require('node:https');

const { INDEX, check, expectThrows, caught, listen, close, startHttpServer } = require('./test-helpers.cjs');
const { Koon, KoonProxy } = require(INDEX);

async function testProxy() {
  console.log('KoonProxy: fields, shutdown() promise');
  const caDir = fs.mkdtempSync(path.join(os.tmpdir(), 'koon-ca-'));
  try {
    const proxy = await KoonProxy.start({ caDir, headerMode: 'Passthrough', timeout: 5 });
    check('instanceof KoonProxy', proxy instanceof KoonProxy);
    check('port is a number', typeof proxy.port === 'number' && proxy.port > 0, proxy.port);
    check('url names the port', proxy.url === `http://127.0.0.1:${proxy.port}`, proxy.url);
    check('caCertPath is in caDir', proxy.caCertPath.startsWith(caDir), proxy.caCertPath);
    check('caCertPem() is a PEM Buffer', proxy.caCertPem().toString().startsWith('-----BEGIN CERTIFICATE-----'));
    const stopping = proxy.shutdown();
    check('shutdown() returns a promise', stopping instanceof Promise);
    check('shutdown() resolves to undefined', (await stopping) === undefined);
    check('shutdown() twice is a no-op', (await proxy.shutdown()) === undefined);
    try {
      new KoonProxy();
      check('KoonProxy has no public constructor', false, 'constructed');
    } catch (err) {
      check('KoonProxy has no public constructor', err instanceof TypeError, err.message);
    }
  } finally {
    fs.rmSync(caDir, { recursive: true, force: true });
  }
}

async function testProxyUpstream() {
  console.log('KoonProxy: the upstream client takes the connection options');
  // Answers requests in absolute form itself, as a forward proxy does for http:// URLs.
  const upstream = startHttpServer();
  const upstreamPort = await listen(upstream);
  const caDir = fs.mkdtempSync(path.join(os.tmpdir(), 'koon-ca-'));
  let proxy;
  try {
    proxy = await KoonProxy.start({
      caDir,
      proxy: `http://127.0.0.1:${upstreamPort}`,
      locale: 'de-DE',
      timeout: 2.5,
      retries: 1,
    });
    const body = await new Promise((resolve, reject) => {
      const req = http.request(
        {
          host: '127.0.0.1',
          port: proxy.port,
          path: 'http://example.test/through',
          headers: { host: 'example.test', 'accept-language': 'en-GB' },
          agent: false,
        },
        (res) => {
          const chunks = [];
          res.on('data', (chunk) => chunks.push(chunk));
          res.on('end', () => resolve(Buffer.concat(chunks).toString()));
        }
      );
      req.on('error', reject);
      req.end();
    });
    const seen = JSON.parse(body);
    check('forwarded through the upstream proxy', seen.url === 'http://example.test/through', seen.url);
    const raw = seen.rawHeaders;
    const lang = raw[raw.findIndex((name, i) => i % 2 === 0 && name.toLowerCase() === 'accept-language') + 1];
    check('locale sets the Accept-Language', typeof lang === 'string' && lang.startsWith('de-DE,de;q=0.9'), lang);
  } finally {
    if (proxy) await proxy.shutdown();
    await close(upstream);
    fs.rmSync(caDir, { recursive: true, force: true });
  }
  await expectThrows(() => KoonProxy.start({ proxy: 'nonsense' }), 'invalid upstream proxy', 'PROXY_ERROR');
}

// A self-signed certificate for 127.0.0.1 and localhost (P-256, valid until
// 2126) for the local TLS proxy.
const PROXY_CERT = `-----BEGIN CERTIFICATE-----
MIIBpzCCAU2gAwIBAgIUTT+1Q/UeQCoCj9+GTVjktiVQ7NAwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPa29vbiB0ZXN0IHByb3h5MCAXDTI2MDkyMzIxMzAzNFoYDzIx
MjYwODMwMjEzMDM0WjAaMRgwFgYDVQQDDA9rb29uIHRlc3QgcHJveHkwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAATPkRI3WI8c7+qaKXL70r52fX/rC1Rk9fVUzAww
YWSHRaT/Wd5KpkYuy8RPNNIt05FR6O0P09zHaeAv3+pyvvswo28wbTAdBgNVHQ4E
FgQUGwZLCfYZbin9FDavBNJSG5DnSbkwHwYDVR0jBBgwFoAUGwZLCfYZbin9FDav
BNJSG5DnSbkwDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARhwR/AAABgglsb2Nh
bGhvc3QwCgYIKoZIzj0EAwIDSAAwRQIhALFwL3gr3T3UQeApA+A8k2xyqyaCtcMx
gq52rAWcGvWpAiBDGDHXckJ1xNL33TII0Ff6mUws376mH49GIX3eEQ0Lag==
-----END CERTIFICATE-----
`;
const PROXY_KEY = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQguMLKO1ivNEiVSl0C
Uy7cZMPy8VPlFlhacX4F8dvpAWuhRANCAATPkRI3WI8c7+qaKXL70r52fX/rC1Rk
9fVUzAwwYWSHRaT/Wd5KpkYuy8RPNNIt05FR6O0P09zHaeAv3+pyvvsw
-----END PRIVATE KEY-----
`;

async function testHttpsProxy() {
  console.log('https:// proxies: certificate verification, proxyCaCerts, ignoreProxyTlsErrors');
  // koon sends http:// URLs to an HTTP(S) proxy in absolute form: the proxy
  // answers them itself.
  const lines = [];
  const tlsProxy = https.createServer({ cert: PROXY_CERT, key: PROXY_KEY }, (req, res) => {
    lines.push(`${req.method} ${req.url}`);
    res.end('proxied');
  });
  const plain = startHttpServer();
  const proxy = `https://127.0.0.1:${await listen(tlsProxy)}`;
  const plainPort = await listen(plain);
  try {
    let err = await caught(() => new Koon({ proxy }).get('http://example.test/'));
    check(
      'an untrusted proxy certificate is rejected',
      err && err.code === 'PROXY_ERROR' && err.message.includes('TLS to proxy failed'),
      err && err.message
    );
    err = await caught(() => new Koon({ proxy, ignoreTlsErrors: true }).get('http://example.test/'));
    check('ignoreTlsErrors does not cover the proxy', err && err.code === 'PROXY_ERROR', err && err.message);
    check('no request reached the untrusted proxy', lines.length === 0, JSON.stringify(lines));

    let resp = await new Koon({ proxy, proxyCaCerts: PROXY_CERT }).get('http://example.test/a');
    check('proxyCaCerts as a string', resp.text() === 'proxied' && lines.pop() === 'GET http://example.test/a');
    resp = await new Koon({ proxy, proxyCaCerts: Buffer.from(PROXY_CERT) }).get('http://example.test/b');
    check('proxyCaCerts as a Buffer', resp.text() === 'proxied' && lines.pop() === 'GET http://example.test/b');
    resp = await new Koon({ proxy, ignoreProxyTlsErrors: true }).get('http://example.test/c');
    check('ignoreProxyTlsErrors', resp.text() === 'proxied' && lines.pop() === 'GET http://example.test/c');
    await expectThrows(() => new Koon({ proxyCaCerts: 'not a certificate' }), 'invalid proxyCaCerts', 'INVALID_ARGUMENT');

    err = await caught(() => new Koon({ proxy: `https://127.0.0.1:${plainPort}` }).get('http://example.test/'));
    check(
      'a plain HTTP proxy addressed as https:// gets a hint',
      err && err.code === 'PROXY_ERROR' && err.message.includes('answered in plain HTTP; use http:// instead of https://'),
      err && err.message
    );
  } finally {
    await close(tlsProxy);
    await close(plain);
  }
}

async function testListenerOptions() {
  console.log('KoonProxy: allowNonLoopback, auth, maxConnections');
  // 192.0.2.1 (TEST-NET-1) is no address of this machine: without the opt-in the
  // refusal comes before any bind, with it the bind itself fails. Nothing listens
  // on a reachable interface.
  await expectThrows(
    () => KoonProxy.start({ listenAddr: '192.0.2.1:0' }),
    'a non-loopback listenAddr is refused without allowNonLoopback',
    'PROXY_ERROR'
  );
  await expectThrows(
    () => KoonProxy.start({ listenAddr: '192.0.2.1:0', allowNonLoopback: true }),
    'allowNonLoopback opts in (the bind itself fails)',
    'IO_ERROR'
  );

  let proxy;

  const upstream = startHttpServer();
  const upstreamPort = await listen(upstream);
  try {
    proxy = await KoonProxy.start({
      auth: { username: 'user', password: 'pass' },
      maxConnections: 5,
    });
    const requestThrough = (headers) =>
      new Promise((resolve, reject) => {
        const req = http.request(
          {
            host: '127.0.0.1',
            port: proxy.port,
            path: `http://127.0.0.1:${upstreamPort}/`,
            headers: { host: `127.0.0.1:${upstreamPort}`, ...headers },
            agent: false,
          },
          (res) => resolve(res.statusCode)
        );
        req.on('error', reject);
        req.end();
      });

    check('no credentials: 407', (await requestThrough({})) === 407);
    check(
      'wrong credentials: 407',
      (await requestThrough({ 'proxy-authorization': `Basic ${Buffer.from('user:wrong').toString('base64')}` })) === 407
    );
    check(
      'correct credentials: forwarded (maxConnections still allows one request)',
      (await requestThrough({ 'proxy-authorization': `Basic ${Buffer.from('user:pass').toString('base64')}` })) === 200
    );
  } finally {
    if (proxy) await proxy.shutdown();
    await close(upstream);
  }
}

async function run() {
  await testProxy();
  await testProxyUpstream();
  await testHttpsProxy();
  await testListenerOptions();
}

module.exports = { run };
