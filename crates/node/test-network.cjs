// Network-required tests: fingerprint checks against a real target and
// HTTP/3 shutdown behaviour. Run only when `test.cjs` is invoked without
// `--offline`.
const { INDEX, check } = require('./test-helpers.cjs');
const { Koon } = require(INDEX);

const FINGERPRINT_URL = 'https://tls.browserleaks.com/json';

async function testRequest() {
  console.log('request through the fingerprinted stack');
  // Chrome 151+ draws its server-padding field trial group once per client (~6% ask for
  // padding, changing the JA4): pinned to 'none' so this exact-JA4 check isn't flaky.
  const client = new Koon({ browser: 'chrome153', serverPadding: 'none' });
  const resp = await client.get(FINGERPRINT_URL);
  check('status 200', resp.status === 200, `got ${resp.status}`);
  const data = resp.json();
  check('JA4 matches real Chrome 153', data.ja4 === 't13d1517h2_8daaf6152771_cb7bf5808d99', data.ja4);
  check('user-agent sent', data.user_agent.includes('Chrome/153'), data.user_agent);
  check('bytes counted', resp.bytesReceived > 0, resp.bytesReceived);
}

async function testFirefoxFingerprint() {
  console.log('Firefox 156 keeps its own fingerprint');
  const data = (await new Koon({ browser: 'firefox156' }).get(FINGERPRINT_URL)).json();
  check('JA4 matches real Firefox 156', data.ja4 === 't13d1517h2_8daaf6152771_3cbfd9057e0d', data.ja4);
}

async function testShutdownHttp3() {
  console.log('shutdown() ends an HTTP/3 connection');
  const url = 'https://www.google.com/generate_204';
  const client = new Koon();
  await client.get(url); // advertises HTTP/3
  client.close();
  const resp = await client.get(url);
  check('second connection is HTTP/3', resp.version === 'h3', resp.version);
  await client.shutdown();
  check('the client stays usable', (await client.get(url)).status === 204);
  await client.shutdown();
}

async function run() {
  await testRequest();
  await testFirefoxFingerprint();
  await testShutdownHttp3();
}

module.exports = { run };
