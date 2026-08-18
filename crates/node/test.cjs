// Smoke test for the Node binding. Run with `npm test` after `npm run build`.
//
// Loads the locally built binary rather than going through index.js, which
// prefers a published @koonjs platform package and would silently test an
// installed version instead of this checkout.
const path = require('path');

const LOCAL_BINARIES = {
  'win32-x64': 'koon.win32-x64-msvc.node',
  'linux-x64': 'koon.linux-x64-gnu.node',
  'darwin-x64': 'koon.darwin-x64.node',
  'darwin-arm64': 'koon.darwin-arm64.node',
};

const platformArch = `${process.platform}-${process.arch}`;
const binary = LOCAL_BINARIES[platformArch];
if (!binary) {
  console.error(`no local binary mapping for ${platformArch}`);
  process.exit(1);
}

const { Koon } = require(path.join(__dirname, binary));

const FINGERPRINT_URL = 'https://tls.browserleaks.com/json';

let failures = 0;

function check(name, condition, detail) {
  if (condition) {
    console.log(`  ok    ${name}`);
  } else {
    failures++;
    console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

async function testLatestProfiles() {
  console.log('latest profile of every browser resolves and reports its version');
  const expected = [
    ['chrome', 'Chrome/152'],
    ['firefox', 'Firefox/154'],
    ['edge', 'Edg/151'],
    ['opera', 'OPR/134'],
    ['safari', 'Version/26.6'],
    ['chrome-mobile', 'Chrome/152'],
    ['firefox-mobile', 'Firefox/154'],
    ['safari-mobile', 'Version/26.6'],
    ['okhttp', 'okhttp'],
  ];
  for (const [browser, marker] of expected) {
    const ua = new Koon({ browser }).userAgent;
    check(`${browser} → ${marker}`, ua.includes(marker), ua);
  }
}

async function testRequest() {
  console.log('request through the fingerprinted stack');
  const client = new Koon({ browser: 'chrome152' });
  const resp = await client.get(FINGERPRINT_URL);
  check('status 200', resp.status === 200, `got ${resp.status}`);
  check('ok flag', resp.ok === true);

  const data = resp.json();
  check('JA4 matches real Chrome 152', data.ja4 === 't13d1516h2_8daaf6152771_806a8c22fdea', data.ja4);
  check('user-agent sent', data.user_agent.includes('Chrome/152'), data.user_agent);
  check('header accessor', typeof resp.header('content-type') === 'string');
  check('bytes counted', resp.bytesReceived > 0, String(resp.bytesReceived));
}

async function testFirefoxFingerprint() {
  console.log('Firefox 154 keeps its own fingerprint');
  const client = new Koon({ browser: 'firefox154' });
  const data = (await client.get(FINGERPRINT_URL)).json();
  check('JA4 matches real Firefox 154', data.ja4 === 't13d1617h2_86a278354501_3cbfd9057e0d', data.ja4);
}

async function testUnknownProfile() {
  console.log('unknown profile is rejected with the supported range');
  try {
    new Koon({ browser: 'chrome999' });
    check('throws', false, 'no error raised');
  } catch (err) {
    check('throws', true);
    check('names the supported range', /131-\d+/.test(err.message), err.message);
  }
}

(async () => {
  await testLatestProfiles();
  await testRequest();
  await testFirefoxFingerprint();
  await testUnknownProfile();

  console.log('');
  if (failures > 0) {
    console.error(`${failures} check(s) failed`);
    process.exit(1);
  }
  console.log('all checks passed');
})().catch((err) => {
  console.error('test run failed:', err);
  process.exit(1);
});
