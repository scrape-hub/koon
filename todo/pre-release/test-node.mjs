/**
 * Pre-release test: Node.js (ESM)
 */
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { Koon } = require('koonjs');

let passed = 0, failed = 0, skipped = 0;

function ok(label, condition) {
  if (condition) { console.log(`  [PASS] ${label}`); passed++; }
  else { console.log(`  [FAIL] ${label}`); failed++; }
}
function skip(label) { console.log(`  [SKIP] ${label}`); skipped++; }

console.log('\n=== Node.js ===\n');

try { await runTests(); } catch (e) {
  console.log(`  [FAIL] FATAL: ${e.message}`); failed++;
}

const total = passed + failed;
let summary = `\n=== node: ${passed}/${total} passed`;
if (failed) summary += `, ${failed} FAILED`;
if (skipped) summary += `, ${skipped} skipped`;
summary += ' ===\n';
console.log(summary);
process.exit(failed ? 1 : 0);

async function runTests() {

// ── Response Properties ──────────────────────────────────────────
console.log('-- Response Properties --');
const client = new Koon({ browser: 'chrome145', timeout: 15 });
let resp = await client.get('https://httpbin.org/get');
ok('status=200', resp.status === 200);
ok('statusCode alias', resp.statusCode === 200);
ok('ok is true', resp.ok === true);
ok('text() is string', typeof resp.text() === 'string' && resp.text().includes('url'));
ok('json() is object', typeof resp.json() === 'object' && resp.json().url);
ok('headers is array', Array.isArray(resp.headers) && resp.headers.length > 0);
ok('body is Buffer', Buffer.isBuffer(resp.body) && resp.body.length > 0);
ok('contentType', resp.contentType && resp.contentType.includes('json'));
ok('bytesSent > 0', resp.bytesSent > 0);
ok('bytesReceived > 0', resp.bytesReceived > 0);
ok('version is string', typeof resp.version === 'string');

// ── Browser Profiles ─────────────────────────────────────────────
console.log('-- Browser Profiles --');
for (const profile of ['chrome145', 'firefox148', 'safari183']) {
  const c = new Koon({ browser: profile, timeout: 15 });
  const r = await c.get('https://httpbin.org/get');
  ok(`${profile} GET status=200`, r.status === 200);
  c.close();
}

// ── HTTP Methods ─────────────────────────────────────────────────
console.log('-- HTTP Methods --');
resp = await client.post('https://httpbin.org/post', 'node body');
ok('POST echoes body', resp.json().data.includes('node body'));

resp = await client.put('https://httpbin.org/put', 'put data');
ok('PUT status=200', resp.status === 200);

resp = await client.delete('https://httpbin.org/delete');
ok('DELETE status=200', resp.status === 200);

resp = await client.head('https://httpbin.org/get');
ok('HEAD body empty', resp.body.length === 0);

// ── Per-Request Headers & Timeout ────────────────────────────────
console.log('-- Per-Request Headers & Timeout --');
resp = await client.get('https://httpbin.org/headers', {
  headers: { 'X-Koon-Test': 'node789' },
});
ok('custom header sent', resp.json().headers['X-Koon-Test'] === 'node789');

try {
  await client.get('https://httpbin.org/delay/10', { timeout: 2 });
  ok('timeout triggers', false);
} catch (e) {
  ok('timeout triggers', e.message.includes('timed out') || e.message.includes('TIMEOUT'));
}

// ── Cookies & Sessions ──────────────────────────────────────────
console.log('-- Cookies & Sessions --');
await client.get('https://httpbin.org/cookies/set/nodekey/nodeval');
resp = await client.get('https://httpbin.org/cookies');
ok('cookie persisted', resp.json().cookies.nodekey === 'nodeval');

const session = client.saveSession();
ok('saveSession returns string', typeof session === 'string' && session.length > 10);

const client2 = new Koon({ browser: 'chrome145', timeout: 15 });
client2.loadSession(session);
resp = await client2.get('https://httpbin.org/cookies');
ok('loadSession restores cookies', resp.json().cookies.nodekey === 'nodeval');
client2.close();

client.clearCookies();
resp = await client.get('https://httpbin.org/cookies');
ok('clearCookies works', !resp.json().cookies.nodekey);

// ── Redirect ─────────────────────────────────────────────────────
console.log('-- Redirect --');
resp = await client.get('https://httpbin.org/redirect/3');
ok('redirect followed to 200', resp.status === 200 && !resp.url.includes('redirect'));

// ── Per-Request Proxy ────────────────────────────────────────────
console.log('-- Per-Request Proxy --');
const proxy = process.env.KOON_TEST_PROXY;
if (proxy) {
  try {
    resp = await client.get('https://httpbin.org/ip', { proxy });
    ok('per-request proxy works', resp.status === 200);
  } catch (e) {
    ok(`per-request proxy (${e.message})`, false);
  }
} else {
  skip('per-request proxy (KOON_TEST_PROXY not set)');
}

// ── WebSocket ────────────────────────────────────────────────────
console.log('-- WebSocket --');
try {
  const ws = await client.websocket('wss://echo.websocket.org');
  await ws.receive(); // skip server greeting
  await ws.send('koon-node-test');
  const msg = await ws.receive();
  ok('websocket echo', msg && msg.data.toString().includes('koon-node-test'));
  await ws.close();
} catch (e) {
  ok(`websocket (${e.message})`, false);
}

// ── Streaming ────────────────────────────────────────────────────
console.log('-- Streaming --');
try {
  const stream = await client.requestStreaming('GET', 'https://httpbin.org/bytes/5000');
  const body = await stream.collect();
  ok('streaming collect', body.length === 5000);
} catch (e) {
  ok(`streaming (${e.message})`, false);
}

// ── WAF Smoke ────────────────────────────────────────────────────
console.log('-- WAF Smoke (soft-fail) --');
for (const [url, name] of [['https://nowsecure.nl', 'Cloudflare'], ['https://www.nike.com', 'Akamai']]) {
  try {
    const r = await client.get(url);
    if (r.status === 200) { console.log(`  [PASS] ${name} -> 200`); passed++; }
    else { console.log(`  [WARN] ${name} -> ${r.status}`); }
  } catch (e) {
    console.log(`  [WARN] ${name} -> ${e.message.slice(0, 60)}`);
  }
}

// ── Cleanup ──────────────────────────────────────────────────────
client.close();

} // end runTests
