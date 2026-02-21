/**
 * Unified koon test suite — Node.js bindings.
 */
const { Koon } = require('./crates/node');
const fs = require('fs');
const os = require('os');
const path = require('path');

let PASS = 0, FAIL = 0;

function ok(name, cond, detail) {
  if (cond) {
    PASS++;
    console.log(`  [PASS] ${name}` + (detail ? `  (${detail})` : ''));
  } else {
    FAIL++;
    console.log(`  [FAIL] ${name}` + (detail ? `  (${detail})` : ''));
  }
}

function text(resp) { return Buffer.from(resp.body).toString(); }
function json(resp) { return JSON.parse(text(resp)); }

async function main() {
  console.log('=== koon Node.js Test Suite ===\n');

  // --- 1. Browser profiles GET ---
  console.log('[Browsers]');

  const chrome = new Koon({ browser: 'chrome145' });
  let r = await chrome.get('https://www.google.com');
  ok('1. Chrome 145 GET google.com', r.status === 200, `${r.status} ${r.version} ${r.body.length}b`);

  const firefox = new Koon({ browser: 'firefox147' });
  r = await firefox.get('https://www.cloudflare.com');
  ok('2. Firefox 147 GET cloudflare.com', r.status === 200, `${r.status} ${r.version} ${r.body.length}b`);

  const safari = new Koon({ browser: 'safari183' });
  r = await safari.get('https://www.amazon.com');
  ok('3. Safari 183 GET amazon.com', [200, 202, 503].includes(r.status), `${r.status} ${r.version} ${r.body.length}b`);

  const edge = new Koon({ browser: 'edge145' });
  r = await edge.get('https://www.nike.com');
  ok('4. Edge 145 GET nike.com', r.status === 200, `${r.status} ${r.version} ${r.body.length}b`);

  const opera = new Koon({ browser: 'opera127' });
  r = await opera.get('https://httpbin.org/get');
  ok('5. Opera 127 GET httpbin.org', r.status === 200, `${r.status} ${r.version}`);

  // --- 2. HTTP methods ---
  console.log('\n[HTTP Methods]');

  r = await chrome.post('https://httpbin.org/post', Buffer.from('hello from node'));
  let j = json(r);
  ok('6. POST with body', r.status === 200 && j.data === 'hello from node', `echo: "${j.data}"`);

  r = await chrome.put('https://httpbin.org/put', Buffer.from('put data'));
  ok('7. PUT with body', r.status === 200, `${r.status}`);

  r = await chrome.delete('https://httpbin.org/delete');
  ok('8. DELETE', r.status === 200, `${r.status}`);

  r = await chrome.patch('https://httpbin.org/patch', Buffer.from('patch data'));
  ok('9. PATCH with body', r.status === 200, `${r.status}`);

  r = await chrome.head('https://httpbin.org/get');
  ok('10. HEAD', r.status === 200 && r.body.length === 0, `${r.status} body=${r.body.length}b`);

  // --- 3. Features ---
  console.log('\n[Features]');

  const custom = new Koon({ browser: 'chrome145', headers: { 'X-Koon-Test': 'nodejs-binding' } });
  r = await custom.get('https://httpbin.org/headers');
  j = json(r);
  ok('11. Custom headers', JSON.stringify(j.headers).includes('nodejs-binding'));

  await chrome.get('https://httpbin.org/cookies/set/nodetest/nodevalue');
  r = await chrome.get('https://httpbin.org/cookies');
  j = json(r);
  ok('12. Cookie persistence', j.cookies?.nodetest === 'nodevalue', JSON.stringify(j.cookies));

  const session = chrome.saveSession();
  ok('13. Session save', session.includes('cookies') && session.includes('nodetest'));

  const chrome2 = new Koon({ browser: 'chrome145' });
  chrome2.loadSession(session);
  r = await chrome2.get('https://httpbin.org/cookies');
  j = json(r);
  ok('14. Session load', j.cookies?.nodetest === 'nodevalue');

  const tmpfile = path.join(os.tmpdir(), 'koon_node_test_session.json');
  chrome.saveSessionToFile(tmpfile);
  ok('15. Session save to file', fs.existsSync(tmpfile));
  const chrome3 = new Koon({ browser: 'chrome145' });
  chrome3.loadSessionFromFile(tmpfile);
  fs.unlinkSync(tmpfile);
  r = await chrome3.get('https://httpbin.org/cookies');
  j = json(r);
  ok('16. Session load from file', j.cookies?.nodetest === 'nodevalue');

  const profile = chrome.exportProfile();
  ok('17. Profile export', profile.includes('cipher_list') && profile.includes('http2'));

  const rand = new Koon({ browser: 'chrome145', randomize: true });
  r = await rand.get('https://httpbin.org/get');
  ok('18. Randomize', r.status === 200);

  // --- 4. TLS Fingerprint ---
  console.log('\n[Fingerprint]');

  r = await chrome.get('https://tls.browserleaks.com/json');
  let fp = json(r);
  ok('19. Chrome JA3N', fp.ja3n_hash === '8e19337e7524d2573be54efb2b0784c9', fp.ja3n_hash);
  ok('20. Chrome JA4', fp.ja4 === 't13d1516h2_8daaf6152771_d8a2da3f94cd', fp.ja4);
  ok('21. Chrome Akamai', fp.akamai_hash === '52d84b11737d980aef856699f885ca86', fp.akamai_hash);

  r = await firefox.get('https://tls.browserleaks.com/json');
  fp = json(r);
  ok('22. Firefox JA3N', fp.ja3n_hash === 'e4147a4860c1f347354f0a84d8787c02', fp.ja3n_hash);

  r = await safari.get('https://tls.browserleaks.com/json');
  fp = json(r);
  ok('23. Safari JA3', fp.ja3_hash === '773906b0efdefa24a7f2b8eb6985bf37', fp.ja3_hash);

  // --- 5. Anti-Bot Sites ---
  console.log('\n[Anti-Bot]');

  r = await chrome.get('https://nowsecure.nl');
  ok('24. nowsecure.nl (Cloudflare)', r.status === 200, `${r.status}`);

  r = await firefox.get('https://www.ticketmaster.com');
  ok('25. ticketmaster.com', r.status === 200, `${r.status}`);

  // --- 6. WebSocket ---
  console.log('\n[WebSocket]');

  const ws = await chrome.websocket('wss://echo.websocket.org');
  await ws.receive(); // welcome
  await ws.send('hello from koon node');
  const echo = await ws.receive();
  const echoText = echo ? Buffer.from(echo.data).toString() : '';
  ok('26. WebSocket echo', echoText === 'hello from koon node', `"${echoText}"`);
  await ws.close();

  // --- 7. Streaming ---
  console.log('\n[Streaming]');

  const streaming = await chrome.requestStreaming('GET', 'https://httpbin.org/bytes/5000');
  ok('27. Streaming status', streaming.status === 200, `${streaming.status} ${streaming.version}`);
  const collected = await streaming.collect();
  ok('28. Streaming collect', collected.length === 5000, `${collected.length} bytes`);

  // --- 8. Multipart ---
  console.log('\n[Multipart]');

  r = await chrome.postMultipart('https://httpbin.org/post', [
    { name: 'field1', value: 'node_test' },
    { name: 'file', fileData: Buffer.from('file content here'), filename: 'test.txt', contentType: 'text/plain' },
  ]);
  j = json(r);
  ok('29. Multipart field', JSON.stringify(j).includes('node_test'), `form=${JSON.stringify(j.form || {})}`);
  ok('30. Multipart file', JSON.stringify(j).includes('file content here'), `files=${JSON.stringify(j.files || {})}`);

  // --- Summary ---
  const total = PASS + FAIL;
  process.stdout.write(`\n=== Node.js: ${PASS}/${total} passed`);
  if (FAIL) console.log(`, ${FAIL} FAILED ===`);
  else console.log(' ===');

  if (FAIL) process.exit(1);
}

main().catch(e => { console.error('FATAL:', e); process.exit(1); });
