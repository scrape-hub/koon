// Entry point for the Node binding's tests. Run with `npm test` after
// `npm run build`; `node test.cjs --offline` (also `npm run test:offline`)
// runs only the checks that need no network access.
//
// The suite itself is split by concern into test-core.cjs (requests,
// cookies, hooks), test-websocket.cjs, test-proxy.cjs (KoonProxy and
// https:// proxies), test-fetch.cjs (the koonFetch polyfill) and
// test-streaming.cjs, all offline, plus test-network.cjs for the checks
// that need real network access. test-helpers.cjs holds what they share:
// check() and its pass/fail counters, the local HTTP/WebSocket servers, and
// the child-process helpers a few tests need.
const { stats } = require('./test-helpers.cjs');

const OFFLINE = process.argv.includes('--offline');

async function runOfflineTests() {
  await require('./test-core.cjs').run();
  await require('./test-websocket.cjs').run();
  await require('./test-proxy.cjs').run();
  await require('./test-fetch.cjs').run();
  await require('./test-streaming.cjs').run();
}

async function runNetworkTests() {
  await require('./test-network.cjs').run();
}

(async () => {
  await runOfflineTests();
  if (!OFFLINE) {
    await runNetworkTests();
  } else {
    console.log('(--offline: skipped network fingerprint checks)');
  }

  console.log('');
  if (stats.failures > 0) {
    console.error(`${stats.failures} check(s) failed, ${stats.passed} passed`);
    process.exit(1);
  }
  console.log(`all ${stats.passed} checks passed`);
})().catch((err) => {
  console.error('test run failed:', err);
  process.exit(1);
});
