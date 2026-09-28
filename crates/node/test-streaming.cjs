// Offline tests: streaming responses decoded by default (raw with
// decode: false), and how cancel()/leaving a loop early/koonFetch cancel
// drop the underlying connection.
const zlib = require('node:zlib');
const http = require('node:http');

const { INDEX, check, expectThrows, withTimeout, caught, listen, close } = require('./test-helpers.cjs');
const { Koon, koonFetch } = require(INDEX);

const FETCH_TEXT = 'koon decodes this body once. '.repeat(200);

async function testStreamingDecode() {
  console.log('streaming responses: bodies decoded by default, raw with decode: false');
  const bodies = {
    '/gzip': ['gzip', zlib.gzipSync(FETCH_TEXT)],
    '/br': ['br', zlib.brotliCompressSync(FETCH_TEXT)],
    '/bad-gzip': ['gzip', Buffer.from('not gzip at all')],
  };
  const server = http.createServer((req, res) => {
    const [coding, data] = bodies[req.url];
    res.writeHead(200, { 'content-type': 'text/plain', 'content-encoding': coding, 'content-length': data.length });
    res.end(data);
  });
  const port = await listen(server);
  const base = `http://127.0.0.1:${port}`;
  const header = (stream, name) => (stream.headers.find((h) => h.name.toLowerCase() === name) || {}).value;
  try {
    const client = new Koon();
    for (const coding of ['gzip', 'br']) {
      const decoded = await client.requestStreaming('GET', `${base}/${coding}`);
      const chunks = [];
      for await (const chunk of decoded) chunks.push(chunk);
      check(`a ${coding} body is decoded by default`, Buffer.concat(chunks).toString() === FETCH_TEXT);
      check(`the ${coding} headers stay as received`, header(decoded, 'content-encoding') === coding && header(decoded, 'content-length') === String(bodies[`/${coding}`][1].length));
      const collected = await (await client.requestStreaming('GET', `${base}/${coding}`, undefined, { timeout: 5 })).collect();
      check(`collect() of a ${coding} body is decoded`, collected.toString() === FETCH_TEXT);
      const raw = await (await client.requestStreaming('GET', `${base}/${coding}`, undefined, { decode: false })).collect();
      check(`decode: false gives the ${coding} bytes as sent`, raw.equals(bodies[`/${coding}`][1]));
    }
    await expectThrows(
      async () => (await client.requestStreaming('GET', `${base}/bad-gzip`)).collect(),
      'a body that does not decode fails the read',
      'IO_ERROR'
    );
  } finally {
    await close(server);
  }
}

// /drip sends a chunk every 50 ms until the client drops the connection,
// which `dropped()` reports; /hold sends one chunk and then waits.
function startDripServer() {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.write(req.url === '/hold' ? 'first;' : 'drip;');
    const timer = req.url === '/drip' ? setInterval(() => res.write('drip;'), 50) : null;
    res.on('close', () => {
      clearInterval(timer);
      if (!res.writableFinished) server.emit('dropped');
    });
  });
  server.dropped = () => withTimeout(new Promise((resolve) => server.once('dropped', () => resolve(true))), 3000, 'the drop');
  return server;
}

async function testStreamingCancel() {
  console.log('streaming responses: cancel(), leaving for await early, koonFetch cancel');
  const server = startDripServer();
  const port = await listen(server);
  const base = `http://127.0.0.1:${port}`;
  try {
    const client = new Koon();

    let dropped = server.dropped();
    const looped = await client.requestStreaming('GET', `${base}/drip`);
    for await (const chunk of looped) {
      if (chunk.length > 0) break;
    }
    check('leaving for await early drops the connection', await caught(() => dropped) === null);
    await expectThrows(() => looped.nextChunk(), 'nextChunk() after the loop was left', 'BODY_ERROR');

    dropped = server.dropped();
    const cancelled = await client.requestStreaming('GET', `${base}/drip`);
    await cancelled.nextChunk();
    cancelled.cancel();
    cancelled.cancel();
    check('cancel() drops the connection (twice is harmless)', await caught(() => dropped) === null);
    await expectThrows(() => cancelled.nextChunk(), 'nextChunk() after cancel()', 'BODY_ERROR');
    await expectThrows(() => cancelled.collect(), 'collect() after cancel()', 'BODY_ERROR');

    const held = await client.requestStreaming('GET', `${base}/hold`);
    await held.nextChunk();
    const pending = held.nextChunk();
    setTimeout(() => held.cancel(), 100);
    await expectThrows(() => withTimeout(pending, 2000, 'the pending read'), 'cancel() ends a pending nextChunk()', 'BODY_ERROR');
    const collecting = await client.requestStreaming('GET', `${base}/hold`);
    const whole = collecting.collect();
    setTimeout(() => collecting.cancel(), 100);
    await expectThrows(() => withTimeout(whole, 2000, 'the pending collect'), 'cancel() ends a pending collect()', 'BODY_ERROR');

    dropped = server.dropped();
    const fetched = await koonFetch(client)(`${base}/drip`);
    const reader = fetched.body.getReader();
    await reader.read();
    await reader.cancel();
    check('cancelling a koonFetch body drops the connection', await caught(() => dropped) === null);
    const after = await client.requestStreaming('GET', `${base}/hold`);
    check('the client goes on', after.status === 200);
    after.cancel();
  } finally {
    await close(server);
  }
}

async function run() {
  await testStreamingDecode();
  await testStreamingCancel();
}

module.exports = { run };
