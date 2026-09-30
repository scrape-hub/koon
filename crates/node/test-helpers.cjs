// Shared infrastructure for the Node binding's test files: the pass/fail
// counters and `check()`, local HTTP/WebSocket test servers, and the
// child-process helpers a few tests need to observe process-level effects
// (warnings, exit behaviour) in isolation.
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const INDEX = path.join(__dirname, 'index.js');
const LOCAL_BINARIES = {
  'win32-x64': 'koon.win32-x64-msvc.node',
  'linux-x64': 'koon.linux-x64-gnu.node',
  'darwin-x64': 'koon.darwin-x64.node',
  'darwin-arm64': 'koon.darwin-arm64.node',
};
const BINARY = path.join(__dirname, LOCAL_BINARIES[`${process.platform}-${process.arch}`] || '');

// Shared across every test file that requires this module (the require
// cache gives them the same object), so the runner can total the count
// after running each one.
const stats = { passed: 0, failures: 0 };

function check(name, condition, detail) {
  if (condition) {
    stats.passed++;
    console.log(`  ok    ${name}`);
  } else {
    stats.failures++;
    console.log(`  FAIL  ${name}${detail === undefined ? '' : `: ${detail}`}`);
  }
}

async function expectThrows(fn, name, expectedCode) {
  try {
    await fn();
    check(name, false, 'did not throw');
  } catch (err) {
    check(name, err.code === expectedCode, `code ${err.code}: ${err.message}`);
  }
}

function withTimeout(promise, ms, what) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${what} did not settle within ${ms}ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/** The error `fn` throws (or rejects with), or null. */
async function caught(fn) {
  try {
    await fn();
    return null;
  } catch (err) {
    return err;
  }
}

/** Run a script in a child process; returns its stdout, or throws with its stderr if it fails. */
function runChild(script) {
  try {
    return execFileSync(process.execPath, ['-e', script], { timeout: 10000, encoding: 'utf8', stdio: 'pipe' });
  } catch (err) {
    throw new Error(`${err.message}\n${err.stderr || ''}`);
  }
}

/** Runs `script` in a child process and JSON-parses what it printed. On
 * failure (a crash, a timeout, invalid JSON), reports it as a single failing
 * `check(label, ...)` and returns undefined, so the caller can skip its own
 * assertions with `if (result) { ... }`. */
function runChildJson(script, label) {
  try {
    return JSON.parse(runChild(script));
  } catch (err) {
    check(label, false, err.message);
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Local servers
// ---------------------------------------------------------------------------

function listen(server) {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

function close(server) {
  server.closeAllConnections?.();
  return new Promise((resolve) => server.close(resolve));
}

/** A local port nothing listens on. */
async function closedPort() {
  const probe = http.createServer();
  const port = await listen(probe);
  await close(probe);
  return port;
}

function startHttpServer() {
  const server = http.createServer((req, res) => {
    if (req.url === '/redirect') {
      res.writeHead(302, { Location: '/target' });
      res.end();
      return;
    }
    if (req.url === '/slow') return; // never answers: exercises timeouts
    if (req.url === '/stream') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.write('first,');
      setTimeout(() => res.end('second'), 20);
      return;
    }
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'application/json', 'x-dup': ['a', 'b'] });
      res.end(
        JSON.stringify({
          method: req.method,
          url: req.url,
          rawHeaders: req.rawHeaders,
          cookie: req.headers.cookie || null,
          body: Buffer.concat(chunks).toString(),
        })
      );
    });
  });
  return server;
}

function parseFrame(buf) {
  if (buf.length < 2) return null;
  const masked = (buf[1] & 0x80) !== 0;
  let length = buf[1] & 0x7f;
  let offset = 2;
  if (length === 126) {
    if (buf.length < 4) return null;
    length = buf.readUInt16BE(2);
    offset = 4;
  } else if (length === 127) {
    if (buf.length < 10) return null;
    length = Number(buf.readBigUInt64BE(2));
    offset = 10;
  }
  const maskLength = masked ? 4 : 0;
  if (buf.length < offset + maskLength + length) return null;
  const mask = buf.subarray(offset, offset + maskLength);
  const payload = Buffer.from(buf.subarray(offset + maskLength, offset + maskLength + length));
  if (masked) for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
  return { opcode: buf[0] & 0x0f, payload, length: offset + maskLength + length };
}

function encodeFrame(opcode, payload) {
  return Buffer.concat([Buffer.from([0x80 | opcode, payload.length]), payload]);
}

// A minimal WebSocket server that echoes text and binary messages and
// answers a close frame. Client frames are masked; server frames are not.
function startWsServer() {
  const server = http.createServer();
  server.on('upgrade', (req, socket) => {
    const accept = crypto
      .createHash('sha1')
      .update(`${req.headers['sec-websocket-key']}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
      .digest('base64');
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
    );
    let pending = Buffer.alloc(0);
    socket.on('data', (data) => {
      pending = Buffer.concat([pending, data]);
      for (let frame = parseFrame(pending); frame; frame = parseFrame(pending)) {
        pending = pending.subarray(frame.length);
        if (frame.opcode === 0x8) {
          socket.end(encodeFrame(0x8, frame.payload));
          return;
        }
        if (frame.opcode === 0x1 || frame.opcode === 0x2) socket.write(encodeFrame(frame.opcode, frame.payload));
      }
    });
    socket.on('error', () => {});
  });
  return server;
}

module.exports = {
  INDEX,
  BINARY,
  stats,
  check,
  expectThrows,
  withTimeout,
  caught,
  runChild,
  runChildJson,
  listen,
  close,
  closedPort,
  startHttpServer,
  startWsServer,
};
