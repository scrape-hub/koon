// Offline test: WebSocket send/receive concurrency and close.
const { INDEX, check, expectThrows, withTimeout, listen, close, startWsServer } = require('./test-helpers.cjs');
const { Koon } = require(INDEX);

async function testWebSocket() {
  console.log('WebSocket: send while receive() is pending, close');
  const server = startWsServer();
  const port = await listen(server);
  try {
    const ws = await new Koon().websocket(`ws://127.0.0.1:${port}/`);
    const pending = ws.receive();
    try {
      await withTimeout(ws.send('ping'), 3000, 'send() during receive()');
      check('send() completes while receive() is pending', true);
      const message = await withTimeout(pending, 3000, 'receive()');
      check('receive() gets the echo', message && message.isText && message.data.toString() === 'ping', JSON.stringify(message));
    } catch (err) {
      check('send() completes while receive() is pending', false, err.message);
    }
    await ws.send(Buffer.from([1, 2, 3]));
    const binary = await withTimeout(ws.receive(), 3000, 'binary receive()');
    check('binary message round trip', !binary.isText && binary.data.equals(Buffer.from([1, 2, 3])));

    await expectThrows(() => ws.close(70000), 'close code beyond u16', 'INVALID_ARGUMENT');
    await withTimeout(ws.close(1000, 'done'), 3000, 'close()');
    check('receive() after close() ends with null', (await withTimeout(ws.receive(), 3000, 'receive after close')) === null);
    await expectThrows(() => ws.send('late'), 'send() after close()', 'WEBSOCKET_ERROR');
  } finally {
    await close(server);
  }
}

async function run() {
  await testWebSocket();
}

module.exports = { run };
