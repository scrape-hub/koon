// Install test: koonjs as npm installed it sends a request to a local server.
const http = require('http');
const { Koon } = require('koonjs');

const server = http.createServer((req, res) => {
  res.setHeader('content-type', 'text/plain');
  res.end(req.headers['user-agent'].includes('Chrome/') ? 'ok' : 'no chrome user-agent');
});

server.listen(0, '127.0.0.1', async () => {
  const client = new Koon({ browser: 'chrome' });
  const response = await client.get(`http://127.0.0.1:${server.address().port}/`);
  if (response.status !== 200 || response.text() !== 'ok') {
    throw new Error(`unexpected response: ${response.status} ${response.text()}`);
  }
  await client.shutdown();
  server.close();
  console.log(`koonjs ${require('koonjs/package.json').version} on node ${process.version}: ok`);
});
