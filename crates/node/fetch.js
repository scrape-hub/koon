'use strict';

// koonFetch: a fetch() that sends through a koon client and resolves to a
// standard Response (Node's global Response, Headers and ReadableStream).
// index.js exports it; the rules are documented in index.d.ts.

const { STATUS_CODES } = require('node:http');

// Methods fetch() rejects, and the ones it normalizes to uppercase (Fetch
// standard: "forbidden method", "normalize a method").
const FORBIDDEN_METHODS = new Set(['CONNECT', 'TRACE', 'TRACK']);
const NORMALIZED_METHODS = new Set(['DELETE', 'GET', 'HEAD', 'OPTIONS', 'POST', 'PUT']);
// Responses to these carry no body ("null body status").
const NULL_BODY_STATUSES = new Set([101, 103, 204, 205, 304]);
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const REDIRECT_MODES = new Set(['follow', 'manual', 'error']);

function fetchFailed(cause) {
  return new TypeError('fetch failed', { cause });
}

// The caller's headers as [name, value] pairs in their order: a record, or
// pairs from an array, a Headers or a Map. A repeated name is sent once,
// its values joined as Headers joins them (Cookie with '; ').
function headerList(init) {
  if (init === undefined || init === null) return [];
  const pairs =
    typeof init[Symbol.iterator] === 'function'
      ? Array.from(init, (pair) => {
          const entry = Array.from(pair);
          if (entry.length !== 2) throw new TypeError('Header pairs must contain exactly a name and a value');
          return entry;
        })
      : Object.entries(init);
  const merged = new Map();
  for (const [name, value] of pairs) {
    const key = String(name).toLowerCase();
    const text = String(value);
    const seen = merged.get(key);
    if (seen) seen[1] += (key === 'cookie' ? '; ' : ', ') + text;
    else merged.set(key, [String(name), text]);
  }
  return [...merged.values()];
}

function hasHeader(headers, name) {
  return headers.some(([key]) => key.toLowerCase() === name);
}

async function readAll(iterable) {
  const chunks = [];
  for await (const chunk of iterable) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength));
  }
  return Buffer.concat(chunks);
}

// A body as koon sends it (a string or a Buffer) and the Content-Type fetch()
// gives it (Fetch standard, "extract a body"). A FormData becomes multipart
// with the browser's boundary; streams and Blobs are read into memory.
async function extractBody(client, body) {
  if (body === undefined || body === null) return { data: undefined, type: null };
  if (typeof body === 'string') return { data: body, type: 'text/plain;charset=UTF-8' };
  if (body instanceof URLSearchParams) {
    return { data: body.toString(), type: 'application/x-www-form-urlencoded;charset=UTF-8' };
  }
  if (body instanceof FormData) {
    const fields = [];
    for (const [name, value] of body) {
      if (typeof value === 'string') {
        fields.push({ name, value });
      } else {
        fields.push({
          name,
          fileData: Buffer.from(await value.arrayBuffer()),
          filename: value.name,
          contentType: value.type || 'application/octet-stream',
        });
      }
    }
    const encoded = client._encodeMultipart(fields);
    return { data: encoded.body, type: encoded.contentType };
  }
  if (body instanceof Blob) return { data: Buffer.from(await body.arrayBuffer()), type: body.type || null };
  if (body instanceof ArrayBuffer) return { data: Buffer.from(body), type: null };
  if (ArrayBuffer.isView(body)) return { data: Buffer.from(body.buffer, body.byteOffset, body.byteLength), type: null };
  if (body instanceof ReadableStream || typeof body[Symbol.asyncIterator] === 'function') {
    return { data: await readAll(body), type: null };
  }
  return { data: String(body), type: 'text/plain;charset=UTF-8' };
}

// Options fetch() takes that koon cannot honour: a clear error instead of
// silently doing something else. Everything else fetch() takes either
// holds as is (koon has no HTTP cache, keeps connections alive and sends
// its cookie jar's cookies) or is listed in index.d.ts.
function checkOptions(init, request) {
  const credentials = init.credentials !== undefined ? init.credentials : request && request.credentials;
  if (credentials === 'omit') {
    throw new TypeError("koonFetch: credentials 'omit' is not supported: the client's cookie jar sends its cookies; create the client with cookieJar: false");
  }
  const cache = init.cache !== undefined ? init.cache : request && request.cache;
  if (cache === 'only-if-cached') throw new TypeError("koonFetch: cache 'only-if-cached' is not supported: koon has no HTTP cache");
  const integrity = init.integrity !== undefined ? init.integrity : request && request.integrity;
  if (integrity) throw new TypeError('koonFetch: integrity is not supported');
  if (init.dispatcher !== undefined) {
    throw new TypeError('koonFetch: dispatcher is not supported; give koonFetch() the proxy and other client options');
  }
}

// Node's Response constructor takes no url and no status outside 200-599;
// they become properties of the instance, kept by clone().
function describe(response, meta) {
  const clone = response.clone;
  const properties = {
    url: { value: meta.url, enumerable: true },
    redirected: { value: meta.redirected, enumerable: true },
    clone: {
      value: function cloneResponse() {
        return describe(clone.call(this), meta);
      },
    },
  };
  if (meta.status !== undefined) {
    properties.status = { value: meta.status, enumerable: true };
    properties.ok = { value: meta.status >= 200 && meta.status < 300, enumerable: true };
  }
  return Object.defineProperties(response, properties);
}

// A header value as Node's fetch gives it: the bytes as Latin-1 (koon
// decodes them as UTF-8).
function wireValue(value) {
  return /[^\x00-\x7f]/.test(value) ? Buffer.from(value, 'utf8').toString('latin1') : value;
}

// Resolves `input`/`init` (a Request, a URL or a string, plus RequestInit)
// into the request's URL, method, redirect mode, AbortSignal, header list
// and body (`extractBody()` reads it into what `client._fetch()` takes).
async function resolveRequest(client, input, init) {
  const request = input instanceof Request ? input : null;
  init = init || {};
  checkOptions(init, request);

  const url = new URL(request ? request.url : input instanceof URL ? input.href : String(input));
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw fetchFailed(new Error(`URL scheme "${url.protocol.slice(0, -1)}" is not supported`));
  if (url.username || url.password) throw new TypeError(`Request cannot be constructed from a URL that includes credentials: ${url.href}`);
  url.hash = '';

  let method = init.method !== undefined ? String(init.method) : request ? request.method : 'GET';
  const upper = method.toUpperCase();
  if (FORBIDDEN_METHODS.has(upper)) throw new TypeError(`'${method}' HTTP method is unsupported.`);
  if (NORMALIZED_METHODS.has(upper)) method = upper;

  const redirect = init.redirect !== undefined ? init.redirect : request ? request.redirect : 'follow';
  if (!REDIRECT_MODES.has(redirect)) throw new TypeError(`'${redirect}' is not a valid redirect mode`);
  const signal = init.signal !== undefined ? init.signal : request ? request.signal : null;

  const headers = headerList(init.headers !== undefined ? init.headers : request ? request.headers : undefined);
  let bodyInit = init.body;
  if (bodyInit === undefined && request && request.body !== null) bodyInit = await request.arrayBuffer();
  if (bodyInit !== undefined && bodyInit !== null && (method === 'GET' || method === 'HEAD')) {
    throw new TypeError('Request with GET/HEAD method cannot have body.');
  }
  const { data, type } = await extractBody(client, bodyInit);
  if (type !== null && !hasHeader(headers, 'content-type')) headers.push(['Content-Type', type]);
  const referrer = init.referrer !== undefined ? init.referrer : request ? request.referrer : '';
  if (referrer && referrer !== 'about:client' && !hasHeader(headers, 'referer')) {
    headers.push(['Referer', new URL(referrer, url).href]);
  }

  return { url, method, redirect, signal, headers, data };
}

// Sends the request and waits for the response head, racing `signal`'s
// abort against it so a cancelled fetch() rejects instead of hanging.
async function sendAndRaceAbort(client, method, url, data, headers, redirect, signal) {
  if (signal && signal.aborted) throw signal.reason;
  let pending;
  try {
    pending = client._fetch(method, url.href, data, { headers, followRedirects: redirect === 'follow' });
  } catch (err) {
    // An argument koon refuses, such as an invalid method: a TypeError, as fetch() throws.
    throw new TypeError(err.message, { cause: err });
  }
  let onAbort;
  const aborted =
    signal &&
    new Promise((_, reject) => {
      onAbort = () => {
        pending.abort();
        reject(signal.reason);
      };
      signal.addEventListener('abort', onAbort, { once: true });
    });
  let head;
  try {
    head = await (aborted ? Promise.race([pending.response(), aborted]) : pending.response());
  } catch (err) {
    if (signal && signal.aborted) throw signal.reason;
    throw fetchFailed(err);
  } finally {
    if (signal) signal.removeEventListener('abort', onAbort);
  }
  if (signal && signal.aborted) {
    head.cancel();
    throw signal.reason;
  }
  return head;
}

// The response body as a ReadableStream pulling chunks from `head`, or null
// for a HEAD request or a null-body status; `signal`'s abort errors it.
function responseBodyStream(head, method, status, signal) {
  if (method === 'HEAD' || NULL_BODY_STATUSES.has(status)) {
    head.cancel();
    return null;
  }
  let controller;
  const onBodyAbort = () => {
    head.cancel();
    controller.error(signal.reason);
  };
  const done = () => {
    if (signal) signal.removeEventListener('abort', onBodyAbort);
  };
  if (signal) signal.addEventListener('abort', onBodyAbort, { once: true });
  return new ReadableStream(
    {
      start(c) {
        controller = c;
      },
      async pull(c) {
        let chunk;
        try {
          chunk = await head.nextChunk();
        } catch (err) {
          done();
          c.error(signal && signal.aborted ? signal.reason : new TypeError('terminated', { cause: err }));
          return;
        }
        if (chunk === null) {
          done();
          c.close();
        } else {
          c.enqueue(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength));
        }
      },
      cancel() {
        done();
        head.cancel();
      },
    },
    { highWaterMark: 0 }
  );
}

async function send(client, input, init = {}) {
  const { url, method, redirect, signal, headers, data } = await resolveRequest(client, input, init);
  const head = await sendAndRaceAbort(client, method, url, data, headers, redirect, signal);

  const status = head.status;
  if (redirect === 'error' && REDIRECT_STATUSES.has(status)) {
    head.cancel();
    throw fetchFailed(new Error('unexpected redirect'));
  }

  const decoded = head._decodeContent();
  const responseHeaders = new Headers();
  for (const { name, value } of head.headers) {
    const lower = name.toLowerCase();
    // koon decodes the body: the encoding and length of the wire are gone.
    if (decoded && (lower === 'content-encoding' || lower === 'content-length')) continue;
    responseHeaders.append(name, wireValue(value));
  }

  const body = responseBodyStream(head, method, status, signal);

  const inRange = status >= 200 && status <= 599;
  const response = new Response(body, {
    status: inRange ? status : 200,
    statusText: STATUS_CODES[status] || '',
    headers: responseHeaders,
  });
  const finalUrl = new URL(head.url).href;
  return describe(response, {
    url: finalUrl,
    redirected: redirect === 'follow' && finalUrl !== url.href,
    status: inRange ? undefined : status,
  });
}

// koonFetch(options | client): a fetch() bound to a koon client, created
// from the options (as `new Koon(options)`) or given.
function createKoonFetch(Koon) {
  return function koonFetch(options) {
    const client = options instanceof Koon ? options : new Koon(options);
    const fetch = (input, init) => send(client, input, init);
    Object.defineProperty(fetch, 'client', { value: client, enumerable: true });
    return fetch;
  };
}

module.exports = { createKoonFetch };
