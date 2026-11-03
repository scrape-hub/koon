'use strict';

const { platform, arch } = process;

// Linux binaries come for glibc and for musl (Alpine): ldd names its libc, and
// Node's report has a glibc version only on glibc.
function linuxLibc() {
  try {
    if (require('fs').readFileSync('/usr/bin/ldd', 'utf8').includes('musl')) return 'musl';
  } catch {}
  try {
    return process.report.getReport().header.glibcVersionRuntime ? 'gnu' : 'musl';
  } catch {
    return 'gnu';
  }
}

const platforms = {
  'win32-x64': 'win32-x64-msvc',
  'win32-arm64': 'win32-arm64-msvc',
  'linux-x64': `linux-x64-${platform === 'linux' ? linuxLibc() : 'gnu'}`,
  'linux-arm64': `linux-arm64-${platform === 'linux' ? linuxLibc() : 'gnu'}`,
  'darwin-x64': 'darwin-x64',
  'darwin-arm64': 'darwin-arm64',
};

const platformArch = `${platform}-${arch}`;
const target = platforms[platformArch];
const localFile = target && `./koon.${target}.node`;
const pkg = target && `@koonjs/${target}`;
if (!localFile) {
  throw new Error(
    `koon: unsupported platform ${platformArch}. ` +
      `Supported: ${Object.keys(platforms).join(', ')}`
  );
}

// Prefer the build sitting next to this file (what a checkout's own `npm run
// build` produces, and the napi-rs convention) over an installed @koonjs
// platform package, which may be a stale version pulled in transitively.
let native;
let localLoadError;
try {
  native = require(localFile);
} catch (err) {
  localLoadError = err;
}
if (!native) {
  try {
    native = require(pkg);
  } catch (err) {
    // Surface both real underlying errors instead of a generic message that
    // hides why loading actually failed.
    const combined = new Error(
      `koon: failed to load the native module for ${platformArch}.\n` +
        `Tried local build at ${localFile}: ${localLoadError.message}\n` +
        `Tried package ${pkg}: ${err.message}\n` +
        `Install the platform package: npm install ${pkg}`
    );
    combined.cause = err;
    throw combined;
  }
}

const warned = new Set();
function warnOnce(code, message) {
  if (warned.has(code)) return;
  warned.add(code);
  process.emitWarning(message, { code });
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

// Native code calls a hook through a function that must not throw (napi-rs
// aborts the process), so every hook is wrapped. The wrapper returns `true`
// to go on, `false` to stop a redirect (onRedirect follows unless the hook
// returned exactly `false`), or the id under which it keeps what the hook
// threw: the native side then fails the request with `[HOOK_ERROR] #id`,
// and `settleError` rejects with the thrown value itself. Hooks are
// synchronous: a Promise a hook returns is not awaited, so its rejection
// cannot fail the request; it is reported as a warning instead of becoming
// an unhandled rejection.

// Values hooks threw, by id, until the request they failed rejects with them.
const thrownByHooks = new Map();
let lastHookErrorId = 0;

function reportHookError(name, err) {
  process.emitWarning(`koon: the Promise the '${name}' hook returned rejected: ${err && err.stack ? err.stack : err}`);
}

function safeHook(fn, name) {
  return function koonHook(...args) {
    let result;
    try {
      result = fn.apply(this, args);
    } catch (err) {
      lastHookErrorId += 1;
      thrownByHooks.set(lastHookErrorId, err);
      return lastHookErrorId;
    }
    if (result !== null && typeof result === 'object' && typeof result.then === 'function') {
      result.then(undefined, (err) => reportHookError(name, err));
      if (name === 'onRedirect') {
        warnOnce(
          'KOON_ASYNC_HOOK',
          "koon: 'onRedirect' returned a Promise; hooks are synchronous, so the redirect is followed. " +
            'Return true or false directly.'
        );
      }
    }
    return name !== 'onRedirect' || result !== false;
  };
}

// Headers are an object or [name, value] pairs; other iterables of pairs
// (a Map, a fetch Headers) become an array for the native side.
function headerInit(headers) {
  if (
    headers !== null &&
    typeof headers === 'object' &&
    !Array.isArray(headers) &&
    !ArrayBuffer.isView(headers) &&
    typeof headers[Symbol.iterator] === 'function'
  ) {
    return Array.from(headers);
  }
  return headers;
}

// In an options object, functions (the hooks) are wrapped and iterables of
// pairs become arrays; the native side checks every key and value. Inherited
// enumerable keys count, as the native side reads them. The object is copied
// only when that changes something.
function prepareOptions(options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options) || ArrayBuffer.isView(options)) {
    return options;
  }
  let prepared = null;
  for (const name in options) {
    const value = options[name];
    const mapped = typeof value === 'function' ? safeHook(value, name) : headerInit(value);
    if (mapped !== value) {
      if (!prepared) {
        prepared = {};
        for (const key in options) prepared[key] = options[key];
      }
      prepared[name] = mapped;
    }
  }
  return prepared || options;
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

// Native errors carry their code, and the phase of a request's transport
// failure, as a "[CODE] message" or "[CODE:phase] message" prefix (see
// koon_napi_error in src/lib.rs); napi-rs itself sets `err.code` to one of
// its status names. The phase moves to `err.phase`, the message keeps
// "[CODE] ". napi-rs's argument conversion errors ("StringExpected", ...)
// are invalid arguments too. Other errors, such as an exception a caller's
// own getter threw, pass through unchanged.
const NAPI_ARGUMENT_STATUS = /^(InvalidArg|[A-Za-z]+Expected)$/;

function attachErrorCode(err) {
  if (err instanceof Error) {
    const match = /^\[([A-Z0-9_]+)(?::([a-z]+))?\] /.exec(err.message);
    if (match) {
      err.code = match[1];
      if (match[2]) {
        err.phase = match[2];
        const prefix = `[${match[1]}:${match[2]}]`;
        err.message = `[${match[1]}]${err.message.slice(prefix.length)}`;
        if (typeof err.stack === 'string') err.stack = err.stack.replace(prefix, `[${match[1]}]`);
      }
    } else if (NAPI_ARGUMENT_STATUS.test(err.code)) {
      err.code = 'INVALID_ARGUMENT';
      err.message = `[INVALID_ARGUMENT] ${err.message}`;
    }
  }
  return err;
}

const HOOK_ERROR = /^\[HOOK_ERROR\] #(\d+)$/;

// What a failed call rejects with: the value a hook threw when that failed
// the request, else the error with its `code`.
function settleError(err) {
  const match = err instanceof Error && HOOK_ERROR.exec(err.message);
  if (match && thrownByHooks.has(Number(match[1]))) {
    const thrown = thrownByHooks.get(Number(match[1]));
    thrownByHooks.delete(Number(match[1]));
    return thrown;
  }
  return attachErrorCode(err);
}

function callWithErrorCode(fn, self, args) {
  let result;
  try {
    result = fn.apply(self, args);
  } catch (err) {
    throw settleError(err);
  }
  if (result instanceof Promise) {
    return result.catch((err) => {
      throw settleError(err);
    });
  }
  return result;
}

// Every method of every native class gets `err.code`; Koon's also get their
// hooks wrapped and iterable headers turned into arrays. Classes whose
// instances Rust creates itself (responses, sockets, proxies) never pass
// through a JS subclass, so their prototypes are patched in place. napi-rs
// defines instance methods as writable.
for (const nativeClass of [
  native.Koon,
  native.KoonResponse,
  native.KoonStreamingResponse,
  native.KoonPendingResponse,
  native.KoonWebSocket,
  native.KoonProxy,
]) {
  const proto = nativeClass.prototype;
  const mapArgs = nativeClass === native.Koon ? (name, args) => args.map(prepareOptions) : (name, args) => args;
  for (const name of Object.getOwnPropertyNames(proto)) {
    const { value } = Object.getOwnPropertyDescriptor(proto, name);
    if (name === 'constructor' || typeof value !== 'function') continue;
    proto[name] = {
      [name](...args) {
        return callWithErrorCode(value, this, mapArgs(name, args));
      },
    }[name];
  }
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

// `for await (const chunk of response)`: the chunks of nextChunk(). Leaving
// the loop early (break, return, throw) calls the iterator's return(), which
// runs the finally block: the rest of the body is dropped at once.
native.KoonStreamingResponse.prototype[Symbol.asyncIterator] = async function* chunks() {
  let finished = false;
  try {
    for (let chunk = await this.nextChunk(); chunk !== null; chunk = await this.nextChunk()) {
      yield chunk;
    }
    finished = true;
  } finally {
    if (!finished) this.cancel();
  }
};

// A subclass is the only way to reach the constructor itself (for the hook
// wrapping and `err.code`). The verbs are shorthands for `request`.
// `Koon.browsers()` is inherited from the native class.
class Koon extends native.Koon {
  constructor(options) {
    try {
      super(prepareOptions(options));
    } catch (err) {
      throw attachErrorCode(err);
    }
  }

  websocket(url, headers) {
    return super.websocket(url, headerInit(headers));
  }

  get(url, options) {
    return this.request('GET', url, undefined, options);
  }

  post(url, body, options) {
    return this.request('POST', url, body, options);
  }

  put(url, body, options) {
    return this.request('PUT', url, body, options);
  }

  delete(url, options) {
    return this.request('DELETE', url, undefined, options);
  }

  patch(url, body, options) {
    return this.request('PATCH', url, body, options);
  }

  head(url, options) {
    return this.request('HEAD', url, undefined, options);
  }

  // The fingerprint self-test: the report of the native side, parsed.
  static async verify(browser = 'chrome', options = undefined) {
    return JSON.parse(await callWithErrorCode(native.verifyJson, undefined, [browser, prepareOptions(options)]));
  }
}

// `KoonProxy.start` is a static method, which napi-rs defines as
// non-writable, so it cannot be patched like the instance methods: a
// wrapper function takes its place, sharing the native prototype so
// `instanceof KoonProxy` holds for the instances `start` returns.
const nativeProxyStart = native.KoonProxy.start.bind(native.KoonProxy);
function KoonProxy() {
  throw new TypeError('KoonProxy has no public constructor; use KoonProxy.start() instead.');
}
KoonProxy.prototype = native.KoonProxy.prototype;
KoonProxy.start = function start(options) {
  return callWithErrorCode(nativeProxyStart, undefined, [prepareOptions(options)]);
};

// `KoonResponse.blockedBy` for a response whose body the caller reads (a
// koonFetch Response, a KoonStreamingResponse): fetch Headers and koon's
// { name, value } entries become pairs, a string body its UTF-8 bytes.
function blockedBy(response, body) {
  let { headers } = response;
  if (headers !== null && typeof headers === 'object' && typeof headers[Symbol.iterator] === 'function') {
    headers = Array.from(headers, (entry) => (Array.isArray(entry) ? entry : [entry.name, entry.value]));
  }
  let bytes = body;
  if (typeof body === 'string') bytes = Buffer.from(body);
  else if (body instanceof ArrayBuffer) bytes = Buffer.from(body);
  else if (ArrayBuffer.isView(body)) bytes = Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  return callWithErrorCode(native.blockedBy, undefined, [response.status, headers, bytes, response.url]);
}

// Literal `module.exports.X = ...` assignments (not a loop over a list, and
// not `module.exports = native` alone) so cjs-module-lexer can statically
// detect these as named exports: that's what lets ESM do
// `import { Koon } from 'koonjs'`.
module.exports.Koon = Koon;
module.exports.KoonProxy = KoonProxy;
module.exports.KoonResponse = native.KoonResponse;
module.exports.KoonStreamingResponse = native.KoonStreamingResponse;
module.exports.KoonWebSocket = native.KoonWebSocket;
// fetch() with koon's fingerprint, resolving to a standard Response (fetch.js).
module.exports.koonFetch = require('./fetch.js').createKoonFetch(Koon);
module.exports.blockedBy = blockedBy;
