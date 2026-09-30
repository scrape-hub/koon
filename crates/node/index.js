'use strict';

const { platform, arch } = process;
const platformArch = `${platform}-${arch}`;

// No linux-arm64 entry: there is no @koonjs/linux-arm64-gnu package and no
// prebuilt local binary for it.
const packages = {
  'win32-x64': '@koonjs/win32-x64-msvc',
  'linux-x64': '@koonjs/linux-x64-gnu',
  'darwin-x64': '@koonjs/darwin-x64',
  'darwin-arm64': '@koonjs/darwin-arm64',
};

const localFiles = {
  'win32-x64': './koon.win32-x64-msvc.node',
  'linux-x64': './koon.linux-x64-gnu.node',
  'darwin-x64': './koon.darwin-x64.node',
  'darwin-arm64': './koon.darwin-arm64.node',
};

const localFile = localFiles[platformArch];
const pkg = packages[platformArch];
if (!localFile) {
  throw new Error(
    `koon: unsupported platform ${platformArch}. ` +
      `Supported: ${Object.keys(localFiles).join(', ')}`
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
const HOOKS = ['onRequest', 'onResponse', 'onRedirect'];

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
    typeof headers[Symbol.iterator] === 'function'
  ) {
    return Array.from(headers);
  }
  return headers;
}

const HEADER_OPTIONS = ['headers', 'proxyHeaders'];

// Options objects are copied only when they carry a hook or iterable headers.
function prepareOptions(options) {
  if (options === null || typeof options !== 'object' || ArrayBuffer.isView(options)) return options;
  const hooks = HOOKS.filter((name) => typeof options[name] === 'function');
  const headers = HEADER_OPTIONS.filter((name) => headerInit(options[name]) !== options[name]);
  if (hooks.length === 0 && headers.length === 0) return options;
  const prepared = { ...options };
  for (const name of hooks) prepared[name] = safeHook(options[name], name);
  for (const name of headers) prepared[name] = headerInit(options[name]);
  return prepared;
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

// Native errors carry their code as a "[CODE] message" prefix (see
// koon_napi_error in src/lib.rs); napi-rs itself sets `err.code` to one of
// its status names. Its argument conversion errors ("StringExpected", ...)
// are invalid arguments too. Other errors, such as an exception a caller's
// own getter threw, pass through unchanged.
const NAPI_ARGUMENT_STATUS = /^(InvalidArg|[A-Za-z]+Expected)$/;

function attachErrorCode(err) {
  if (err instanceof Error) {
    const match = /^\[([A-Z_]+)\] /.exec(err.message);
    if (match) {
      err.code = match[1];
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
  const mapArgs = nativeClass === native.Koon ? (args) => args.map(prepareOptions) : (args) => args;
  for (const name of Object.getOwnPropertyNames(proto)) {
    const { value } = Object.getOwnPropertyDescriptor(proto, name);
    if (name === 'constructor' || typeof value !== 'function') continue;
    proto[name] = {
      [name](...args) {
        return callWithErrorCode(value, this, mapArgs(args));
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

  // The body is decoded (Content-Encoding) unless `decode: false`; the
  // decoder is set before the caller can read the first chunk.
  async requestStreaming(method, url, body, options) {
    let decode = true;
    if (options !== null && typeof options === 'object' && 'decode' in options) {
      ({ decode, ...options } = options);
    }
    const response = await super.requestStreaming(method, url, body, options);
    if (decode !== false) response._decodeContent();
    return response;
  }

  // The fingerprint self-test: the report of the native side, parsed.
  static async verify(browser = 'chrome', options = {}) {
    const proxy = options && options.proxy != null ? options.proxy : undefined;
    return JSON.parse(await callWithErrorCode(native.verifyJson, undefined, [browser, proxy]));
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
