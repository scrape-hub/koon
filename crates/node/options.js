'use strict';

// The keys of each options type in index.d.ts. napi-rs drops any other key without a word, so a
// typo or another binding's spelling (`follow_redirects`) would silently change nothing.

const HOOKS = ['onRequest', 'onResponse', 'onRedirect'];
const REQUEST_OPTIONS = ['headers', 'timeout', 'proxy', 'followRedirects', 'maxRedirects', ...HOOKS];
const CONNECTION_OPTIONS = [
  'browser', 'profileJson', 'proxy', 'proxies', 'timeout', 'ignoreTlsErrors', 'proxyCaCerts',
  'ignoreProxyTlsErrors', 'proxyHeaders', 'sessionResumption', 'doh', 'localAddress', 'retries',
  'locale', 'ipVersion', 'resolve', 'maxResponseBody', 'serverPadding',
];

const OPTION_KEYS = {
  KoonOptions: new Set([
    ...CONNECTION_OPTIONS, 'headers', 'followRedirects', 'maxRedirects', 'cookieJar', ...HOOKS,
  ]),
  KoonRequestOptions: new Set(REQUEST_OPTIONS),
  KoonStreamingOptions: new Set([...REQUEST_OPTIONS, 'decode']),
  KoonProxyOptions: new Set([
    ...CONNECTION_OPTIONS, 'listenAddr', 'headerMode', 'caDir', 'allowNonLoopback', 'auth',
    'maxConnections',
  ]),
  KoonVerifyOptions: new Set(['proxy']),
};

// Throws an INVALID_ARGUMENT error for the first key of `options` that `type` does not have.
function checkOptions(options, type) {
  if (options === null || typeof options !== 'object' || ArrayBuffer.isView(options)) return;
  const known = OPTION_KEYS[type];
  for (const key of Object.keys(options)) {
    if (known.has(key)) continue;
    const camel = key.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
    const hint = known.has(camel) ? ` (did you mean '${camel}'?)` : '';
    const err = new Error(`[INVALID_ARGUMENT] unknown option '${key}'${hint}`);
    err.code = 'INVALID_ARGUMENT';
    throw err;
  }
}

module.exports = { HOOKS, OPTION_KEYS, checkOptions };
