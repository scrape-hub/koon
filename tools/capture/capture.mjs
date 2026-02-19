import { chromium } from 'playwright-core';
import { spawn } from 'child_process';
import { existsSync } from 'fs';
import { join, resolve } from 'path';
import http from 'http';

const DEFAULT_ENDPOINT = 'https://tls.browserleaks.com/json';
const CAPTURE_TIMEOUT = 30000;

// Capture fingerprint data from a browser instance.
// Returns the raw JSON from the fingerprint endpoint plus captured headers.
export async function captureFingerprint(browserPath, browserType, endpoint = DEFAULT_ENDPOINT) {
  console.log(`  Launching ${browserType} from: ${browserPath}`);
  console.log(`  Endpoint: ${endpoint}`);

  if (browserType === 'chrome') {
    return captureChromePlaywright(browserPath, endpoint);
  } else if (browserType === 'firefox') {
    return captureFirefoxDirect(browserPath, endpoint);
  } else {
    throw new Error(`Unknown browser type: ${browserType}`);
  }
}

// Chrome: use Playwright with executablePath (reliable)
async function captureChromePlaywright(browserPath, endpoint) {
  const browser = await chromium.launch({
    executablePath: browserPath,
    headless: false,
    args: [
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-background-networking',
      '--disable-sync',
      '--disable-translate',
      '--metrics-recording-only',
      '--no-service-autorun',
    ],
  });

  let fingerprintData;
  try {
    const context = await browser.newContext();
    const page = await context.newPage();

    console.log('  Navigating to fingerprint endpoint...');
    const response = await page.goto(endpoint, {
      waitUntil: 'networkidle',
      timeout: CAPTURE_TIMEOUT,
    });

    if (!response || !response.ok()) {
      throw new Error(`HTTP ${response?.status()} from ${endpoint}`);
    }

    const bodyText = await page.evaluate(() => document.body.innerText);
    try {
      fingerprintData = JSON.parse(bodyText);
    } catch {
      const preText = await page.evaluate(() => {
        const pre = document.querySelector('pre');
        return pre ? pre.textContent : document.body.textContent;
      });
      fingerprintData = JSON.parse(preText);
    }

    const navigatorInfo = await page.evaluate(() => ({
      userAgent: navigator.userAgent,
      language: navigator.language,
      languages: navigator.languages,
      platform: navigator.platform,
    }));
    fingerprintData._navigator = navigatorInfo;
  } finally {
    await browser.close().catch(() => {});
  }

  fingerprintData._capturedAt = new Date().toISOString();
  fingerprintData._browserPath = browserPath;
  fingerprintData._browserType = 'chrome';
  console.log('  Fingerprint captured successfully.');
  return fingerprintData;
}

// Firefox: use geckodriver (WebDriver protocol) for unpatched Firefox.
// Playwright doesn't support custom Firefox binaries.
async function captureFirefoxDirect(browserPath, endpoint) {
  // Use the geckodriver npm package's start() function
  let gdModule;
  try {
    gdModule = await import('geckodriver');
  } catch {
    throw new Error(
      'geckodriver not found. Firefox capture requires geckodriver.\n' +
      '  Install: npm install geckodriver (already in package.json)'
    );
  }

  const port = 4444 + Math.floor(Math.random() * 1000);
  console.log(`  Starting geckodriver on port ${port}...`);

  const driver = await gdModule.start({ port });
  if (!driver) throw new Error('Failed to start geckodriver');

  // Wait for geckodriver to start
  await new Promise(r => setTimeout(r, 1500));

  const wdUrl = `http://127.0.0.1:${port}`;

  try {
    // Create WebDriver session
    console.log('  Creating WebDriver session...');
    const session = await wdPost(`${wdUrl}/session`, {
      capabilities: {
        alwaysMatch: {
          browserName: 'firefox',
          'moz:firefoxOptions': {
            binary: browserPath,
            args: ['-no-remote'],
            prefs: {
              'browser.shell.checkDefaultBrowser': false,
              'datareporting.policy.dataSubmissionEnabled': false,
              'toolkit.telemetry.reportingpolicy.firstRun': false,
              'browser.startup.homepage_override.mstone': 'ignore',
              // Disable Firefox's JSON viewer so we get raw text
              'devtools.jsonview.enabled': false,
            },
          },
        },
      },
    });

    const sessionId = session.value?.sessionId;
    if (!sessionId) {
      throw new Error(`WebDriver session creation failed: ${JSON.stringify(session)}`);
    }

    try {
      // Navigate directly to the endpoint. With devtools.jsonview.enabled=false,
      // Firefox will show the raw JSON as plain text instead of the JSON viewer.
      console.log('  Navigating to fingerprint endpoint...');
      await wdPost(`${wdUrl}/session/${sessionId}/url`, { url: endpoint });
      await new Promise(r => setTimeout(r, 5000));

      // Extract the raw JSON text and navigator info
      const jsResp = await wdPost(`${wdUrl}/session/${sessionId}/execute/sync`, {
        script: `
          var text = document.body.innerText || document.body.textContent || '';
          // Find JSON in the text
          var start = text.indexOf('{');
          var end = text.lastIndexOf('}');
          var json = (start >= 0 && end > start) ? text.substring(start, end + 1) : text;
          return JSON.stringify({
            body: json,
            nav: {
              userAgent: navigator.userAgent,
              language: navigator.language,
              languages: Array.from(navigator.languages),
              platform: navigator.platform,
            }
          });
        `,
        args: [],
      });

      const result = JSON.parse(jsResp.value);
      const fingerprintData = JSON.parse(result.body);
      fingerprintData._navigator = result.nav;
      fingerprintData._navigator = result.nav;
      fingerprintData._capturedAt = new Date().toISOString();
      fingerprintData._browserPath = browserPath;
      fingerprintData._browserType = 'firefox';

      console.log('  Fingerprint captured successfully.');

      // Close session
      await wdDelete(`${wdUrl}/session/${sessionId}`).catch(() => {});

      return fingerprintData;
    } catch (err) {
      await wdDelete(`${wdUrl}/session/${sessionId}`).catch(() => {});
      throw err;
    }
  } finally {
    if (!driver.killed) driver.kill();
  }
}

// WebDriver HTTP helpers
function wdRequest(url, method, body) {
  return new Promise((resolve, reject) => {
    const { hostname, port, pathname } = new URL(url);
    const options = {
      hostname, port, path: pathname, method,
      headers: { 'Content-Type': 'application/json' },
    };
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { resolve({ value: data }); }
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

function wdPost(url, body) { return wdRequest(url, 'POST', body); }
function wdGet(url) { return wdRequest(url, 'GET'); }
function wdDelete(url) { return wdRequest(url, 'DELETE'); }

// Capture with retry logic
export async function captureFingerprintWithRetry(browserPath, browserType, endpoint, maxRetries = 2) {
  let lastError;
  for (let i = 0; i <= maxRetries; i++) {
    try {
      return await captureFingerprint(browserPath, browserType, endpoint);
    } catch (err) {
      lastError = err;
      console.warn(`  Attempt ${i + 1} failed: ${err.message}`);
      if (i < maxRetries) {
        console.log('  Retrying...');
        await new Promise(r => setTimeout(r, 2000));
      }
    }
  }
  throw lastError;
}
