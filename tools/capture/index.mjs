#!/usr/bin/env node

// koon-capture: Automated browser fingerprint capture tool
//
// Usage:
//   node index.mjs --browser chrome --versions 131,136,145
//   node index.mjs --browser firefox --versions 132,135
//   node index.mjs --list-chrome    (show available Chrome versions)
//   node index.mjs --browser chrome --versions 131 --endpoint https://tls.browserleaks.com/json
//
// This tool:
// 1. Downloads specific browser versions (Chrome for Testing / Firefox from Mozilla FTP)
// 2. Launches each browser with Playwright
// 3. Navigates to a TLS/H2 fingerprint reflection endpoint
// 4. Captures the raw fingerprint data
// 5. Converts it to a koon-compatible BrowserProfile JSON

import { writeFileSync, mkdirSync } from 'fs';
import { join, resolve } from 'path';
import { downloadChrome, downloadFirefox, listChromeVersions } from './download.mjs';
import { captureFingerprintWithRetry } from './capture.mjs';
import { convertToKoonProfile, applyBrowserDefaults, formatProfileSummary } from './convert.mjs';

const RAW_DIR = resolve('raw');
const PROFILES_DIR = resolve('profiles');

function parseArgs() {
  const args = process.argv.slice(2);
  const opts = {
    browser: null,
    versions: [],
    platform: 'auto',
    endpoint: 'https://tls.browserleaks.com/json',
    keepBrowsers: false,
    listChrome: false,
    skipDownload: false,
    browserPath: null,
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--browser':
      case '-b':
        opts.browser = args[++i];
        break;
      case '--versions':
      case '-v':
        opts.versions = args[++i].split(',').map(v => v.trim());
        break;
      case '--platform':
      case '-p':
        opts.platform = args[++i];
        break;
      case '--endpoint':
      case '-e':
        opts.endpoint = args[++i];
        break;
      case '--keep-browsers':
        opts.keepBrowsers = true;
        break;
      case '--list-chrome':
        opts.listChrome = true;
        break;
      case '--skip-download':
        opts.skipDownload = true;
        break;
      case '--browser-path':
        opts.browserPath = args[++i];
        break;
      case '--help':
      case '-h':
        printHelp();
        process.exit(0);
      default:
        console.error(`Unknown option: ${args[i]}`);
        printHelp();
        process.exit(1);
    }
  }

  return opts;
}

function printHelp() {
  console.log(`
koon-capture — Automated browser fingerprint capture

Usage:
  node index.mjs [options]

Options:
  --browser, -b <chrome|firefox>   Browser to capture
  --versions, -v <v1,v2,...>       Major versions (comma-separated)
  --platform, -p <win64|linux64>   Platform (default: auto-detect)
  --endpoint, -e <url>             Fingerprint endpoint
                                   (default: https://tls.browserleaks.com/json)
  --keep-browsers                  Don't delete downloaded browser binaries
  --list-chrome                    List available Chrome for Testing versions
  --skip-download                  Skip browser download (use --browser-path)
  --browser-path <path>            Path to browser binary (with --skip-download)
  --help, -h                       Show this help

Examples:
  node index.mjs --browser chrome --versions 131,136,145
  node index.mjs --browser firefox --versions 132,135
  node index.mjs --list-chrome
  node index.mjs --browser chrome --versions 131 --skip-download --browser-path "C:\\path\\to\\chrome.exe"

Output:
  raw/       — Raw fingerprint JSON from the endpoint
  profiles/  — Converted koon BrowserProfile JSON files
`);
}

async function main() {
  const opts = parseArgs();

  // List available Chrome versions
  if (opts.listChrome) {
    console.log('Fetching available Chrome for Testing milestones...\n');
    const versions = await listChromeVersions();
    console.log('Milestone  Version');
    console.log('─────────  ──────────────────');
    for (const v of versions) {
      console.log(`  ${String(v.milestone).padEnd(8)} ${v.version}`);
    }
    return;
  }

  // Validate args
  if (!opts.browser) {
    console.error('Error: --browser is required (chrome or firefox)');
    process.exit(1);
  }
  if (opts.versions.length === 0 && !opts.browserPath) {
    console.error('Error: --versions is required');
    process.exit(1);
  }

  mkdirSync(RAW_DIR, { recursive: true });
  mkdirSync(PROFILES_DIR, { recursive: true });

  const results = [];

  // If using a custom browser path, capture a single version
  if (opts.skipDownload && opts.browserPath) {
    const version = opts.versions[0] || 'unknown';
    const result = await captureAndConvert(opts.browserPath, opts.browser, version, opts.endpoint);
    results.push(result);
  } else {
    // Download and capture each version
    for (const version of opts.versions) {
      console.log(`\n${'═'.repeat(60)}`);
      console.log(`Capturing ${opts.browser} ${version}`);
      console.log('═'.repeat(60));

      try {
        // Download browser
        let browserPath;
        if (opts.browser === 'chrome') {
          browserPath = await downloadChrome(parseInt(version));
        } else if (opts.browser === 'firefox') {
          browserPath = await downloadFirefox(version);
        } else {
          throw new Error(`Unknown browser: ${opts.browser}`);
        }

        const result = await captureAndConvert(browserPath, opts.browser, version, opts.endpoint);
        results.push(result);

      } catch (err) {
        console.error(`\nFailed to capture ${opts.browser} ${version}: ${err.message}`);
        results.push({ browser: opts.browser, version, error: err.message });
      }
    }
  }

  // Print summary
  console.log(`\n${'═'.repeat(60)}`);
  console.log('CAPTURE SUMMARY');
  console.log('═'.repeat(60));

  for (const r of results) {
    if (r.error) {
      console.log(`  ${r.browser} ${r.version}: FAILED — ${r.error}`);
    } else {
      console.log(`  ${r.browser} ${r.version}: OK`);
      console.log(`    Raw:     ${r.rawFile}`);
      console.log(`    Profile: ${r.profileFile}`);
      console.log(`    JA3:     ${r.ja3Hash}`);
      console.log(`    JA4:     ${r.ja4}`);
      console.log(`    Akamai:  ${r.akamaiHash || '(none)'}`);
    }
  }
}

async function captureAndConvert(browserPath, browser, version, endpoint) {
  // Capture fingerprint
  console.log('\n--- Capturing fingerprint ---');
  const rawData = await captureFingerprintWithRetry(browserPath, browser, endpoint);

  // Save raw data
  const platform = detectPlatform();
  const rawFile = join(RAW_DIR, `${browser}-${version}-${platform}.json`);
  writeFileSync(rawFile, JSON.stringify(rawData, null, 2));
  console.log(`  Raw data saved: ${rawFile}`);

  // Convert to koon profile
  console.log('\n--- Converting to koon profile ---');
  const browserInfo = { browser, version, platform };
  let profile = convertToKoonProfile(rawData, browserInfo);
  profile = applyBrowserDefaults(profile, browserInfo);

  // Print summary
  console.log(formatProfileSummary(profile));

  // Save profile
  const profileFile = join(PROFILES_DIR, `${browser}-${version}-${platform}.json`);
  writeFileSync(profileFile, JSON.stringify(profile, null, 2));
  console.log(`\n  Profile saved: ${profileFile}`);

  return {
    browser,
    version,
    rawFile,
    profileFile,
    ja3Hash: rawData.ja3_hash,
    ja4: rawData.ja4,
    akamaiHash: rawData.akamai_hash,
  };
}

function detectPlatform() {
  if (process.platform === 'win32' || process.env.OS === 'Windows_NT') return 'windows';
  if (process.platform === 'darwin') return 'macos';
  return 'linux';
}

main().catch(err => {
  console.error(`\nFatal error: ${err.message}`);
  console.error(err.stack);
  process.exit(1);
});
