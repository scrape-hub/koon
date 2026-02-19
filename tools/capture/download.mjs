import { createWriteStream, existsSync, mkdirSync } from 'fs';
import { pipeline } from 'stream/promises';
import { execSync } from 'child_process';
import { join, resolve } from 'path';
import https from 'https';
import http from 'http';

const BROWSERS_DIR = resolve('browsers');

// Chrome for Testing API
const CHROME_VERSIONS_URL = 'https://googlechromelabs.github.io/chrome-for-testing/latest-versions-per-milestone-with-downloads.json';

// Mozilla FTP base
const FIREFOX_FTP = 'https://ftp.mozilla.org/pub/firefox/releases';

function getPlatform() {
  const p = process.platform;
  if (p === 'win32' || process.env.OSTYPE?.includes('cygwin') || process.env.OS === 'Windows_NT') return 'win64';
  if (p === 'darwin') return 'mac-x64';
  return 'linux64';
}

function getChromePlatform() {
  const p = getPlatform();
  if (p === 'win64') return 'win64';
  if (p === 'mac-x64') return 'mac-x64';
  return 'linux64';
}

function getFirefoxPlatform() {
  const p = getPlatform();
  if (p === 'win64') return 'win64';
  if (p === 'mac-x64') return 'mac';
  return 'linux-x86_64';
}

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    mod.get(url, { headers: { 'User-Agent': 'koon-capture/1.0' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return fetchJson(res.headers.location).then(resolve, reject);
      }
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
      });
      res.on('error', reject);
    }).on('error', reject);
  });
}

function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    const file = createWriteStream(dest);
    const mod = url.startsWith('https') ? https : http;

    function doGet(downloadUrl) {
      mod.get(downloadUrl, { headers: { 'User-Agent': 'koon-capture/1.0' } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          file.close();
          return doGet(res.headers.location);
        }
        if (res.statusCode !== 200) {
          file.close();
          return reject(new Error(`HTTP ${res.statusCode} for ${downloadUrl}`));
        }
        const total = parseInt(res.headers['content-length'] || '0');
        let downloaded = 0;
        res.on('data', (chunk) => {
          downloaded += chunk.length;
          if (total > 0) {
            process.stdout.write(`\r  Downloading: ${(downloaded / 1024 / 1024).toFixed(1)}/${(total / 1024 / 1024).toFixed(1)} MB`);
          }
        });
        pipeline(res, file).then(() => {
          console.log(' Done.');
          resolve(dest);
        }).catch(reject);
      }).on('error', (e) => { file.close(); reject(e); });
    }

    doGet(url);
  });
}

// Download Chrome for Testing
export async function downloadChrome(majorVersion, destDir = BROWSERS_DIR) {
  const platform = getChromePlatform();
  const chromeDir = join(destDir, `chrome-${majorVersion}`);
  const exeName = platform === 'win64' ? 'chrome.exe' : 'chrome';
  const chromeBin = platform === 'win64'
    ? join(chromeDir, `chrome-${platform}`, exeName)
    : join(chromeDir, `chrome-${platform}`, exeName);

  if (existsSync(chromeBin)) {
    console.log(`  Chrome ${majorVersion} already downloaded: ${chromeBin}`);
    return chromeBin;
  }

  console.log(`  Fetching Chrome for Testing version info for milestone ${majorVersion}...`);
  const versionsData = await fetchJson(CHROME_VERSIONS_URL);

  const milestone = versionsData.milestones?.[String(majorVersion)];
  if (!milestone) {
    throw new Error(`Chrome milestone ${majorVersion} not found. Available: ${Object.keys(versionsData.milestones || {}).sort((a, b) => a - b).join(', ')}`);
  }

  const version = milestone.version;
  const downloads = milestone.downloads?.chrome;
  if (!downloads) {
    throw new Error(`No Chrome downloads for milestone ${majorVersion} (version ${version})`);
  }

  const platformDownload = downloads.find(d => d.platform === platform);
  if (!platformDownload) {
    throw new Error(`No Chrome ${majorVersion} for platform ${platform}. Available: ${downloads.map(d => d.platform).join(', ')}`);
  }

  console.log(`  Chrome ${majorVersion} → ${version} (${platform})`);

  mkdirSync(chromeDir, { recursive: true });

  const zipPath = join(chromeDir, `chrome-${platform}.zip`);
  await downloadFile(platformDownload.url, zipPath);

  console.log('  Extracting...');
  const extractZip = (await import('extract-zip')).default;
  await extractZip(zipPath, { dir: resolve(chromeDir) });

  if (!existsSync(chromeBin)) {
    throw new Error(`Chrome binary not found at expected path: ${chromeBin}`);
  }

  console.log(`  Chrome ${majorVersion} ready: ${chromeBin}`);
  return chromeBin;
}

// Resolve Firefox major version to full version (e.g., "135" → "135.0.1")
async function resolveFirefoxVersion(majorOrFull) {
  // If it's already a full version (e.g., "135.0"), use it
  if (majorOrFull.includes('.')) return majorOrFull;

  // Fetch the releases directory listing
  const url = `${FIREFOX_FTP}/`;
  const data = await new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'koon-capture/1.0' } }, (res) => {
      let body = '';
      res.on('data', (chunk) => body += chunk);
      res.on('end', () => resolve(body));
      res.on('error', reject);
    }).on('error', reject);
  });

  // Parse directory listing for matching versions
  // Format: <a href="/pub/firefox/releases/135.0.1/">135.0.1/</a>
  const regex = new RegExp(`href="[^"]*/${majorOrFull}\\.([\\d.]+)/"`, 'g');
  const matches = [];
  let match;
  while ((match = regex.exec(data)) !== null) {
    const full = `${majorOrFull}.${match[1]}`;
    // Skip beta/rc versions
    if (!full.includes('b') && !full.includes('rc') && !full.includes('esr')) {
      matches.push(full);
    }
  }

  if (matches.length === 0) {
    throw new Error(`No Firefox release found for version ${majorOrFull}. Check https://ftp.mozilla.org/pub/firefox/releases/`);
  }

  // Sort and return the latest patch version
  matches.sort((a, b) => {
    const pa = a.split('.').map(Number);
    const pb = b.split('.').map(Number);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const diff = (pb[i] || 0) - (pa[i] || 0);
      if (diff !== 0) return diff;
    }
    return 0;
  });

  return matches[0];
}

// Download Firefox
export async function downloadFirefox(version, destDir = BROWSERS_DIR) {
  // Resolve to full version
  version = await resolveFirefoxVersion(version);
  console.log(`  Resolved Firefox version: ${version}`);

  const platform = getFirefoxPlatform();
  const ffDir = join(destDir, `firefox-${version}`);

  // Firefox binary location after extraction
  let ffBin;
  if (platform === 'win64') {
    ffBin = join(ffDir, 'core', 'firefox.exe');
    // Also check alternative extraction paths
    if (!existsSync(ffBin)) {
      ffBin = join(ffDir, 'firefox', 'firefox.exe');
    }
  } else if (platform === 'mac') {
    ffBin = join(ffDir, 'Firefox.app', 'Contents', 'MacOS', 'firefox');
  } else {
    ffBin = join(ffDir, 'firefox', 'firefox');
  }

  if (existsSync(ffBin)) {
    console.log(`  Firefox ${version} already downloaded: ${ffBin}`);
    return ffBin;
  }

  mkdirSync(ffDir, { recursive: true });

  if (platform === 'win64') {
    // Windows: download NSIS installer, extract with 7z
    const installerUrl = `${FIREFOX_FTP}/${version}/win64/en-US/Firefox%20Setup%20${version}.exe`;
    const installerPath = join(ffDir, `firefox-${version}-setup.exe`);

    console.log(`  Firefox ${version} (${platform}) from Mozilla FTP...`);
    await downloadFile(installerUrl, installerPath);

    // Check for 7z
    let sevenZip = '7z';
    try {
      execSync('7z --help', { stdio: 'ignore' });
    } catch {
      try {
        execSync('7za --help', { stdio: 'ignore' });
        sevenZip = '7za';
      } catch {
        // Try common Windows paths
        const paths = [
          'C:\\Program Files\\7-Zip\\7z.exe',
          'C:\\Program Files (x86)\\7-Zip\\7z.exe',
        ];
        const found = paths.find(p => existsSync(p));
        if (found) {
          sevenZip = `"${found}"`;
        } else {
          throw new Error('7z not found. Install 7-Zip to extract Firefox installer.');
        }
      }
    }

    console.log('  Extracting with 7z...');
    execSync(`${sevenZip} x "${installerPath}" -o"${ffDir}" -y`, { stdio: 'pipe' });

    // Find the firefox.exe
    const possiblePaths = [
      join(ffDir, 'core', 'firefox.exe'),
      join(ffDir, 'firefox', 'firefox.exe'),
      join(ffDir, 'Firefox', 'firefox.exe'),
    ];
    ffBin = possiblePaths.find(p => existsSync(p));
    if (!ffBin) {
      // List contents to help debug
      const contents = execSync(`ls -R "${ffDir}" | head -50`, { encoding: 'utf8' });
      throw new Error(`Firefox binary not found after extraction. Contents:\n${contents}`);
    }

  } else if (platform === 'linux-x86_64') {
    const tarUrl = `${FIREFOX_FTP}/${version}/linux-x86_64/en-US/firefox-${version}.tar.bz2`;
    const tarPath = join(ffDir, `firefox-${version}.tar.bz2`);

    console.log(`  Firefox ${version} (${platform}) from Mozilla FTP...`);
    await downloadFile(tarUrl, tarPath);

    console.log('  Extracting...');
    execSync(`tar xjf "${tarPath}" -C "${ffDir}"`, { stdio: 'pipe' });

    ffBin = join(ffDir, 'firefox', 'firefox');
  } else {
    // macOS: download DMG — more complex, skip for now
    throw new Error('macOS Firefox download not yet supported. Use Linux or Windows.');
  }

  if (!existsSync(ffBin)) {
    throw new Error(`Firefox binary not found at: ${ffBin}`);
  }

  console.log(`  Firefox ${version} ready: ${ffBin}`);
  return ffBin;
}

// List available Chrome milestones
export async function listChromeVersions() {
  const data = await fetchJson(CHROME_VERSIONS_URL);
  return Object.entries(data.milestones || {})
    .map(([m, d]) => ({ milestone: parseInt(m), version: d.version }))
    .sort((a, b) => a.milestone - b.milestone);
}
