import { Koon } from 'koonjs';
import { execSync } from 'child_process';

// ─── Site lists by WAF ────────────────────────────────────────────────
const sites = [
  // Akamai Bot Manager (25)
  { url: 'https://nike.com', waf: 'Akamai' },
  { url: 'https://adidas.com', waf: 'Akamai' },
  { url: 'https://zalando.com', waf: 'Akamai' },
  { url: 'https://footlocker.com', waf: 'Akamai' },
  { url: 'https://macys.com', waf: 'Akamai' },
  { url: 'https://costco.com', waf: 'Akamai' },
  { url: 'https://sephora.com', waf: 'Akamai' },
  { url: 'https://homedepot.com', waf: 'Akamai' },
  { url: 'https://dickssportinggoods.com', waf: 'Akamai' },
  { url: 'https://mrporter.com', waf: 'Akamai' },
  { url: 'https://finishline.com', waf: 'Akamai' },
  { url: 'https://lufthansa.com', waf: 'Akamai' },
  { url: 'https://delta.com', waf: 'Akamai' },
  { url: 'https://united.com', waf: 'Akamai' },
  { url: 'https://emirates.com', waf: 'Akamai' },
  { url: 'https://marriott.com', waf: 'Akamai' },
  { url: 'https://airbnb.com', waf: 'Akamai' },
  { url: 'https://capitalone.com', waf: 'Akamai' },
  { url: 'https://americanexpress.com', waf: 'Akamai' },
  { url: 'https://ups.com', waf: 'Akamai' },
  { url: 'https://sony.com', waf: 'Akamai' },
  { url: 'https://ea.com', waf: 'Akamai' },
  { url: 'https://usatoday.com', waf: 'Akamai' },
  { url: 'https://cnbc.com', waf: 'Akamai' },
  { url: 'https://bbc.com', waf: 'Akamai' },

  // Cloudflare (25)
  { url: 'https://discord.com', waf: 'Cloudflare' },
  { url: 'https://notion.so', waf: 'Cloudflare' },
  { url: 'https://canva.com', waf: 'Cloudflare' },
  { url: 'https://medium.com', waf: 'Cloudflare' },
  { url: 'https://stockx.com', waf: 'Cloudflare' },
  { url: 'https://glassdoor.com', waf: 'Cloudflare' },
  { url: 'https://indeed.com', waf: 'Cloudflare' },
  { url: 'https://coinbase.com', waf: 'Cloudflare' },
  { url: 'https://shopify.com', waf: 'Cloudflare' },
  { url: 'https://crunchyroll.com', waf: 'Cloudflare' },
  { url: 'https://npmjs.com', waf: 'Cloudflare' },
  { url: 'https://priceline.com', waf: 'Cloudflare' },
  { url: 'https://etsy.com', waf: 'Cloudflare' },
  { url: 'https://wayfair.com', waf: 'Cloudflare' },
  { url: 'https://g2.com', waf: 'Cloudflare' },
  { url: 'https://zendesk.com', waf: 'Cloudflare' },
  { url: 'https://hubspot.com', waf: 'Cloudflare' },
  { url: 'https://gitlab.com', waf: 'Cloudflare' },
  { url: 'https://figma.com', waf: 'Cloudflare' },
  { url: 'https://linear.app', waf: 'Cloudflare' },
  { url: 'https://kraken.com', waf: 'Cloudflare' },
  { url: 'https://depop.com', waf: 'Cloudflare' },
  { url: 'https://soundcloud.com', waf: 'Cloudflare' },
  { url: 'https://reddit.com', waf: 'Cloudflare' },
  { url: 'https://nowsecure.nl', waf: 'Cloudflare' },

  // Kasada (5)
  { url: 'https://twitch.tv', waf: 'Kasada' },
  { url: 'https://kick.com', waf: 'Kasada' },
  { url: 'https://canadagoose.com', waf: 'Kasada' },
  { url: 'https://playstation.com', waf: 'Kasada' },
  { url: 'https://hyatt.com', waf: 'Kasada' },

  // DataDome (5)
  { url: 'https://tripadvisor.com', waf: 'DataDome' },
  { url: 'https://vinted.com', waf: 'DataDome' },
  { url: 'https://deezer.com', waf: 'DataDome' },
  { url: 'https://hermes.com', waf: 'DataDome' },
  { url: 'https://patreon.com', waf: 'DataDome' },

  // Imperva (5)
  { url: 'https://gamestop.com', waf: 'Imperva' },
  { url: 'https://walmart.com', waf: 'Imperva' },
  { url: 'https://westernunion.com', waf: 'Imperva' },
  { url: 'https://hsbc.com', waf: 'Imperva' },
  { url: 'https://seatgeek.com', waf: 'Imperva' },

  // Shape/F5 (3)
  { url: 'https://nordstrom.com', waf: 'Shape/F5' },
  { url: 'https://starbucks.com', waf: 'Shape/F5' },
  { url: 'https://southwest.com', waf: 'Shape/F5' },
];

// ─── Helpers ──────────────────────────────────────────────────────────
function curlStatus(url) {
  try {
    const r = execSync(
      `curl -s -o /dev/null -w "%{http_code}" --max-time 15 -L "${url}"`,
      { timeout: 20000, encoding: 'utf8' }
    );
    return parseInt(r.trim()) || 'ERR';
  } catch { return 'ERR'; }
}

async function koonStatus(client, url) {
  try {
    const r = await client.get(url, { timeout: 15 });
    return r.status;
  } catch (e) {
    const m = e.message || '';
    if (m.includes('TIMEOUT')) return 'T/O';
    return 'ERR';
  }
}

function fmt(s) {
  if (s === 200) return '\x1b[32m200\x1b[0m';
  if (s === 403) return '\x1b[31m403\x1b[0m';
  if (s === 'T/O') return '\x1b[33mT/O\x1b[0m';
  if (s === 'ERR') return '\x1b[33mERR\x1b[0m';
  return `\x1b[33m${s}\x1b[0m`;
}

// ─── Main ─────────────────────────────────────────────────────────────
const profiles = ['chrome145', 'firefox148', 'safari183'];
const clients = Object.fromEntries(
  profiles.map(p => [p, new Koon({ browser: p, timeout: 15 })])
);

console.log(`\nTesting ${sites.length} sites: curl + ${profiles.join(', ')}\n`);
console.log('WAF'.padEnd(12) + 'Site'.padEnd(30) + 'curl'.padEnd(6) + 'chrome'.padEnd(8) + 'firefox'.padEnd(9) + 'safari');
console.log('-'.repeat(75));

const results = [];

for (const site of sites) {
  const domain = new URL(site.url).hostname.replace('www.', '');
  const row = { domain, waf: site.waf };

  row.curl = curlStatus(site.url);

  for (const p of profiles) {
    row[p] = await koonStatus(clients[p], site.url);
  }

  console.log(
    site.waf.padEnd(12) +
    domain.padEnd(30) +
    fmt(row.curl).padEnd(6 + 9) +  // +9 for ANSI codes
    fmt(row.chrome145).padEnd(8 + 9) +
    fmt(row.firefox148).padEnd(9 + 9) +
    fmt(row.safari183)
  );
  results.push(row);
}

// ─── Summary ──────────────────────────────────────────────────────────
console.log('\n\n═══ PASS RATES (HTTP 200) ═══\n');

const wafs = [...new Set(sites.map(s => s.waf))];
const tools = ['curl', ...profiles];

// Header
console.log('WAF'.padEnd(14) + tools.map(t => t.padEnd(12)).join(''));
console.log('-'.repeat(62));

for (const waf of wafs) {
  const wafResults = results.filter(r => r.waf === waf);
  const counts = tools.map(t => {
    const passed = wafResults.filter(r => r[t] === 200).length;
    return `${passed}/${wafResults.length}`;
  });
  console.log(waf.padEnd(14) + counts.map(c => c.padEnd(12)).join(''));
}

// Total
const total = tools.map(t => {
  const passed = results.filter(r => r[t] === 200).length;
  return `${passed}/${results.length} (${Math.round(passed / results.length * 100)}%)`;
});
console.log('-'.repeat(62));
console.log('TOTAL'.padEnd(14) + total.map(t => t.padEnd(12)).join(''));

// ─── Markdown output for README/docs ──────────────────────────────────
const md = ['\n\n## Markdown Table\n'];
md.push('| WAF | Site | curl | koon Chrome | koon Firefox | koon Safari |');
md.push('|-----|------|------|-------------|--------------|-------------|');
for (const r of results) {
  const f = (s) => s === 200 ? '✅ 200' : s === 403 ? '❌ 403' : `⚠️ ${s}`;
  md.push(`| ${r.waf} | ${r.domain} | ${f(r.curl)} | ${f(r.chrome145)} | ${f(r.firefox148)} | ${f(r.safari183)} |`);
}
console.log(md.join('\n'));

for (const c of Object.values(clients)) c.close();
