"""Update the full versions in releases.toml to the last release of every major the tables list.
It never adds a major: a new one needs captures. Edge is only reported, and Opera for Android and
Samsung Internet are left alone: the Chromium version they send only a capture shows.

Usage: python crates/core/data/update.py [--check]
--check changes nothing and exits with 1 when a version is out of date. After an update, run
`KOON_BLESS=1 cargo test -p koon-core --test generated` and add a CHANGELOG entry.
Needs `pip install koon`.
"""
import datetime
import os
import re
import sys

from koon import KoonSync

PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'releases.toml')
CHROME_PLATFORMS = {'windows': 'Windows', 'macos': 'Mac', 'linux': 'Linux', 'android': 'Android'}

client = KoonSync('chrome')


def get(url):
    response = client.get(url)
    if response.status != 200:
        sys.exit(f'{url}: HTTP {response.status}')
    return response


def key(version):
    return tuple(int(part) for part in version.split('.'))


def chrome():
    """The last Stable release of every milestone, per platform."""
    last = {}
    for field, platform in CHROME_PLATFORMS.items():
        url = f'https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform={platform}&num=1000'
        for release in get(url).json():
            current = last.setdefault(release['milestone'], {}).get(field)
            if current is None or key(release['version']) > key(current):
                last[release['milestone']][field] = release['version']
    return last


def opera_chromium(major, release):
    """The Chromium version of an Opera release from its changelog: the newest Chromium update at or
    before the release. None when that entry names no version."""
    page = get(f'https://blogs.opera.com/desktop/changelog-for-{major}/').text
    text = re.sub(r'<[^>]+>', '\n', page)
    sections = re.split(r'\n\s*(\d+\.\d+\.\d+\.\d+) \S+ \d{4}-\d{2}-\d{2}', text)
    found = False
    for version, body in zip(sections[1::2], sections[2::2]):
        found = found or version == release
        if not found:
            continue
        for line in body.splitlines():
            if re.search(r'Updat\w* Chromium', line):
                match = re.search(r'\b(\d+\.0\.\d+\.\d+)\b', line)
                return match.group(1) if match else None
    return None


def opera(majors):
    listing = get('https://get.geo.opera.com/pub/opera/desktop/').text
    last = {}
    for version in re.findall(r'href="(\d+\.\d+\.\d+\.\d+)/"', listing):
        major = int(version.split('.')[0])
        if major in majors and key(version) > key(last.get(major, '0')):
            last[major] = version
    return last


def brave(majors):
    """The last Brave release on every Chromium major, from its release titles."""
    last = {}
    for page in range(1, 11):
        releases = get(f'https://api.github.com/repos/brave/brave-browser/releases?per_page=100&page={page}').json()
        oldest = None
        for release in releases:
            match = re.match(r'Release v([\d.]+) \(Chromium ([\d.]+)\)', release['name'] or '')
            if not match:
                continue
            version, chromium = match.groups()
            major = int(chromium.split('.')[0])
            oldest = major if oldest is None else min(oldest, major)
            if major in majors and key(version) > key(last.get(major, ('0', ''))[0]):
                last[major] = (version, chromium)
        if not releases or (oldest is not None and oldest < min(majors)):
            break
    return last


def edge():
    products = get('https://edgeupdates.microsoft.com/api/products').json()
    stable = next(p for p in products if p['Product'] == 'Stable')
    release = next(r for r in stable['Releases'] if r['Platform'] == 'Windows' and r['Architecture'] == 'x64')
    return release['ProductVersion']


def table(text, name):
    """The span of a [name] table."""
    start = text.index(f'\n[{name}]\n')
    end = text.find('\n[', start + 1)
    return start, len(text) if end < 0 else end


def main():
    check = '--check' in sys.argv[1:]
    text = open(PATH, encoding='utf-8').read()
    changes, notes = [], []
    today = datetime.date.today().isoformat()

    def update_table(name, update_row):
        nonlocal text
        start, end = table(text, name)
        block = text[start:end]
        new = re.sub(r'(?m)^  \{.*\},?$', lambda m: update_row(m.group(0)), block)
        if new != block:
            new = re.sub(r'(?m)^updated = .*$', f'updated = {today}', new, count=1)
            text = text[:start] + new + text[end:]

    def field(row, name):
        return re.search(rf'\b{name} = "?([\w.]+)"?', row).group(1)

    def set_field(row, name, value, label):
        old = field(row, name)
        if old != value:
            changes.append(f'{label} {name}: {old} -> {value}')
            row = re.sub(rf'\b{name} = "[\w.]+"', f'{name} = "{value}"', row)
        return row

    last = chrome()

    def chrome_row(row):
        major = int(field(row, 'major'))
        for name, version in last.get(major, {}).items():
            row = set_field(row, name, version, f'Chrome {major}')
        return row

    update_table('chrome', chrome_row)

    start, end = table(text, 'opera')
    majors = [int(m) for m in re.findall(r'\{ major = (\d+),', text[start:end])]
    last_opera = opera(majors)

    def opera_row(row):
        major = int(field(row, 'major'))
        release = last_opera.get(major)
        if release is None or release == field(row, 'full'):
            return row
        chromium = opera_chromium(major, release)
        if chromium is None or chromium.split('.')[0] != field(row, 'chromium'):
            notes.append(f'Opera {release}: its changelog names no Chromium {field(row, "chromium")} version')
            return row
        row = set_field(row, 'full', release, f'Opera {major}')
        return set_field(row, 'chromium_full', chromium, f'Opera {major}')

    update_table('opera', opera_row)

    start, end = table(text, 'brave')
    majors = [int(m) for m in re.findall(r'\{ chromium = (\d+),', text[start:end])]
    last_brave = brave(majors)

    def brave_row(row):
        major = int(field(row, 'chromium'))
        if major not in last_brave:
            return row
        version, chromium = last_brave[major]
        row = set_field(row, 'brave', version, f'Brave (Chromium {major})')
        return set_field(row, 'chromium_full', chromium, f'Brave (Chromium {major})')

    update_table('brave', brave_row)

    edge_version = edge()
    start, end = table(text, 'edge')
    row = re.search(rf'\{{ major = {edge_version.split(".")[0]}, full = "([\d.]+)"', text[start:end])
    if row and row.group(1) != edge_version:
        notes.append(f'Edge {edge_version} (table: {row.group(1)}): capture its Chromium version '
                     '(Sec-CH-UA-Full-Version-List)')

    for line in changes:
        print(line)
    for line in notes:
        print('note:', line)
    if not changes:
        print('releases.toml is up to date')
    elif check:
        sys.exit(1)
    else:
        open(PATH, 'w', encoding='utf-8', newline='\n').write(text)


if __name__ == '__main__':
    main()
