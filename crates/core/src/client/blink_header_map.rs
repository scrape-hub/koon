//! The order in which Blink's request header map (`fetch()`, `XMLHttpRequest`, subresources) hands
//! its headers to the network stack: a `WTF::HashMap` keyed by `DeprecatedCaseFoldingHash`,
//! iterated in bucket order, which depends on which headers are present. Rebuilds that table;
//! rapidhash, growth and probing match `wtf/hash_table.h`/`text/case_folding_hash.h` (Chromium
//! 155).

/// rapidhash's default seed and secrets (`third_party/rapidhash`).
const RAPID_SEED: u64 = 0xbdd8_9aa9_8270_4029;
const RAPID_SECRET: [u64; 3] = [
    0x2d35_8dcc_aa6c_78a5,
    0x8bb8_4b93_962e_acc9,
    0x4b33_a62e_d433_d4a3,
];

/// The table size of a new map (`HashTraits::kMinimumTableSize`).
const MINIMUM_TABLE_SIZE: usize = 8;

/// Splits a 128-bit product into its low and high 64 bits: the truncation is the point, matching
/// rapidhash's own 128-bit multiply-and-split.
#[allow(clippy::cast_possible_truncation)]
fn mul128(a: u64, b: u64) -> (u64, u64) {
    let r = u128::from(a) * u128::from(b);
    (r as u64, (r >> 64) as u64)
}

fn mix(a: u64, b: u64) -> u64 {
    let (lo, hi) = mul128(a, b);
    lo ^ hi
}

fn read64(p: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(p[at..at + 8].try_into().expect("8 bytes"))
}

fn read32(p: &[u8], at: usize) -> u64 {
    u64::from(u32::from_le_bytes(
        p[at..at + 4].try_into().expect("4 bytes"),
    ))
}

/// rapidhash of `p`, which holds UTF-16 code units: its length is even, so the 1-to-3-byte case of
/// the reference cannot occur.
fn rapidhash(p: &[u8]) -> u64 {
    let len = p.len();
    let mut seed = RAPID_SEED ^ mix(RAPID_SEED ^ RAPID_SECRET[0], RAPID_SECRET[1]) ^ len as u64;
    let (mut a, mut b);
    if len <= 16 {
        if len >= 4 {
            let last = len - 4;
            a = (read32(p, 0) << 32) | read32(p, last);
            let delta = (len & 24) >> (len >> 3);
            b = (read32(p, delta) << 32) | read32(p, last - delta);
        } else {
            a = 0;
            b = 0;
        }
    } else {
        let mut i = len;
        let mut at = 0;
        if i > 48 {
            let (mut see1, mut see2) = (seed, seed);
            while i >= 48 {
                seed = mix(read64(p, at) ^ RAPID_SECRET[0], read64(p, at + 8) ^ seed);
                see1 = mix(
                    read64(p, at + 16) ^ RAPID_SECRET[1],
                    read64(p, at + 24) ^ see1,
                );
                see2 = mix(
                    read64(p, at + 32) ^ RAPID_SECRET[2],
                    read64(p, at + 40) ^ see2,
                );
                at += 48;
                i -= 48;
            }
            seed ^= see1 ^ see2;
        }
        if i > 16 {
            seed = mix(
                read64(p, at) ^ RAPID_SECRET[2],
                read64(p, at + 8) ^ seed ^ RAPID_SECRET[1],
            );
            if i > 32 {
                seed = mix(
                    read64(p, at + 16) ^ RAPID_SECRET[2],
                    read64(p, at + 24) ^ seed,
                );
            }
        }
        a = read64(p, at + i - 16);
        b = read64(p, at + i - 8);
    }
    a ^= RAPID_SECRET[1];
    b ^= seed;
    let (a, b) = mul128(a, b);
    mix(a ^ RAPID_SECRET[0] ^ len as u64, b ^ RAPID_SECRET[1])
}

/// `DeprecatedCaseFoldingHash` of a header name: rapidhash of the lowercase name as UTF-16LE,
/// reduced to 24 bits, never 0. Header names are ASCII tokens, which Blink keeps as Latin-1
/// strings.
fn case_folding_hash(name: &str) -> u32 {
    let units: Vec<u8> = name
        .bytes()
        .flat_map(|b| u16::from(b.to_ascii_lowercase()).to_le_bytes())
        .collect();
    let hash = (rapidhash(&units) & 0x00ff_ffff) as u32;
    if hash == 0 { 0x0080_0000 } else { hash }
}

/// The names of a map that `names` were set on in this order, in the map's iteration order. Names
/// are compared ignoring case; a name set again keeps its bucket.
pub(crate) fn iteration_order<'a>(names: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
    let mut table: Vec<Option<(&str, u32)>> = Vec::new();
    let mut count = 0;
    for name in names {
        if table.is_empty() {
            table = vec![None; MINIMUM_TABLE_SIZE];
        }
        let hash = case_folding_hash(name);
        if !insert(&mut table, name, hash) {
            continue;
        }
        count += 1;
        // `ShouldExpand`: at half load the table doubles, and its entries move over in bucket
        // order.
        if count * 2 >= table.len() {
            let old = std::mem::take(&mut table);
            table = vec![None; old.len() * 2];
            for (name, hash) in old.into_iter().flatten() {
                insert(&mut table, name, hash);
            }
        }
    }
    table.into_iter().flatten().map(|(name, _)| name).collect()
}

/// Put `name` into its bucket; `false` if the table holds it already.
fn insert<'a>(table: &mut [Option<(&'a str, u32)>], name: &'a str, hash: u32) -> bool {
    let mask = table.len() - 1;
    let mut i = hash as usize & mask;
    let mut probe = 0;
    while let Some((existing, _)) = table[i] {
        if existing.eq_ignore_ascii_case(name) {
            return false;
        }
        probe += 1;
        i = (i + probe) & mask;
    }
    table[i] = Some((name, hash));
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The client hints and User-Agent of a same-origin fetch() in the order Blink sets them
    /// (`FrameFetchContext::AddClientHintsIfNecessary`, then `PrepareRequest`), and the order the
    /// browsers sent them in.
    #[test]
    fn reproduces_captured_orders() {
        // Chrome 155 on Android, the hints of an Accept-CH asking for the User-Agent, device and
        // network hints.
        let set = [
            "device-memory",
            "sec-ch-device-memory",
            "rtt",
            "downlink",
            "ect",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-arch",
            "sec-ch-ua-platform",
            "sec-ch-ua-platform-version",
            "sec-ch-ua-model",
            "sec-ch-ua-full-version",
            "sec-ch-ua-full-version-list",
            "sec-ch-ua-bitness",
            "sec-ch-ua-wow64",
            "sec-ch-ua-form-factors",
            "sec-ch-prefers-color-scheme",
            "dpr",
            "sec-ch-dpr",
            "viewport-width",
            "sec-ch-viewport-width",
            "user-agent",
        ];
        assert_eq!(
            iteration_order(set),
            [
                "sec-ch-ua-full-version-list",
                "sec-ch-ua-platform",
                "viewport-width",
                "device-memory",
                "sec-ch-ua",
                "sec-ch-dpr",
                "sec-ch-ua-model",
                "sec-ch-ua-mobile",
                "sec-ch-ua-form-factors",
                "sec-ch-ua-bitness",
                "sec-ch-ua-wow64",
                "sec-ch-ua-arch",
                "sec-ch-ua-full-version",
                "sec-ch-viewport-width",
                "downlink",
                "ect",
                "sec-ch-device-memory",
                "dpr",
                "sec-ch-prefers-color-scheme",
                "user-agent",
                "rtt",
                "sec-ch-ua-platform-version",
            ]
        );
        // The same fetch() with a JSON body: Content-Type comes first, from fetch()'s header list.
        let with_body: Vec<&str> = std::iter::once("content-type").chain(set).collect();
        let order = iteration_order(with_body);
        let at = |name| order.iter().position(|n| *n == name).unwrap();
        assert_eq!(at("content-type"), at("sec-ch-ua-full-version") + 1);
        assert_eq!(at("sec-ch-viewport-width"), at("content-type") + 1);

        // Chrome 153 on Windows with fewer hints: 15 entries fit into 32 buckets, where `downlink`
        // wraps around to the first one.
        let chrome_153 = [
            "rtt",
            "downlink",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-arch",
            "sec-ch-ua-platform",
            "sec-ch-ua-platform-version",
            "sec-ch-ua-model",
            "sec-ch-ua-full-version",
            "sec-ch-ua-full-version-list",
            "sec-ch-ua-bitness",
            "sec-ch-ua-wow64",
            "sec-ch-ua-form-factors",
            "sec-ch-prefers-color-scheme",
            "user-agent",
        ];
        assert_eq!(
            iteration_order(chrome_153),
            [
                "downlink",
                "sec-ch-ua-full-version-list",
                "sec-ch-ua-platform",
                "sec-ch-ua",
                "sec-ch-ua-bitness",
                "sec-ch-ua-model",
                "sec-ch-ua-mobile",
                "sec-ch-ua-form-factors",
                "sec-ch-ua-wow64",
                "sec-ch-ua-arch",
                "sec-ch-ua-full-version",
                "sec-ch-prefers-color-scheme",
                "user-agent",
                "rtt",
                "sec-ch-ua-platform-version",
            ]
        );
        // A Content-Type grows the table to 64 buckets: `downlink` follows it then (Chrome 153).
        let order = iteration_order(std::iter::once("content-type").chain(chrome_153));
        let at = |name| order.iter().position(|n| *n == name).unwrap();
        assert_eq!(at("downlink"), at("content-type") + 1);

        // Without client hints (Chrome 153, fetch() with a body).
        assert_eq!(
            iteration_order([
                "content-type",
                "sec-ch-ua",
                "sec-ch-ua-mobile",
                "sec-ch-ua-platform",
                "user-agent"
            ]),
            [
                "sec-ch-ua-platform",
                "user-agent",
                "sec-ch-ua",
                "content-type",
                "sec-ch-ua-mobile"
            ]
        );
    }

    #[test]
    fn names_are_compared_and_hashed_ignoring_case() {
        assert_eq!(
            case_folding_hash("User-Agent"),
            case_folding_hash("user-agent")
        );
        assert_eq!(
            iteration_order(["Sec-CH-UA", "sec-ch-ua", "user-agent"]),
            ["user-agent", "Sec-CH-UA"]
        );
        // Long names take rapidhash's 48-byte rounds.
        assert_eq!(
            case_folding_hash("sec-ch-prefers-reduced-transparency"),
            0x002d_8c14
        );
    }
}
