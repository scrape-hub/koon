const RAPID_SEED: u64 = 0xbdd8_9aa9_8270_4029;
const RAPID_SECRET: [u64; 3] = [
    0x2d35_8dcc_aa6c_78a5,
    0x8bb8_4b93_962e_acc9,
    0x4b33_a62e_d433_d4a3,
];

const MINIMUM_TABLE_SIZE: usize = 8;

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

fn case_folding_hash(name: &str) -> u32 {
    let units: Vec<u8> = name
        .bytes()
        .flat_map(|b| u16::from(b.to_ascii_lowercase()).to_le_bytes())
        .collect();
    let hash = (rapidhash(&units) & 0x00ff_ffff) as u32;
    if hash == 0 { 0x0080_0000 } else { hash }
}

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
