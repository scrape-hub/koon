const SIZES: [usize; 13] = [0, 3, 7, 13, 23, 41, 71, 127, 191, 251, 383, 631, 1087];
const CAPACITIES: [usize; 13] = [0, 3, 6, 11, 19, 32, 52, 85, 118, 155, 237, 390, 672];

fn cf_hash(name: &str) -> u64 {
    hash_chars(
        name.bytes()
            .map(|b| u32::from(b.to_ascii_lowercase()))
            .collect(),
    )
}

fn cf_hash_exact(name: &str) -> u64 {
    hash_chars(name.bytes().map(u32::from).collect())
}

fn hash_chars(chars: Vec<u32>) -> u64 {
    let len = chars.len();
    let mut result = len as u64;
    let mut four = |c: &[u32]| {
        let inner = c[0]
            .wrapping_mul(257)
            .wrapping_add(c[1])
            .wrapping_mul(257)
            .wrapping_add(c[2])
            .wrapping_mul(257)
            .wrapping_add(c[3]);
        result = result
            .wrapping_mul(67_503_105)
            .wrapping_add(u64::from(inner));
    };
    if len <= 96 {
        let mut quads = chars.chunks_exact(4);
        quads.by_ref().for_each(&mut four);
        let rest = quads.remainder();
        for &c in rest {
            result = result.wrapping_mul(257).wrapping_add(u64::from(c));
        }
    } else {
        let middle = len / 2 - 16;
        for piece in [
            &chars[..32],
            &chars[middle..middle + 32],
            &chars[len - 32..],
        ] {
            piece.chunks_exact(4).for_each(&mut four);
        }
    }
    result.wrapping_add(result << (len & 31))
}

#[derive(Clone, PartialEq, Debug)]
enum Bucket {
    Empty,
    Deleted,
    Name(String),
}

#[derive(Clone, Debug)]
pub(crate) struct HeaderDict {
    size: usize,
    buckets: Vec<Bucket>,
    used: usize,
    deleted: usize,
}

impl HeaderDict {
    pub(crate) fn new() -> Self {
        Self {
            size: 0,
            buckets: Vec::new(),
            used: 0,
            deleted: 0,
        }
    }

    pub(crate) fn with<I: IntoIterator<Item = S>, S: AsRef<str>>(names: I) -> Self {
        let mut dict = Self::new();
        for name in names {
            dict.set(name.as_ref());
        }
        dict
    }

    pub(crate) fn order(&self) -> Vec<&str> {
        self.buckets
            .iter()
            .filter_map(|b| match b {
                Bucket::Name(name) => Some(name.as_str()),
                _ => None,
            })
            .collect()
    }

    pub(crate) fn home(&self, name: &str) -> usize {
        match SIZES[self.size] {
            0 => 0,
            n => (cf_hash(name) % n as u64) as usize,
        }
    }

    fn find(&self, name: &str) -> (Option<usize>, Option<usize>) {
        let n = SIZES[self.size];
        if n == 0 {
            return (None, None);
        }
        let mut probe = (cf_hash(name) % n as u64) as usize;
        let mut deleted = None;
        for _ in 0..n {
            match &self.buckets[probe] {
                Bucket::Empty => return (None, deleted.or(Some(probe))),
                Bucket::Deleted => {
                    deleted.get_or_insert(probe);
                }
                Bucket::Name(existing) if existing.eq_ignore_ascii_case(name) => {
                    return (Some(probe), None);
                }
                Bucket::Name(_) => {}
            }
            probe = if probe + 1 == n { 0 } else { probe + 1 };
        }
        (None, deleted)
    }

    fn rehash(&mut self, new_items: isize) {
        if new_items != 0 {
            let wanted = self.used + new_items.max(0).unsigned_abs();
            self.size = CAPACITIES
                .iter()
                .position(|&c| wanted <= c)
                .expect("a header dictionary stays small");
        }
        let n = SIZES[self.size];
        let old = std::mem::replace(&mut self.buckets, vec![Bucket::Empty; n]);
        self.deleted = 0;
        for name in old.into_iter().filter_map(|b| match b {
            Bucket::Name(name) => Some(name),
            _ => None,
        }) {
            let mut probe = (cf_hash(&name) % n as u64) as usize;
            while self.buckets[probe] != Bucket::Empty {
                probe = if probe + 1 == n { 0 } else { probe + 1 };
            }
            self.buckets[probe] = Bucket::Name(name);
        }
    }

    pub(crate) fn set(&mut self, name: &str) {
        let (found, mut slot) = self.find(name);
        if let Some(at) = found {
            self.buckets[at] = Bucket::Name(name.to_string());
            return;
        }
        if CAPACITIES[self.size] < self.used + 1 {
            self.rehash(1);
            slot = self.find(name).1;
        } else if slot.is_some_and(|at| self.buckets[at] == Bucket::Deleted) {
            self.deleted -= 1;
        }
        let at = slot.expect("a table below capacity has a free bucket");
        self.buckets[at] = Bucket::Name(name.to_string());
        self.used += 1;
    }

    pub(crate) fn remove(&mut self, name: &str) {
        let Some(at) = self.find(name).0 else {
            return;
        };
        self.buckets[at] = Bucket::Deleted;
        self.used -= 1;
        self.deleted += 1;
        if self.size > 2 && self.used < CAPACITIES[self.size - 2] {
            self.rehash(-1);
        } else if SIZES[self.size] >= 20 && SIZES[self.size] / 4 <= self.deleted {
            self.rehash(0);
        }
    }

    pub(crate) fn rebuild<I: IntoIterator<Item = S>, S: AsRef<str>>(&mut self, names: I) {
        let old: Vec<String> = self.order().into_iter().map(str::to_string).collect();
        for name in old {
            self.remove(&name);
        }
        for name in names {
            self.set(name.as_ref());
        }
    }
}

pub(crate) fn ipc_order<'a>(names: &[&'a str]) -> Vec<&'a str> {
    let size = CAPACITIES
        .iter()
        .position(|&c| names.len() <= c)
        .expect("a header dictionary stays small");
    let n = SIZES[size];
    let mut buckets: Vec<Option<&str>> = vec![None; n];
    for &name in names {
        let mut probe = (cf_hash_exact(name) % n as u64) as usize;
        while buckets[probe].is_some() {
            probe = if probe + 1 == n { 0 } else { probe + 1 };
        }
        buckets[probe] = Some(name);
    }
    buckets.into_iter().flatten().collect()
}
