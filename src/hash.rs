//! A fast hash for keys that are already random.
//!
//! The standard library hashes with SipHash-1-3, which is a good default
//! because it makes hash collisions unpredictable to somebody who gets to
//! choose the keys. What this daemon hashes is MAC addresses, interface
//! indices and a handful of interface names - and it hashes them constantly:
//! a pass over a large host puts thousands of addresses through several sets.
//! SipHash's guarantee costs more than the lookups themselves.
//!
//! This is the multiply-rotate hash rustc uses internally (FxHash), written
//! out here rather than taken as a dependency: the whole daemon is one
//! dependency deep on purpose, which is what makes a static binary for a
//! foreign host a matter of one build flag.
//!
//! What SipHash buys and this does not is collisions an attacker cannot
//! predict, and here the attacker is real: the keys are MAC addresses the
//! bridges learnt, and a guest behind the bridge chooses those by sending
//! frames. Thousands of addresses that all land in one bucket turn every
//! lookup into a walk, and a pass over a large table is where this daemon
//! spends what little time it spends.
//!
//! So the state is seeded, once per process, from the kernel's random pool.
//! The multiply-rotate step is unchanged and still costs a multiplication;
//! what changes is that the arrangement it produces is not the same twice, so
//! there is nothing to aim at. That is not SipHash's guarantee - somebody who
//! learns the seed can still construct collisions - but it is the difference
//! between an attack anybody can copy from a blog post and one that needs the
//! contents of this process's memory.

use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};

/// The odd 64-bit constant rustc's FxHash uses: 2^64 / phi, rounded to odd.
const MULTIPLIER: u64 = 0x51_7c_c1_b7_27_22_0a_95;

/// Where every hash in this process starts. Zero means "not chosen yet";
/// once chosen it never changes, because a set whose hasher changed under it
/// would never find anything again.
static SEED: AtomicU64 = AtomicU64::new(0);

fn seed() -> u64 {
    let existing = SEED.load(Ordering::Relaxed);
    if existing != 0 {
        return existing;
    }
    let mut bytes = [0u8; 8];
    let got = unsafe {
        libc::getrandom(
            bytes.as_mut_ptr() as *mut libc::c_void,
            bytes.len(),
            libc::GRND_NONBLOCK,
        )
    };
    // A kernel that will not hand out randomness leaves the seed at a fixed
    // value rather than a weak one: the daemon still works, it simply has the
    // predictability this is meant to remove. It has never been seen to
    // happen outside early boot.
    let fresh = if got == bytes.len() as isize {
        u64::from_ne_bytes(bytes) | 1
    } else {
        MULTIPLIER
    };
    // First writer wins; everyone else takes what is there. Two hashers in
    // one process must never disagree about where a key belongs.
    match SEED.compare_exchange(0, fresh, Ordering::Relaxed, Ordering::Relaxed) {
        Ok(_) => fresh,
        Err(already) => already,
    }
}

#[derive(Clone, Copy)]
pub struct FxHasher {
    hash: u64,
}

impl Default for FxHasher {
    fn default() -> Self {
        FxHasher { hash: seed() }
    }
}

impl FxHasher {
    #[inline]
    fn add(&mut self, word: u64) {
        self.hash = (self.hash.rotate_left(5) ^ word).wrapping_mul(MULTIPLIER);
    }
}

impl Hasher for FxHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut rest = bytes;
        while rest.len() >= 8 {
            self.add(u64::from_ne_bytes(rest[..8].try_into().unwrap()));
            rest = &rest[8..];
        }
        if rest.len() >= 4 {
            self.add(u32::from_ne_bytes(rest[..4].try_into().unwrap()) as u64);
            rest = &rest[4..];
        }
        for b in rest {
            self.add(*b as u64);
        }
    }

    #[inline]
    fn write_u8(&mut self, n: u8) {
        self.add(n as u64);
    }

    #[inline]
    fn write_u32(&mut self, n: u32) {
        self.add(n as u64);
    }

    #[inline]
    fn write_u64(&mut self, n: u64) {
        self.add(n);
    }

    #[inline]
    fn write_usize(&mut self, n: usize) {
        self.add(n as u64);
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.hash
    }
}

pub type FxBuild = BuildHasherDefault<FxHasher>;
pub type Set<T> = HashSet<T, FxBuild>;
pub type Map<K, V> = HashMap<K, V, FxBuild>;

/// `HashSet::new` and `HashMap::new` exist only for the default hasher, so
/// these stand in for them.
pub fn set<T>() -> Set<T> {
    Set::default()
}

pub fn map<K, V>() -> Map<K, V> {
    Map::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::Hash;

    fn hash_of<T: Hash>(v: &T) -> u64 {
        let mut h = FxHasher::default();
        v.hash(&mut h);
        h.finish()
    }

    /// The point of a hash is that different things land in different places.
    /// A hash that ignores part of its input passes every set test - the set
    /// still works, it just gets slow - so this looks at the hash itself.
    #[test]
    fn every_byte_of_an_address_reaches_the_hash() {
        let base = [0x02u8, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mut seen = std::collections::HashSet::new();
        seen.insert(hash_of(&base));
        for i in 0..6 {
            for bit in 0..8 {
                let mut other = base;
                other[i] ^= 1 << bit;
                assert!(
                    seen.insert(hash_of(&other)),
                    "flipping bit {bit} of byte {i} did not change the hash"
                );
            }
        }
    }

    #[test]
    fn the_sets_behave_like_sets() {
        let mut s: Set<[u8; 6]> = set();
        assert!(s.insert([1, 2, 3, 4, 5, 6]));
        assert!(!s.insert([1, 2, 3, 4, 5, 6]));
        assert!(s.contains(&[1, 2, 3, 4, 5, 6]));
        assert!(!s.contains(&[1, 2, 3, 4, 5, 7]));

        let mut m: Map<u32, &str> = map();
        m.insert(7, "seven");
        assert_eq!(m.get(&7), Some(&"seven"));
        assert_eq!(m.get(&8), None);
    }

    /// The arrangement must not be the same in two processes, or a guest that
    /// chooses the addresses the bridge learns can choose which of them
    /// collide. Same process, same answer - a set whose hasher changed under
    /// it would never find anything again.
    #[test]
    fn the_seed_is_per_process_and_stable_within_it() {
        let a = hash_of(&[0x02u8, 0, 0, 0, 0, 1]);
        let b = hash_of(&[0x02u8, 0, 0, 0, 0, 1]);
        assert_eq!(a, b, "the same key has to land in the same place");
        assert_ne!(
            super::seed(),
            0,
            "a seed of zero means the state was never initialised"
        );
        // Not the bare multiply-rotate of an unseeded hasher: that is what
        // an attacker would reproduce at home.
        let unseeded = {
            let mut h = FxHasher { hash: 0 };
            [0x02u8, 0, 0, 0, 0, 1].hash(&mut h);
            h.finish()
        };
        assert_ne!(
            a, unseeded,
            "the hash has to depend on the seed, or seeding it changed nothing"
        );
    }
}
