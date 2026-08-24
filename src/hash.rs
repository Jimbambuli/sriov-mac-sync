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
//! What is given up: an attacker who chooses the keys can make lookups
//! collide. Here the keys are MAC addresses the bridges learnt, so a guest
//! behind the bridge can indeed choose some of them. The damage it could do
//! is to make this daemon slower - the sets are bounded by what a unicast
//! filter can hold, and a full pass is milliseconds - which is a poor
//! exchange for the constant cost of the defence.

use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasherDefault, Hasher};

/// The odd 64-bit constant rustc's FxHash uses: 2^64 / phi, rounded to odd.
const SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;

#[derive(Default, Clone, Copy)]
pub struct FxHasher {
    hash: u64,
}

impl FxHasher {
    #[inline]
    fn add(&mut self, word: u64) {
        self.hash = (self.hash.rotate_left(5) ^ word).wrapping_mul(SEED);
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
}
