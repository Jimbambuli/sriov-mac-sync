//! A fast hash for keys that are already random.
//!
//! SipHash-1-3 makes collisions unpredictable to somebody who chooses the
//! keys, and costs more than the lookups themselves: this daemon hashes MAC
//! addresses and interface indices constantly, thousands per pass. This is
//! rustc's multiply-rotate hash (FxHash), written out rather than taken as a
//! dependency - the daemon is one dependency deep on purpose.
//!
//! The attacker is real, though: the keys are addresses the bridges learnt,
//! and a guest chooses those by sending frames; thousands in one bucket turn
//! every lookup into a walk. So the state is seeded once per process from the
//! kernel's random pool: the arrangement is not the same twice, so there is
//! nothing to aim at. Not SipHash's guarantee - somebody who learns the seed
//! can still construct collisions - but the difference between an attack
//! copied from a blog post and one that needs this process's memory.
//!
//! The pool is asked without waiting; a refusal falls through to weaker
//! per-start sources, never to a constant - `fresh_seed` says why.

use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasherDefault, Hasher};
use std::io;
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
    let fresh = fresh_seed();
    // First writer wins; everyone else takes what is there. Two hashers in
    // one process must never disagree about where a key belongs.
    match SEED.compare_exchange(0, fresh, Ordering::Relaxed, Ordering::Relaxed) {
        Ok(_) => fresh,
        Err(already) => already,
    }
}

/// `AT_RANDOM`: the address of sixteen bytes the kernel puts on the initial
/// stack for every process it starts. The number is the same on every
/// architecture Linux has, and libc does not export it.
const AT_RANDOM: libc::c_ulong = 25;

/// This process's seed, from the first source that answers.
///
/// Chosen once and never changed, so a source that will not answer must fall
/// through to another, not to a constant: a daemon started by systemd at boot
/// can ask before the pool is initialised, and a constant left every host in
/// the fleet hashing with the same arrangement - exactly what a guest behind
/// the bridge gets to aim at.
fn fresh_seed() -> u64 {
    if let Some(n) = from_getrandom() {
        return n | 1;
    }
    // The pool is not ready. What is left is weaker - the exec bytes came
    // from the same pool, a boot clock is a narrow range - but differs from
    // one process to the next, which the constant did not.
    (from_auxv() ^ from_the_moment()) | 1
}

/// Eight bytes from the kernel, if it has any without waiting: a daemon that
/// blocks here blocks the boot it was ordered into.
fn from_getrandom() -> Option<u64> {
    let mut bytes = [0u8; 8];
    let mut got = 0;
    while got < bytes.len() {
        let n = unsafe {
            libc::getrandom(
                bytes[got..].as_mut_ptr() as *mut libc::c_void,
                bytes.len() - got,
                libc::GRND_NONBLOCK,
            )
        };
        if n > 0 {
            got += n as usize;
        } else if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        } else {
            return None;
        }
    }
    Some(u64::from_ne_bytes(bytes))
}

/// The bytes the kernel put on the stack at exec - from the same pool
/// `getrandom` refused from, so no better at early boot, but drawn per
/// process.
fn from_auxv() -> u64 {
    let at = unsafe { libc::getauxval(AT_RANDOM) } as *const u8;
    if at.is_null() {
        return 0;
    }
    let mut bytes = [0u8; 8];
    // Sixteen bytes, valid for as long as the process is. Eight are taken.
    unsafe { std::ptr::copy_nonoverlapping(at, bytes.as_mut_ptr(), bytes.len()) };
    u64::from_ne_bytes(bytes)
}

/// Whatever this particular start differs in: two clocks, the process id and
/// an address the loader placed. None of it is secret and none of it is
/// worth much on its own; the point is only that it is not a constant.
fn from_the_moment() -> u64 {
    let mut mono: libc::timespec = unsafe { std::mem::zeroed() };
    let mut real: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut mono);
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut real);
    }
    let stack = &mono as *const libc::timespec as u64;
    (mono.tv_nsec as u64).rotate_left(17)
        ^ (real.tv_nsec as u64).rotate_left(31)
        ^ (real.tv_sec as u64)
        ^ stack.rotate_left(43)
        ^ (std::process::id() as u64).rotate_left(7)
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

    /// The arrangement must differ between two processes, or a guest choosing
    /// the addresses the bridge learns chooses which collide. Same process,
    /// same answer - a set whose hasher changed under it would never find
    /// anything.
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

    /// The seed is chosen once, so the path taken when the pool is not ready
    /// (a daemon started at boot) decides the arrangement for the process's
    /// life. It has to differ between starts.
    #[test]
    fn the_seed_without_the_pool_still_differs_between_starts() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..8 {
            seen.insert((super::from_auxv() ^ super::from_the_moment()) | 1);
        }
        assert!(
            seen.len() > 1,
            "the fallback seed was the same every time: {seen:?}"
        );
        assert!(
            !seen.contains(&MULTIPLIER),
            "the fallback seed is the constant an attacker reproduces at home"
        );
        assert!(
            !seen.contains(&0),
            "a seed of zero hashes everything to zero"
        );
    }

    /// Whatever the seed came from, the `| 1` has to hold: an even seed is
    /// legal for the hash, but a zero one is the sentinel `SEED` reads as
    /// "not chosen yet" - and odd is the cheapest way to never be zero.
    #[test]
    fn the_seed_is_odd_whichever_source_gave_it() {
        assert_eq!(super::fresh_seed() & 1, 1);
        assert_eq!(super::seed() & 1, 1);
    }
}
