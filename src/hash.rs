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
//!
//! The pool is asked without waiting, and a refusal falls through to weaker
//! per-start sources rather than to a constant - `fresh_seed` tells why.

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
/// The seed is chosen once and then never changes, so there is no second
/// chance at it: whatever this returns is what the daemon hashes with until
/// it exits. That is why a source that will not answer has to fall through
/// to another one rather than to a constant. A daemon started by systemd at
/// boot - which is how this one is started - can easily ask before the
/// kernel's pool is initialised, and that used to leave every host in the
/// fleet hashing with the same arrangement: exactly the thing a guest behind
/// the bridge gets to aim at.
fn fresh_seed() -> u64 {
    if let Some(n) = from_getrandom() {
        return n | 1;
    }
    // The pool is not ready. What is left is not as good - the bytes the
    // kernel handed this process at exec came from the same pool, and a
    // clock at boot is a narrow range - but between them they differ from
    // one process to the next, which the constant did not.
    (from_auxv() ^ from_the_moment()) | 1
}

/// Eight bytes from the kernel, if it has any to give without waiting.
///
/// `GRND_NONBLOCK` rather than a wait: a daemon that blocks here blocks the
/// boot it was ordered into. The failure it buys is handled above.
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

/// The bytes the kernel put on the stack when it started this process.
///
/// Drawn from the same pool `getrandom` refused from, so at early boot they
/// are no better than it is - but they are drawn per process, so two daemons
/// on two hosts do not get the same ones.
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

    /// The seed is chosen once and never again, so the path taken when the
    /// kernel's pool is not ready yet - a daemon started at boot - decides
    /// the arrangement for that whole process's life. It used to be a
    /// constant, which is to say the same arrangement on every host that
    /// started early. Whatever it is now, it has to differ between starts.
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
