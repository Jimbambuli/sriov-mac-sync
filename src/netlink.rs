//! The little bit of rtnetlink this daemon needs:
//!
//! * dump every FDB entry the host knows, learnt and permanent alike,
//! * add or remove an entry with `NTF_SELF` - the interface's own unicast
//!   filter, not the bridge's table,
//! * subscribe to `RTNLGRP_NEIGH` and `RTNLGRP_LINK` - interfaces matter as
//!   much as addresses, because a VF whose MAC is set from the host changes
//!   the exclusions without moving a forwarding entry,
//! * ask one interface for its virtual functions' addresses.
//!
//! By hand rather than through a netlink crate: the layouts are small and
//! stable, and a daemon that writes into a NIC's hardware filters is easier
//! to trust when its dependency list is one crate long.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

pub(crate) const RTM_NEWNEIGH: u16 = 28;
pub(crate) const RTM_DELNEIGH: u16 = 29;
const RTM_GETNEIGH: u16 = 30;
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_GETLINK: u16 = 18;

const NLMSG_NOOP: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

pub(crate) const NLM_F_REQUEST: u16 = 0x001;
const NLM_F_ACK: u16 = 0x004;
const NLM_F_ROOT: u16 = 0x100;
// The same bits mean different things on GET and NEW: MATCH belongs to GET
// (part of NLM_F_DUMP), EXCL to NEW; sharing 0x200 is the kernel's doing - as
// with IFLA_VF_INFO and IFLA_VF_MAC, both 1 at their nesting levels.
const NLM_F_MATCH: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_EXCL: u16 = 0x200;
pub(crate) const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
/// The kernel sets this on a dump whose result changed underneath it: what
/// came back is a mixture of two states and must not be acted on.
const NLM_F_DUMP_INTR: u16 = 0x10;

const NDA_LLADDR: u16 = 2;
const NDA_MASTER: u16 = 9;

const NTF_SELF: u8 = 0x02;
const NTF_EXT_LEARNED: u8 = 0x10;

const NUD_PERMANENT: u16 = 0x80;
const NUD_NOARP: u16 = 0x40;

const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFLA_MASTER: u16 = 10;
const IFLA_LINK: u16 = 5;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
/// A bridge's ageing time, in the kernel's clock_t - USER_HZ hundredths of
/// a second, so 30000 is the default five minutes. Inside IFLA_INFO_DATA,
/// which a plain link dump already carries.
const IFLA_BR_AGEING_TIME: u16 = 4;
const IFLA_PARENT_DEV_NAME: u16 = 56;
const IFLA_LINK_NETNSID: u16 = 37;
const IFLA_EXT_MASK: u16 = 29;
const IFLA_VFINFO_LIST: u16 = 22;
const IFLA_VF_INFO: u16 = 1;
const IFLA_VF_MAC: u16 = 1;
const RTEXT_FILTER_VF: u32 = 1;
/// Asking for virtual function details also fetches their traffic counters,
/// which come out of the hardware. This says not to.
const RTEXT_FILTER_SKIP_STATS: u32 = 1 << 3;

const RTNLGRP_LINK: u32 = 1;
const RTNLGRP_NEIGH: u32 = 3;

/// How long any single read may wait for the kernel. Set on the socket, so a
/// read that would hang comes back by itself.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) const NLMSG_HDR: usize = 16;
const NDMSG_LEN: usize = 12;
const IFINFOMSG_LEN: usize = 16;
pub(crate) const RTATTR_HDR: usize = 4;

const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// One forwarding database entry as the kernel reports it.
#[derive(Debug, Clone)]
pub struct FdbEntry {
    /// interface the entry is attached to - the bridge port, or, for `self`
    /// entries, the interface whose own filter list holds it
    pub ifindex: u32,
    /// bridge the port belongs to, when the kernel says so
    pub master: Option<u32>,
    pub mac: [u8; 6],
    pub state: u16,
    pub flags: u8,
}

impl FdbEntry {
    /// An address the bridge picked up from traffic, as opposed to configured
    /// (a port's own, a hand-added entry). Entries planted by an SDN
    /// controller or a VXLAN daemon count as learnt: they say where a peer
    /// is. NUD_NOARP entries - static VXLAN destinations without
    /// NTF_EXT_LEARNED - describe configuration, not an observed peer.
    pub fn is_learned(&self) -> bool {
        if self.flags & NTF_SELF != 0 || self.state & NUD_PERMANENT != 0 {
            return false;
        }
        if self.flags & NTF_EXT_LEARNED != 0 {
            return true;
        }
        self.state & NUD_NOARP == 0
    }

    /// An entry in an interface's own unicast filter list.
    pub fn is_self(&self) -> bool {
        self.flags & NTF_SELF != 0
    }

    pub fn is_unicast(&self) -> bool {
        self.mac[0] & 1 == 0
    }
}

/// One interface as the kernel describes it. Everything here is in one dump;
/// the SR-IOV relations are not, and are read from /sys for the handful of
/// interfaces that have a device behind them at all.
#[derive(Debug, Default, Clone)]
pub struct LinkInfo {
    pub index: u32,
    pub name: String,
    pub mac: Option<[u8; 6]>,
    /// what this interface is enslaved to, by index
    pub master: Option<u32>,
    /// for a VLAN interface the device it sits on; for a veth its peer, which
    /// is why the kind has to be consulted before believing it
    pub link: Option<u32>,
    pub kind: Option<String>,
    /// A bridge's ageing time in clock_t hundredths, where the kernel offered
    /// one: how long ago an address that has just aged out last spoke.
    pub ageing: Option<u32>,
    /// the bus device behind this interface, when the kernel names one. Its
    /// presence answers "is there a device/ directory" without a stat.
    pub parent_dev: Option<String>,
}

/// The most one datagram's answer may demand, so a nonsensical size cannot
/// be turned into an allocation that ends the process; and how many times a
/// growing buffer is offered before an answer is declared unreachable.
const CEILING: usize = 64 * 1024 * 1024;
const ATTEMPTS: usize = 8;

/// How one attempt at a one-interface question ended.
enum OneEnd {
    /// Answered, or ended by the kernel - the question is over.
    Answered,
    /// The answer was this many bytes and the buffer was not.
    TooBig(usize),
}

/// How a dump ended. "Did not fit" and "was interrupted" both mean the answer
/// cannot be used, but they ask different things of the caller: a bigger
/// buffer, or simply another go.
enum DumpEnd {
    Done,
    Interrupted,
    /// the datagram's real size, which the buffer has to reach
    TooBig(usize),
}

/// A batch of notifications: forwarding entries that changed, and whether any
/// interface changed at all.
#[derive(Debug, Default)]
pub struct Events {
    pub fdb: Vec<(u16, FdbEntry)>,
    pub links_changed: bool,
    /// Which interfaces the link messages were about: the picture has to be
    /// read again; whether the VFs' addresses must be re-asked depends on
    /// which interface, and that is the caller's call.
    pub changed_links: Vec<u32>,
}

pub struct Socket {
    /// Whether a spoofed datagram's drop has been said this run. Draining
    /// them is unavoidable (left queued they crowd out real notifications),
    /// but silently hides that a local process aims unicast netlink at this
    /// socket.
    spoof_warned: std::cell::Cell<bool>,
    /// The receive buffer, kept rather than allocated per call: every read
    /// wants tens or hundreds of kilobytes, and `vec![0u8; n]` is an
    /// allocation plus a walk to zero it, per batch, dump and
    /// acknowledgement.
    ///
    /// It only grows, and is not shrunk: what it grew to is this host's
    /// forwarding table in one datagram, which the next dump asks for again -
    /// giving it back means finding it out again by a dump that overruns. The
    /// ceiling is in `dump_into`.
    buf: Vec<u8>,
    fd: OwnedFd,
    seq: u32,
}

impl Socket {
    /// The kept buffer, at least `want` bytes, taken out for the duration of
    /// a read. Taking it rather than borrowing is what lets `&mut self`
    /// methods pass it to `&self` ones; the caller puts it back.
    fn take_buf(&mut self, want: usize) -> Vec<u8> {
        let mut buf = std::mem::take(&mut self.buf);
        if buf.len() < want {
            buf.resize(want, 0);
        }
        buf
    }

    pub fn new() -> io::Result<Self> {
        Self::open(0)
    }

    /// A socket that also receives forwarding and interface notifications: a
    /// NIC that gets VFs, a bridge built after boot, a VF whose address is
    /// set from the host all change the filter without moving a forwarding
    /// entry.
    pub fn subscribed() -> io::Result<Self> {
        Self::open((1 << (RTNLGRP_NEIGH - 1)) | (1 << (RTNLGRP_LINK - 1)))
    }

    fn open(groups: u32) -> io::Result<Self> {
        Self::open_on(groups, libc::NETLINK_ROUTE)
    }

    fn open_on(groups: u32, protocol: libc::c_int) -> io::Result<Self> {
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                protocol,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // A dump of a large forwarding database overruns the default receive
        // buffer, and netlink answers with ENOBUFS rather than short reads.
        //
        // SO_RCVBUF is silently capped at net.core.rmem_max (208 KiB stock,
        // against the megabyte asked for); SO_RCVBUFFORCE ignores the ceiling
        // and needs CAP_NET_ADMIN, which this program holds anyway. Falls
        // back to the capped request where refused: losing notifications is
        // survivable, the full pass reads the real state.
        let size: libc::c_int = 1 << 20;
        let set = |opt| unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                opt,
                &size as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if set(libc::SO_RCVBUFFORCE) < 0 && set(libc::SO_RCVBUF) < 0 {
            eprintln!(
                "warning: cannot enlarge the netlink receive buffer, notifications may be lost"
            );
        }

        // A receive that waits for ever is how a hung kernel stops this
        // daemon without a word, so every read has a deadline - in the socket
        // rather than a poll before each read, which halves the syscalls of a
        // registration. The value is the longest a single read may take; a
        // caller with a shorter deadline checks the clock and comes back, one
        // with a longer one goes round again.
        let tv = libc::timeval {
            // Inferred from the field rather than named: `time_t` is 32-bit on
            // some musl targets and 64-bit on others, and naming it means
            // picking one and being deprecated on the rest.
            tv_sec: READ_TIMEOUT.as_secs() as _,
            tv_usec: 0,
        };
        let rc = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        // Zeroed and then filled in: the struct has a padding field libc does
        // not make public, so there is no literal to write, and the padding
        // has to be zero. Sound because every field of a `sockaddr_nl` is an
        // integer that can hold zero.
        // The subscription hears the whole neighbour table, mostly ARP and ND
        // churn. The userspace check in events_from drops it, but each
        // datagram still queued, still woke this process, and an ARP storm
        // could fill the receive buffer and buy a recovery pass for
        // irrelevant losses. This classic BPF filter drops the noise in the
        // kernel. Fails open: dropped is only a datagram that provably holds
        // a single RTM_NEWNEIGH/ RTM_DELNEIGH whose family is not AF_BRIDGE.
        // Attached before bind; a kernel that refuses it gets a warning and
        // the unfiltered behaviour.
        if groups != 0 {
            // The filter hard-codes little-endian storage; on a big-endian
            // host it would degrade to accept-everything anyway, so it is not
            // attached there
            // - the daemon merely wakes for noise.
            if cfg!(target_endian = "little") {
                if let Err(e) = attach_noise_filter(fd.as_raw_fd()) {
                    eprintln!("warning: cannot filter neighbour noise in the kernel: {e}");
                }
            }
        }

        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_groups = groups;
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Socket {
            fd,
            seq: 1,
            buf: Vec::new(),
            spoof_warned: std::cell::Cell::new(false),
        })
    }

    fn send(&mut self, buf: &[u8]) -> io::Result<()> {
        let n = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                0,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n as usize != buf.len() {
            return Err(io::Error::other("netlink request went out incomplete"));
        }
        Ok(())
    }

    /// Reads one datagram. `MSG_TRUNC` makes the kernel report the real size,
    /// so a too-small buffer shows up as a number larger than the buffer
    /// instead of silently missing entries.
    ///
    /// Only the kernel is listened to: a netlink socket accepts unicast from
    /// any local process, and a forged NLMSG_DONE would end a dump early - an
    /// empty dump reads as an empty table, which ends with every entry
    /// removed. Port id zero is the kernel.
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_flags(buf, 0)
    }

    /// `recv` that never blocks: an empty queue answers WouldBlock. The
    /// event drain lives on this - it takes what is queued and must not
    /// wait for more.
    fn recv_nowait(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_flags(buf, libc::MSG_DONTWAIT)
    }

    fn recv_flags(&self, buf: &mut [u8], extra: libc::c_int) -> io::Result<usize> {
        // Dropping a non-kernel datagram is the anti-spoofing rule; dropping
        // them for ever is a way to be wedged. Unicast to a netlink pid takes
        // CAP_NET_ADMIN (measured on 6.12), so the bound is defence in depth.
        // A bounded batch of drops, then WouldBlock: the deadline caller
        // re-enters and re-checks its clock, the event reader reports an
        // empty batch.
        let mut dropped = 0;
        loop {
            let mut from: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            let mut from_len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            // After a spoofed datagram was skipped the queue may be empty,
            // and blocking then would hand any local process a five-second
            // brake on the loop per datagram. Drain without waiting.
            let flags = if dropped > 0 {
                libc::MSG_TRUNC | libc::MSG_DONTWAIT | extra
            } else {
                libc::MSG_TRUNC | extra
            };
            let n = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    flags,
                    &mut from as *mut _ as *mut libc::sockaddr,
                    &mut from_len,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if from.nl_pid != 0 {
                if !self.spoof_warned.replace(true) {
                    eprintln!(
                        "warning: a local process (netlink port {}) is sending this \
                         socket unicast messages; they are dropped, said once",
                        from.nl_pid
                    );
                }
                dropped += 1;
                if dropped >= 64 {
                    return Err(io::Error::from(io::ErrorKind::WouldBlock));
                }
                continue; // not the kernel talking
            }
            return Ok(n as usize);
        }
    }

    /// `recv`, but gives up at the deadline: a reply that never comes - a
    /// lost final message, a missing acknowledgement - would otherwise stop
    /// the whole daemon.
    fn recv_deadline(&self, buf: &mut [u8], deadline: Instant) -> io::Result<usize> {
        loop {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "no answer from the kernel in time",
                ));
            }
            // The socket's own timeout does the waiting; nothing to read
            // comes back as WouldBlock, and the caller's deadline decides
            // whether that is the end.
            match self.recv(buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                other => return other,
            }
        }
    }

    /// Runs one dump and hands every message body of type `want` to `sink`.
    ///
    /// The two untrustworthy answers are told apart: a dump the kernel
    /// flagged as interrupted is asked again; one whose datagram did not fit
    /// is asked again *into a bigger buffer* - retrying into the same one
    /// gave a large host six identical failures and an error about
    /// interruptions that never happened.
    fn run_dump(
        &self,
        buf: &mut [u8],
        want: u16,
        seq: u32,
        deadline: Instant,
        sink: &mut impl FnMut(&[u8]),
    ) -> io::Result<DumpEnd> {
        loop {
            let n = self.recv_deadline(buf, deadline)?;
            if n > buf.len() {
                // MSG_TRUNC: n is what the datagram really was.
                return Ok(DumpEnd::TooBig(n));
            }
            for msg in messages(&buf[..n]) {
                // An answer to something else, or left over from a dump that
                // was abandoned half-read. Netlink asks callers to check.
                if msg.seq != seq {
                    continue;
                }
                if msg.flags & NLM_F_DUMP_INTR != 0 {
                    return Ok(DumpEnd::Interrupted);
                }
                match msg.kind {
                    // The end of a dump carries the callback's exit code,
                    // negative when the kernel gave up partway (out of
                    // memory, say). Read as finished, a short table passes
                    // for a complete one and every registration past the cut
                    // is removed. Kernels that send no body are taken at
                    // their word.
                    NLMSG_DONE => {
                        if let Some(e) = nlmsg_error(msg.payload) {
                            return Err(e);
                        }
                        return Ok(DumpEnd::Done);
                    }
                    NLMSG_ERROR => {
                        // No acknowledgement was asked for, so an error
                        // message is only ever bad news. One whose code reads
                        // zero, or too short to carry one, must not pass for
                        // a finished dump: an "empty" table would have every
                        // registration removed.
                        return Err(nlmsg_error(msg.payload).unwrap_or_else(|| {
                            io::Error::other("the dump ended in a malformed error message")
                        }));
                    }
                    NLMSG_NOOP => continue,
                    k if k == want => sink(msg.payload),
                    _ => {}
                }
            }
        }
    }

    /// One question about one interface, and its single answer: `RTM_GETLINK`
    /// without `NLM_F_DUMP` honours the index and one message comes back - no
    /// `NLMSG_DONE`, so the first matching answer ends it.
    pub(crate) fn request_one(
        &mut self,
        request: &[u8],
        want: u16,
        sink: &mut impl FnMut(&[u8]),
    ) -> io::Result<()> {
        self.request_one_from(64 * 1024, request, want, sink)
    }

    /// `request_one` with its starting buffer size spelt out; only a test
    /// passes anything but the default, so the growing path is reachable.
    ///
    /// An answer that does not fit is a big host, not an error: a VF list a
    /// few hundred long outgrows any fixed buffer, so the question is asked
    /// again into a bigger one - the dumps' grow-and-retry, same ceiling. A
    /// hard error here failed vf_macs_of and the WHOLE pass, on exactly the
    /// hosts with the most functions to exclude.
    fn request_one_from(
        &mut self,
        start: usize,
        request: &[u8],
        want: u16,
        sink: &mut impl FnMut(&[u8]),
    ) -> io::Result<()> {
        let seq = u32::from_ne_bytes(request[8..12].try_into().unwrap());
        let mut buf = self.take_buf(start);
        let out = self.request_one_grown(&mut buf, request, seq, want, sink);
        self.buf = buf;
        out
    }

    fn request_one_grown(
        &mut self,
        buf: &mut Vec<u8>,
        request: &[u8],
        seq: u32,
        want: u16,
        sink: &mut impl FnMut(&[u8]),
    ) -> io::Result<()> {
        for _ in 0..ATTEMPTS {
            self.send(request)?;
            match self.request_one_into(buf, seq, want, sink)? {
                OneEnd::Answered => return Ok(()),
                OneEnd::TooBig(need) => {
                    if need > CEILING {
                        return Err(io::Error::other(format!(
                            "an answer wants {need} bytes in one datagram, beyond \
                             the {CEILING} this is willing to allocate"
                        )));
                    }
                    // Round up, like the dumps do: the next answer to the
                    // same question need not be the same number of bytes.
                    buf.resize(need.next_power_of_two().min(CEILING), 0);
                }
            }
        }
        Err(io::Error::other(format!(
            "an answer did not fit in {ATTEMPTS} attempts of a growing buffer"
        )))
    }

    fn request_one_into(
        &mut self,
        buf: &mut [u8],
        seq: u32,
        want: u16,
        sink: &mut impl FnMut(&[u8]),
    ) -> io::Result<OneEnd> {
        let deadline = Instant::now() + READ_TIMEOUT;
        loop {
            let n = self.recv_deadline(buf, deadline)?;
            if n > buf.len() {
                // Whatever else the kernel sent for this question is still
                // queued and would be read as the answer to the next one;
                // the retry asks afresh.
                self.drain();
                return Ok(OneEnd::TooBig(n));
            }
            for msg in messages(&buf[..n]) {
                if msg.seq != seq {
                    continue;
                }
                match msg.kind {
                    NLMSG_ERROR => {
                        if let Some(e) = nlmsg_error(msg.payload) {
                            return Err(e);
                        }
                        return Ok(OneEnd::Answered);
                    }
                    // Asked without NLM_F_DUMP, so there is nothing to end -
                    // but a kernel ends it anyway for an interface that has
                    // just gone, with no RTM_NEWLINK. Ignoring it leaves the
                    // caller waiting out the five-second deadline. "Nothing
                    // to report" is the answer - unless the DONE carries a
                    // negative code, which says the question FAILED, and
                    // reading that as "empty" is how a VF list loses its
                    // exclusions.
                    NLMSG_DONE => {
                        if let Some(e) = nlmsg_error(msg.payload) {
                            return Err(e);
                        }
                        return Ok(OneEnd::Answered);
                    }
                    NLMSG_NOOP => continue,
                    k if k == want => {
                        sink(msg.payload);
                        return Ok(OneEnd::Answered);
                    }
                    _ => {}
                }
            }
        }
    }

    /// Runs a dump to completion, retrying when the kernel flags it
    /// interrupted, and returns what `parse` collected.
    ///
    /// The result belongs to this function so a retry starts from nothing;
    /// each retry sends under a fresh sequence number, so an abandoned
    /// attempt's leftovers cannot pass for the new answer. The buffer grows
    /// to whatever a datagram needs: the kernel's cap on a dump datagram is
    /// its business, not a promise, and a fixed buffer left six identical
    /// failures and an error blaming interruptions.
    pub(crate) fn dump<T>(
        &mut self,
        request: &[u8],
        want: u16,
        what: &str,
        parse: impl FnMut(&[u8], &mut Vec<T>),
    ) -> io::Result<Vec<T>> {
        // One kernel dump datagram, near enough. Starting larger cost an
        // allocation and a walk over a quarter megabyte to zero it every time
        // the buffer was fresh; whatever a host really needs, the buffer
        // reaches on its first dump and keeps.
        self.dump_from(64 * 1024, request, want, what, parse)
    }

    /// `dump`, with the size it starts from spelt out. Only a test passes
    /// anything but the default: growing is meant to be the rare path, and a
    /// test that cannot reach it does not test it.
    fn dump_from<T>(
        &mut self,
        start: usize,
        request: &[u8],
        want: u16,
        what: &str,
        parse: impl FnMut(&[u8], &mut Vec<T>),
    ) -> io::Result<Vec<T>> {
        let mut buf = self.take_buf(start);
        let out = self.dump_into(&mut buf, request, want, what, parse);
        self.buf = buf;
        out
    }

    fn dump_into<T>(
        &mut self,
        buf: &mut Vec<u8>,
        request: &[u8],
        want: u16,
        what: &str,
        mut parse: impl FnMut(&[u8], &mut Vec<T>),
    ) -> io::Result<Vec<T>> {
        let mut req = request.to_vec();
        let mut out = Vec::new();
        for _ in 0..ATTEMPTS {
            out.clear();
            self.seq = self.seq.wrapping_add(1);
            req[8..12].copy_from_slice(&self.seq.to_ne_bytes());
            self.send(&req)?;
            let deadline = Instant::now() + READ_TIMEOUT;
            match self.run_dump(buf, want, self.seq, deadline, &mut |payload| {
                parse(payload, &mut out)
            }) {
                Ok(DumpEnd::Done) => return Ok(out),
                Ok(DumpEnd::Interrupted) => self.drain(),
                Ok(DumpEnd::TooBig(need)) => {
                    self.drain();
                    if need > CEILING {
                        return Err(io::Error::other(format!(
                            "{what} dump wants {need} bytes in one datagram, \
                             beyond the {CEILING} this is willing to allocate"
                        )));
                    }
                    // Round up rather than take the exact size: the table is
                    // read because it moves, and the next attempt will not be
                    // answered with the same number of bytes.
                    buf.resize(need.next_power_of_two().min(CEILING), 0);
                }
                Err(e) => {
                    self.drain();
                    return Err(e);
                }
            }
        }
        Err(io::Error::other(format!(
            "{what} dump did not come back whole in {ATTEMPTS} attempts \
             (buffer now {} bytes)",
            buf.len()
        )))
    }

    /// Throws away whatever is still queued from an abandoned request. A
    /// signal must not end the draining early: what stays queued would be
    /// read as the next answer - a sequence number cannot tell them apart
    /// when a retry reuses it.
    fn drain(&self) {
        let mut buf = [0u8; 4096];
        loop {
            let n = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                )
            };
            if n < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return; // EAGAIN: the queue is empty
            }
            // A zero-length datagram is still a datagram; only an error
            // ends the queue. Treating it as the end left the rest of an
            // abandoned dump queued, and the next request answered EBUSY.
        }
    }

    /// Every interface on the host, in one dump.
    ///
    /// Without RTEXT_FILTER_VF: asking for VF details makes the driver answer
    /// out of firmware for every interface that has any (measured 1.35 ms per
    /// PF). The count comes from sysfs - without the flag the kernel sends no
    /// IFLA_NUM_VF - and the addresses are asked separately for the few
    /// interfaces that matter.
    pub fn dump_links(&mut self) -> io::Result<Vec<LinkInfo>> {
        let req = link_dump_request();
        self.dump(&req, RTM_NEWLINK, "link", |payload, out| {
            if let Some(l) = parse_link(payload) {
                out.push(l);
            }
        })
    }

    /// Every forwarding database entry on the host, learnt and configured.
    pub fn dump_fdb(&mut self) -> io::Result<Vec<FdbEntry>> {
        let mut req = Vec::with_capacity(NLMSG_HDR + NDMSG_LEN);
        put_nlmsghdr(
            &mut req,
            (NLMSG_HDR + NDMSG_LEN) as u32,
            RTM_GETNEIGH,
            NLM_F_REQUEST | NLM_F_DUMP,
            0, // dump() assigns a fresh sequence number per attempt
        );
        req.push(libc::AF_BRIDGE as u8); // ndm_family
        req.push(0); // pad1
        req.extend_from_slice(&0u16.to_ne_bytes()); // pad2
        req.extend_from_slice(&0i32.to_ne_bytes()); // ifindex
        req.extend_from_slice(&0u16.to_ne_bytes()); // state
        req.push(0); // flags
        req.push(0); // type

        self.dump(&req, RTM_NEWNEIGH, "forwarding database", |payload, out| {
            if let Some(e) = parse_fdb(payload) {
                out.push(e);
            }
        })
    }

    /// The forwarding entries attached to one interface: for a bridge port,
    /// the bridge's entries learnt on it and the interface's own `self` list.
    pub fn dump_fdb_of(&mut self, ifindex: u32) -> io::Result<Vec<FdbEntry>> {
        let req = fdb_of_request(ifindex);
        self.dump(&req, RTM_NEWNEIGH, "forwarding database", |payload, out| {
            if let Some(e) = parse_fdb(payload) {
                out.push(e);
            }
        })
    }

    /// The addresses administratively set on the VFs of the named interfaces.
    ///
    /// Asked by index, one question each: the dump this replaced had the
    /// kernel describe every interface to reach the few with VFs, and
    /// serialisation dominated. A gone interface answers ENODEV, which is no
    /// failure: it has no VFs to exclude.
    pub fn vf_macs_of(&mut self, indices: &[u32]) -> io::Result<Vec<(u32, [u8; 6])>> {
        let mut out = Vec::new();
        for &index in indices {
            self.seq = self.seq.wrapping_add(1);
            let req = vf_request(index, self.seq);

            match self.request_one(&req, RTM_NEWLINK, &mut |payload| {
                collect_vf_macs(payload, &mut out)
            }) {
                Ok(()) => {}
                Err(e) if e.raw_os_error() == Some(libc::ENODEV) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// Add or remove an address in an interface's own unicast filter list -
    /// the `bridge fdb ... self permanent` of iproute2.
    pub fn set_self_fdb(&mut self, ifindex: u32, mac: &[u8; 6], add: bool) -> io::Result<()> {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        let len = NLMSG_HDR + NDMSG_LEN + RTATTR_HDR + 6 + 2; // lladdr is padded to 8
        let mut req = Vec::with_capacity(len);
        let (kind, flags) = if add {
            (
                RTM_NEWNEIGH,
                NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            )
        } else {
            (RTM_DELNEIGH, NLM_F_REQUEST | NLM_F_ACK)
        };
        put_nlmsghdr(&mut req, len as u32, kind, flags, seq);
        req.push(libc::AF_BRIDGE as u8);
        req.push(0);
        req.extend_from_slice(&0u16.to_ne_bytes());
        req.extend_from_slice(&(ifindex as i32).to_ne_bytes());
        req.extend_from_slice(&NUD_PERMANENT.to_ne_bytes());
        req.push(NTF_SELF);
        req.push(0);
        put_attr(&mut req, NDA_LLADDR, mac);
        self.send(&req)?;

        // An acknowledgement was asked for, so one message with this sequence
        // number is coming. Reading one datagram and hoping is not the same:
        // a stray message from an earlier error path would be read instead,
        // and every call after would judge itself by its predecessor's
        // answer.
        let mut buf = [0u8; 8192];
        let deadline = Instant::now() + READ_TIMEOUT;
        loop {
            let n = self.recv_deadline(&mut buf, deadline)?.min(buf.len());
            for msg in messages(&buf[..n]) {
                if msg.seq != seq {
                    continue;
                }
                if msg.kind == NLMSG_ERROR {
                    // Too short to carry a code is not an acknowledgement:
                    // booking a registration that never happened as done
                    // leaves the guest's traffic falling off the uplink until
                    // the next pass.
                    if msg.payload.len() < 4 {
                        return Err(io::Error::other(
                            "a malformed acknowledgement, too short to carry a code",
                        ));
                    }
                    return match nlmsg_error(msg.payload) {
                        Some(e) => Err(e),
                        None => Ok(()), // the acknowledgement: an error of code zero
                    };
                }
            }
        }
    }

    /// What arrived on the subscription since the last look.
    pub fn recv_events(&mut self) -> io::Result<Events> {
        let mut buf = self.take_buf(64 * 1024);
        let out = self.events_from(&mut buf);
        self.buf = buf;
        out
    }

    /// One wake takes the whole queue. The kernel hands notifications over
    /// one datagram at a time, so a burst of N learns was N batches, each
    /// paying its own driver question and topology re-read. What is queued is
    /// the same moment; taking it all waits for nothing. Capped so a firehose
    /// cannot starve the loop's clock checks.
    const DRAIN_CAP: usize = 256;

    fn events_from(&self, buf: &mut [u8]) -> io::Result<Events> {
        let mut out = Events::default();
        for _ in 0..Self::DRAIN_CAP {
            // A notification that did not fit is a loss like ENOBUFS:
            // unknowable content, so the caller stops trusting what it holds
            // and reads the real state.
            let n = match self.recv_nowait(buf) {
                Ok(n) => n,
                // The queue is empty - on the first round because the caller
                // polls before asking, later because the drain is done.
                // Neither is a loss.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            };
            if n > buf.len() {
                return Err(io::Error::other("a notification batch outgrew the buffer"));
            }
            Self::collect_events(&mut out, &buf[..n]);
        }
        Ok(out)
    }

    fn collect_events(out: &mut Events, datagram: &[u8]) {
        for msg in messages(datagram) {
            if msg.kind == RTM_NEWLINK || msg.kind == RTM_DELLINK {
                out.links_changed = true;
                if msg.payload.len() >= IFINFOMSG_LEN {
                    if let Ok(bytes) = msg.payload[4..8].try_into() {
                        let index = i32::from_ne_bytes(bytes);
                        if index > 0 {
                            out.changed_links.push(index as u32);
                        }
                    }
                }
                continue;
            }
            if msg.kind != RTM_NEWNEIGH && msg.kind != RTM_DELNEIGH {
                continue;
            }
            // RTNLGRP_NEIGH carries the whole neighbour table; only AF_BRIDGE
            // concerns us. The kernel-side filter drops most of the ARP/ND
            // churn first - this is the backstop, and the whole check on
            // kernels that refused the filter.
            if msg.payload.first() != Some(&(libc::AF_BRIDGE as u8)) {
                continue;
            }
            if let Some(e) = parse_fdb(msg.payload) {
                out.fdb.push((msg.kind, e));
            }
        }
    }

    /// The subscription's descriptor, for a caller that polls it together
    /// with something of its own (the daemon adds its stop pipe).
    pub fn raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    /// Wait for a notification, giving up after `millis` - or never, for a
    /// negative number. False on timeout.
    pub fn wait(&self, millis: i32) -> io::Result<bool> {
        let mut pfd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // A signal returns "nothing arrived" rather than polling again: every
        // caller loops against its own deadline and comes straight back, and
        // gets to look at why it was interrupted. A stop that waits out an
        // interval is not a stop.
        let rc = unsafe { libc::poll(&mut pfd, 1, millis.max(-1)) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(e);
        }
        Ok(rc > 0)
    }
}

/// The request that asks one interface about its VFs, its own function so a
/// test can look at what goes out. Without RTEXT_FILTER_SKIP_STATS the kernel
/// also collects each VF's traffic counters out of the hardware: on a
/// ConnectX-4 with two functions of two VFs that was two thirds of the call
/// (2.17 ms against 0.73) for numbers nothing reads.
/// The request behind `dump_links`: every interface, without statistics.
/// Without RTEXT_FILTER_SKIP_STATS the kernel calls every driver's
/// `ndo_get_stats64` and serialises ~200 bytes of counters per link that
/// nothing here reads - measured on pve1 as a quarter of the whole
/// topology read (0.535 -> 0.398 ms cold).
fn link_dump_request() -> Vec<u8> {
    let len = NLMSG_HDR + IFINFOMSG_LEN + RTATTR_HDR + 4;
    let mut req = Vec::with_capacity(len);
    put_nlmsghdr(
        &mut req,
        len as u32,
        RTM_GETLINK,
        NLM_F_REQUEST | NLM_F_DUMP,
        0, // dump() assigns a fresh sequence number per attempt
    );
    req.push(libc::AF_UNSPEC as u8);
    req.push(0);
    req.extend_from_slice(&0u16.to_ne_bytes()); // ifi_type
    req.extend_from_slice(&0i32.to_ne_bytes()); // ifi_index: all of them
    req.extend_from_slice(&0u32.to_ne_bytes()); // ifi_flags
    req.extend_from_slice(&0u32.to_ne_bytes()); // ifi_change
    put_attr_u32(&mut req, IFLA_EXT_MASK, RTEXT_FILTER_SKIP_STATS);
    req
}

/// The request behind `dump_fdb_of`. Shaped as an `ifinfomsg`, not an
/// `ndmsg`: the kernel reads the interface filter only from that shape
/// (`valid_fdb_dump_legacy`) and takes an `ndmsg`-sized request as "every
/// interface" whatever its index says - the shape `bridge fdb show dev X`
/// sends.
fn fdb_of_request(ifindex: u32) -> Vec<u8> {
    let len = NLMSG_HDR + IFINFOMSG_LEN;
    let mut req = Vec::with_capacity(len);
    put_nlmsghdr(
        &mut req,
        len as u32,
        RTM_GETNEIGH,
        NLM_F_REQUEST | NLM_F_DUMP,
        0, // dump() assigns a fresh sequence number per attempt
    );
    req.push(libc::AF_BRIDGE as u8); // ifi_family
    req.push(0);
    req.extend_from_slice(&0u16.to_ne_bytes()); // ifi_type
    req.extend_from_slice(&(ifindex as i32).to_ne_bytes());
    req.extend_from_slice(&0u32.to_ne_bytes()); // ifi_flags
    req.extend_from_slice(&0u32.to_ne_bytes()); // ifi_change
    req
}

fn vf_request(index: u32, seq: u32) -> Vec<u8> {
    let len = NLMSG_HDR + IFINFOMSG_LEN + RTATTR_HDR + 4;
    let mut req = Vec::with_capacity(len);
    put_nlmsghdr(&mut req, len as u32, RTM_GETLINK, NLM_F_REQUEST, seq);
    req.push(libc::AF_UNSPEC as u8);
    req.push(0);
    req.extend_from_slice(&0u16.to_ne_bytes()); // ifi_type
    req.extend_from_slice(&(index as i32).to_ne_bytes());
    req.extend_from_slice(&0u32.to_ne_bytes()); // ifi_flags
    req.extend_from_slice(&0u32.to_ne_bytes()); // ifi_change
    put_attr_u32(
        &mut req,
        IFLA_EXT_MASK,
        RTEXT_FILTER_VF | RTEXT_FILTER_SKIP_STATS,
    );
    req
}

pub(crate) fn put_nlmsghdr(buf: &mut Vec<u8>, len: u32, kind: u16, flags: u16, seq: u32) {
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(&flags.to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes()); // pid: let the kernel fill it in
}

pub(crate) fn put_attr(buf: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let len = RTATTR_HDR + value.len();
    // A netlink attribute's length is 16 bits. Nothing here comes near it
    // (six-byte addresses), but a truncated length would be a silently
    // malformed message rather than a refusal.
    assert!(
        len <= u16::MAX as usize,
        "netlink attribute of {len} bytes cannot state its own length"
    );
    buf.extend_from_slice(&(len as u16).to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(value);
    buf.resize(buf.len() + align4(len) - len, 0);
}

fn put_attr_u32(buf: &mut Vec<u8>, kind: u16, value: u32) {
    put_attr(buf, kind, &value.to_ne_bytes());
}

struct Message<'a> {
    pub kind: u16,
    pub flags: u16,
    pub seq: u32,
    pub payload: &'a [u8],
}

/// One RTM_NEWLINK body. Everything the topology needs except the SR-IOV
/// relations, which the kernel does not describe here.
fn parse_link(payload: &[u8]) -> Option<LinkInfo> {
    if payload.len() < IFINFOMSG_LEN {
        return None;
    }
    let index = i32::from_ne_bytes(payload[4..8].try_into().ok()?);
    if index <= 0 {
        return None;
    }
    let mut out = LinkInfo {
        index: index as u32,
        ..Default::default()
    };
    let mut foreign_parent = false;
    for (kind, value) in attrs(&payload[IFINFOMSG_LEN..]) {
        match kind {
            IFLA_IFNAME => {
                let end = value.iter().position(|b| *b == 0).unwrap_or(value.len());
                out.name = String::from_utf8_lossy(&value[..end]).into_owned();
            }
            // The length guard is the whole check. Written with `?` it could
            // abandon the WHOLE interface over one attribute - and an
            // interface that falls out of the reading takes its PF and the
            // exclusion set with it, the worst direction this program has. So
            // a bad attribute costs that attribute, as with the ageing time
            // next door.
            IFLA_ADDRESS if value.len() == 6 => {
                let mut m = [0u8; 6];
                m.copy_from_slice(&value[..6]);
                out.mac = Some(m);
            }
            IFLA_MASTER if value.len() >= 4 => {
                out.master = Some(u32::from_ne_bytes([value[0], value[1], value[2], value[3]]));
            }
            IFLA_LINK if value.len() >= 4 => {
                let i = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
                if i != 0 {
                    out.link = Some(i);
                }
            }
            // The parent lives in another namespace, and IFLA_LINK is then
            // an index THERE: believing it here would draw a lower edge to
            // whatever local interface happens to wear that number.
            IFLA_LINK_NETNSID => {
                foreign_parent = true;
            }
            IFLA_PARENT_DEV_NAME => {
                let end = value.iter().position(|b| *b == 0).unwrap_or(value.len());
                out.parent_dev = Some(String::from_utf8_lossy(&value[..end]).into_owned());
            }
            IFLA_LINKINFO => {
                for (nested, v) in attrs(value) {
                    match nested {
                        IFLA_INFO_KIND => {
                            let end = v.iter().position(|b| *b == 0).unwrap_or(v.len());
                            out.kind = Some(String::from_utf8_lossy(&v[..end]).into_owned());
                        }
                        IFLA_INFO_DATA => {
                            for (inner, iv) in attrs(v) {
                                if inner == IFLA_BR_AGEING_TIME && iv.len() >= 4 {
                                    out.ageing =
                                        Some(u32::from_ne_bytes([iv[0], iv[1], iv[2], iv[3]]));
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    if foreign_parent {
        out.link = None;
    }
    if out.name.is_empty() {
        return None;
    }
    Some(out)
}

/// Walks the netlink messages in a buffer. A trailing fragment is dropped,
/// not parsed, so a short read cannot turn into nonsense. An iterator: a
/// large dump arrives as thousands of messages per datagram and none needs
/// keeping.
struct Messages<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Iterator for Messages<'a> {
    type Item = Message<'a>;
    fn next(&mut self) -> Option<Message<'a>> {
        if self.off + NLMSG_HDR > self.buf.len() {
            return None;
        }
        let len = u32::from_ne_bytes(self.buf[self.off..self.off + 4].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(self.buf[self.off + 4..self.off + 6].try_into().unwrap());
        let flags = u16::from_ne_bytes(self.buf[self.off + 6..self.off + 8].try_into().unwrap());
        let seq = u32::from_ne_bytes(self.buf[self.off + 8..self.off + 12].try_into().unwrap());
        // checked_add, because len is four wire bytes at face value: on a
        // 32-bit usize the sum can wrap, slip past this check and panic on
        // the slice below.
        let end = self.off.checked_add(len)?;
        if len < NLMSG_HDR || end > self.buf.len() {
            return None;
        }
        let payload = &self.buf[self.off + NLMSG_HDR..end];
        self.off += align4(len);
        Some(Message {
            kind,
            flags,
            seq,
            payload,
        })
    }
}

fn messages(buf: &[u8]) -> Messages<'_> {
    Messages { buf, off: 0 }
}

/// The status code at the front of an NLMSG_ERROR or NLMSG_DONE payload, as
/// an error when it is one. The kernel writes 0 or -errno; anything positive
/// is a spoof or a bug, refused with the same errno - and `saturating_abs`
/// keeps i32::MIN from panicking a debug build. One arithmetic for every
/// reader.
fn nlmsg_error(payload: &[u8]) -> Option<io::Error> {
    if payload.len() < 4 {
        return None;
    }
    let code = i32::from_ne_bytes(payload[0..4].try_into().unwrap());
    if code == 0 {
        None // an acknowledgement, not a failure
    } else {
        Some(io::Error::from_raw_os_error(code.saturating_abs()))
    }
}

/// Walks the attributes of a message body, without collecting them: this runs
/// once per forwarding entry, and there can be thousands.
pub(crate) struct Attrs<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Iterator for Attrs<'a> {
    type Item = (u16, &'a [u8]);
    fn next(&mut self) -> Option<(u16, &'a [u8])> {
        if self.off + RTATTR_HDR > self.buf.len() {
            return None;
        }
        let len = u16::from_ne_bytes(self.buf[self.off..self.off + 2].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(self.buf[self.off + 2..self.off + 4].try_into().unwrap());
        if len < RTATTR_HDR || self.off + len > self.buf.len() {
            return None;
        }
        let value = &self.buf[self.off + RTATTR_HDR..self.off + len];
        self.off += align4(len);
        // The top two bits are NLA_F_NESTED and NLA_F_NET_BYTEORDER, not
        // type. Today's kernels emit these attributes flag-free, but a kernel
        // that stamps NLA_F_NESTED on IFLA_VFINFO_LIST would otherwise return
        // an empty VF list - an exclusion set missing the sister VFs, the
        // worst failure direction this program has.
        Some((kind & 0x3fff, value))
    }
}

pub(crate) fn attrs(buf: &[u8]) -> Attrs<'_> {
    Attrs { buf, off: 0 }
}

fn parse_fdb(payload: &[u8]) -> Option<FdbEntry> {
    if payload.len() < NDMSG_LEN {
        return None;
    }
    // The kernel's index is signed and positive; anything else is not an
    // interface this could ever act on - the same rejection parse_link makes.
    let index = i32::from_ne_bytes(payload[4..8].try_into().unwrap());
    if index <= 0 {
        return None;
    }
    let ifindex = index as u32;
    let state = u16::from_ne_bytes(payload[8..10].try_into().unwrap());
    let flags = payload[10];
    let mut mac = None;
    let mut master = None;
    for (kind, value) in attrs(&payload[NDMSG_LEN..]) {
        match kind {
            NDA_LLADDR if value.len() == 6 => {
                let mut m = [0u8; 6];
                m.copy_from_slice(value);
                mac = Some(m);
            }
            NDA_MASTER if value.len() == 4 => {
                master = Some(u32::from_ne_bytes(value.try_into().unwrap()));
            }
            _ => {}
        }
    }
    Some(FdbEntry {
        ifindex,
        master,
        mac: mac?,
        state,
        flags,
    })
}

/// Known limit: rtattr lengths are u16 on the wire. A VFINFO list beyond 64
/// KiB (roughly three hundred VFs on one PF) arrives with its length wrapped
/// by the kernel, and no parser can tell. Such hosts need the kernel's own
/// fix; no driver family this has run on hands out that many per PF.
fn collect_vf_macs(payload: &[u8], out: &mut Vec<(u32, [u8; 6])>) {
    if payload.len() < IFINFOMSG_LEN {
        return;
    }
    let index = i32::from_ne_bytes(payload[4..8].try_into().unwrap());
    if index <= 0 {
        return;
    }
    let ifindex = index as u32;
    for (kind, value) in attrs(&payload[IFINFOMSG_LEN..]) {
        if kind != IFLA_VFINFO_LIST {
            continue;
        }
        for (vf_kind, vf_info) in attrs(value) {
            if vf_kind != IFLA_VF_INFO {
                continue;
            }
            for (mac_kind, mac_value) in attrs(vf_info) {
                // struct ifla_vf_mac { __u32 vf; __u8 mac[32]; }: number
                // first, then the address, of which six bytes carry meaning.
                // Shorter than number-plus-six cannot be that struct.
                const VF_MAC_OFF: usize = 4;
                const VF_MAC_LEN: usize = 6;
                if mac_kind == IFLA_VF_MAC && mac_value.len() >= VF_MAC_OFF + VF_MAC_LEN {
                    let mut m = [0u8; 6];
                    m.copy_from_slice(&mac_value[VF_MAC_OFF..VF_MAC_OFF + VF_MAC_LEN]);
                    out.push((ifindex, m));
                }
            }
        }
    }
}

pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut n = 0;
    for part in s.split(':') {
        // from_str_radix takes a leading sign, so "+f" reads as 15 - checking
        // the characters is the only way to accept exactly two hex digits.
        if n == 6 || part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        out[n] = u8::from_str_radix(part, 16).ok()?;
        n += 1;
    }
    if n == 6 {
        Some(out)
    } else {
        None
    }
}

/// The kernel-side noise filter for the subscription socket: classic BPF, 25
/// instructions, no dependency. Reads the header byte-wise because cBPF loads
/// are big-endian and the header is host-order.
///
/// In order: a message over 64 KiB is accepted unseen; a datagram with room
/// for a second header behind align4(nlmsg_len) is accepted (multi-message);
/// a type other than RTM_NEWNEIGH/RTM_DELNEIGH is accepted; only then, the
/// datagram proven a single neighbour message, is ndm_family compared against
/// AF_BRIDGE - the one case dropped. Verified in a netns: all bridge events
/// delivered, all ARP/ND noise gone.
fn attach_noise_filter(fd: std::os::fd::RawFd) -> io::Result<()> {
    const fn stmt(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }
    const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }
    // Spelt out because libc exports the structs but not the opcodes.
    const LD_B_ABS: u16 = 0x30; // BPF_LD  | BPF_B | BPF_ABS
    const LD_W_LEN: u16 = 0x80; // BPF_LD  | BPF_W | BPF_LEN
    const JEQ_K: u16 = 0x15; //    BPF_JMP | BPF_JEQ | BPF_K
    const JGE_K: u16 = 0x35; //    BPF_JMP | BPF_JGE | BPF_K
    const LSH_K: u16 = 0x64; //    BPF_ALU | BPF_LSH | BPF_K
    const OR_X: u16 = 0x4c; //     BPF_ALU | BPF_OR  | BPF_X
    const ADD_K: u16 = 0x04; //    BPF_ALU | BPF_ADD | BPF_K
    const AND_K: u16 = 0x54; //    BPF_ALU | BPF_AND | BPF_K
    const SUB_X: u16 = 0x1c; //    BPF_ALU | BPF_SUB | BPF_X
    const TAX: u16 = 0x07; //      BPF_MISC | BPF_TAX
    const RET_K: u16 = 0x06; //    BPF_RET | BPF_K
    const ACCEPT: u32 = u32::MAX;
    let prog = [
        stmt(LD_B_ABS, 2),     //          nlmsg_len, third byte
        jump(JEQ_K, 0, 0, 18), //      != 0: >= 64 KiB, accept
        stmt(LD_B_ABS, 3),     //          nlmsg_len, fourth byte
        jump(JEQ_K, 0, 0, 16), //      != 0: accept
        stmt(LD_B_ABS, 1),     //          nlmsg_len, reconstructed from bytes
        stmt(LSH_K, 8),        //             (byte-wise, hard-coding the host's
        stmt(TAX, 0),          //               little-endian layout - see attach)
        stmt(LD_B_ABS, 0),
        stmt(OR_X, 0), //              A = nlmsg_len
        stmt(ADD_K, 3),
        stmt(AND_K, !3u32), //         A = align4(nlmsg_len)
        stmt(TAX, 0),
        stmt(LD_W_LEN, 0),     //          A = datagram length
        stmt(SUB_X, 0),        //             A = room behind the first message
        jump(JGE_K, 16, 5, 0), //      a second header fits: accept
        stmt(LD_B_ABS, 5),     //          nlmsg_type, high byte
        jump(JEQ_K, 0, 0, 3),  //       >= 256: accept
        stmt(LD_B_ABS, 4),     //          nlmsg_type, low byte
        jump(JEQ_K, RTM_NEWNEIGH as u32, 2, 0),
        jump(JEQ_K, RTM_DELNEIGH as u32, 1, 0),
        stmt(RET_K, ACCEPT), //        everything not proven single-neigh
        stmt(LD_B_ABS, 16),  //         ndm_family
        jump(JEQ_K, libc::AF_BRIDGE as u32, 0, 1),
        stmt(RET_K, ACCEPT), //        the bridge talking: deliver
        stmt(RET_K, 0),      //             ARP/ND churn: drop in the kernel
    ];
    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr() as *mut libc::sock_filter,
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &fprog as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    /// One datagram off a raw fd - the FFI call four of these tests make,
    /// spelled once. What each does with a short or absent answer differs,
    /// so the count comes back raw and the guard stays at the call site.
    fn recv_raw(fd: i32, buf: &mut [u8]) -> isize {
        unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) }
    }
    use super::*;

    /// A netlink socket whose kernel is a thread in this test: a socketpair,
    /// whose other end sends back with a zeroed sender address - port id
    /// zero, "the kernel". The only way to reach paths only a particular
    /// kernel behaviour produces: a dump that does not fit, a question
    /// answered with nothing.
    fn kernel_pair() -> (Socket, std::os::fd::OwnedFd) {
        use std::os::fd::FromRawFd;
        let mut fds = [0 as libc::c_int; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "socketpair: {}", io::Error::last_os_error());
        let ours = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[0]) };
        let theirs = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[1]) };
        // Both ends give up waiting: the kernel side after half a second,
        // because a datagram socketpair does not tell it when our end closes;
        // our side the way a real netlink socket does, so the code under test
        // meets the same WouldBlock.
        let timeout = |fd: &std::os::fd::OwnedFd, usec| {
            let tv = libc::timeval {
                tv_sec: 0,
                tv_usec: usec,
            };
            let rc = unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    &tv as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                )
            };
            assert_eq!(rc, 0, "setsockopt: {}", io::Error::last_os_error());
        };
        timeout(&theirs, 500_000);
        timeout(&ours, 100_000);
        (
            Socket {
                fd: ours,
                seq: 1,
                buf: Vec::new(),
                spoof_warned: std::cell::Cell::new(false),
            },
            theirs,
        )
    }

    fn send_raw(fd: &std::os::fd::OwnedFd, bytes: &[u8]) {
        let n = unsafe {
            libc::send(
                fd.as_raw_fd(),
                bytes.as_ptr() as *const libc::c_void,
                bytes.len(),
                0,
            )
        };
        assert_eq!(n, bytes.len() as isize, "{}", io::Error::last_os_error());
    }

    /// Like `msg`, but with a sequence number: everything that answers a
    /// request has to carry the one the request went out with, or the code
    /// under test rightly ignores it.
    fn msg_seq(kind: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut v = msg(kind, 0, payload);
        v[8..12].copy_from_slice(&seq.to_ne_bytes());
        v
    }

    fn msg(kind: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
        let len = NLMSG_HDR + payload.len();
        let mut v = Vec::with_capacity(align4(len));
        v.extend_from_slice(&(len as u32).to_ne_bytes());
        v.extend_from_slice(&kind.to_ne_bytes());
        v.extend_from_slice(&flags.to_ne_bytes());
        v.extend_from_slice(&0u32.to_ne_bytes()); // seq
        v.extend_from_slice(&0u32.to_ne_bytes()); // pid
        v.extend_from_slice(payload);
        v.resize(align4(len), 0);
        v
    }

    fn ndmsg(
        ifindex: u32,
        state: u16,
        flags: u8,
        mac: Option<[u8; 6]>,
        master: Option<u32>,
    ) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(libc::AF_BRIDGE as u8);
        v.push(0);
        v.extend_from_slice(&0u16.to_ne_bytes());
        v.extend_from_slice(&(ifindex as i32).to_ne_bytes());
        v.extend_from_slice(&state.to_ne_bytes());
        v.push(flags);
        v.push(0);
        if let Some(m) = mac {
            put_attr(&mut v, NDA_LLADDR, &m);
        }
        if let Some(m) = master {
            put_attr_u32(&mut v, NDA_MASTER, m);
        }
        v
    }

    #[test]
    fn messages_walks_a_batch() {
        let mut buf = msg(RTM_NEWNEIGH, 0, b"one");
        buf.extend(msg(RTM_DELNEIGH, 0, b"twotwo"));
        let got: Vec<_> = messages(&buf).collect();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].kind, RTM_NEWNEIGH);
        assert_eq!(&got[0].payload[..3], b"one");
        assert_eq!(got[1].kind, RTM_DELNEIGH);
        assert_eq!(&got[1].payload[..6], b"twotwo");
    }

    /// A datagram that did not fit must lose its last message rather than
    /// hand back a half-parsed one.
    #[test]
    fn a_truncated_tail_is_dropped_not_parsed() {
        let mut buf = msg(RTM_NEWNEIGH, 0, b"complete");
        buf.extend(msg(RTM_NEWNEIGH, 0, b"cut short here"));
        buf.truncate(buf.len() - 6);
        let got: Vec<_> = messages(&buf).collect();
        assert_eq!(got.len(), 1, "only the message that arrived whole");
        assert_eq!(&got[0].payload[..8], b"complete");
    }

    #[test]
    fn a_header_that_claims_less_than_a_header_stops_the_walk() {
        let mut buf = msg(RTM_NEWNEIGH, 0, b"ok");
        buf.extend_from_slice(&4u32.to_ne_bytes()); // len = 4, impossible
        buf.extend_from_slice(&[0u8; 12]);
        assert_eq!(messages(&buf).count(), 1);
    }

    #[test]
    fn the_interrupted_dump_flag_survives_parsing() {
        let buf = msg(RTM_NEWNEIGH, NLM_F_DUMP_INTR, b"x");
        assert_ne!(messages(&buf).next().unwrap().flags & NLM_F_DUMP_INTR, 0);
    }

    #[test]
    fn errors_and_acknowledgements_are_told_apart() {
        assert!(nlmsg_error(&0i32.to_ne_bytes()).is_none(), "0 is an ack");
        let e = nlmsg_error(&(-libc::EEXIST).to_ne_bytes()).expect("an error");
        assert_eq!(e.raw_os_error(), Some(libc::EEXIST));
    }

    #[test]
    fn fdb_entries_are_classified() {
        let learnt = FdbEntry {
            ifindex: 1,
            master: Some(2),
            mac: [0, 1, 2, 3, 4, 5],
            state: 0x02,
            flags: 0,
        };
        assert!(learnt.is_learned() && !learnt.is_self() && learnt.is_unicast());

        let own = FdbEntry {
            state: NUD_PERMANENT,
            ..learnt.clone()
        };
        assert!(
            !own.is_learned(),
            "a port's own address is configured, not learnt"
        );

        let filter = FdbEntry {
            flags: NTF_SELF,
            state: NUD_PERMANENT,
            ..learnt.clone()
        };
        assert!(filter.is_self() && !filter.is_learned());

        let external = FdbEntry {
            state: NUD_NOARP,
            flags: NTF_EXT_LEARNED,
            ..learnt.clone()
        };
        assert!(
            external.is_learned(),
            "planted by an agent, but still says where a peer is"
        );

        let mcast = FdbEntry {
            mac: [0x01, 0, 0x5e, 0, 0, 1],
            ..learnt.clone()
        };
        assert!(!mcast.is_unicast());
    }

    #[test]
    fn parse_fdb_reads_address_and_bridge() {
        let body = ndmsg(7, 0x02, 0, Some([0xde, 0xad, 0xbe, 0xef, 0, 1]), Some(9));
        let e = parse_fdb(&body).expect("parsed");
        assert_eq!(e.ifindex, 7);
        assert_eq!(e.master, Some(9));
        assert_eq!(e.mac, [0xde, 0xad, 0xbe, 0xef, 0, 1]);
    }

    #[test]
    fn an_entry_without_an_address_is_no_entry() {
        assert!(parse_fdb(&ndmsg(7, 0x02, 0, None, Some(9))).is_none());
        assert!(parse_fdb(&[0u8; 4]).is_none(), "too short to be an ndmsg");
    }

    #[test]
    fn mac_round_trip() {
        let m = [0x02, 0x00, 0x5e, 0x10, 0x00, 0x01];
        assert_eq!(format_mac(&m), "02:00:5e:10:00:01");
        assert_eq!(parse_mac("02:00:5e:10:00:01"), Some(m));
        assert_eq!(
            parse_mac("02:00:5E:10:00:01"),
            Some(m),
            "case does not matter"
        );
    }

    #[test]
    fn a_sign_is_not_a_hex_digit() {
        // from_str_radix accepts "+f" as 15; the parser must not.
        assert_eq!(parse_mac("+1:+2:+3:+4:+5:+6"), None);
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:+f"), None);
    }

    #[test]
    fn malformed_addresses_are_rejected() {
        for bad in [
            "",
            "02:00:5e:10:00",
            "02:00:5e:10:00:01:99",
            "zz:00:5e:10:00:01",
            "2:00:5e:10:00:01",
        ] {
            assert_eq!(parse_mac(bad), None, "{bad} should not parse");
        }
    }

    #[test]
    fn attributes_are_padded_to_four_bytes() {
        let mut v = Vec::new();
        put_attr(&mut v, NDA_LLADDR, &[1, 2, 3, 4, 5, 6]);
        assert_eq!(v.len(), 12, "4 header + 6 payload, padded to 12");
        let got: Vec<_> = attrs(&v).collect();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, NDA_LLADDR);
        assert_eq!(got[0].1, &[1, 2, 3, 4, 5, 6]);
    }

    /// A 16-byte ifinfomsg body: family, type, index, flags - only the
    /// index matters to the parser.
    fn ifinfomsg(index: i32) -> Vec<u8> {
        let mut v = vec![0u8; IFINFOMSG_LEN];
        v[4..8].copy_from_slice(&index.to_ne_bytes());
        v
    }

    /// parse_link had no test at all: the attribute walk, the nested
    /// LINKINFO kind, the NUL the kernel puts on names, and the rejections
    /// were all unasserted. These are the decoder's whole contract.
    #[test]
    fn parse_link_reads_what_the_topology_is_built_from() {
        let mut body = ifinfomsg(7);
        put_attr(&mut body, IFLA_IFNAME, b"nic1\0");
        put_attr(&mut body, IFLA_ADDRESS, &[2, 0, 0, 0, 0, 9]);
        put_attr(&mut body, IFLA_MASTER, &10u32.to_ne_bytes());
        put_attr(&mut body, IFLA_LINK, &4u32.to_ne_bytes());
        put_attr(&mut body, IFLA_PARENT_DEV_NAME, b"0000:01:00.0\0");
        let mut nested = Vec::new();
        put_attr(&mut nested, IFLA_INFO_KIND, b"vlan\0");
        put_attr(&mut body, IFLA_LINKINFO, &nested);

        // A bridge's ageing time rides inside IFLA_INFO_DATA, and nothing
        // else reads it, so a wrong attribute id here is invisible everywhere
        // else. The ids are the kernel headers' numbers (IFLA_INFO_DATA 2,
        // IFLA_BR_AGEING_TIME 4), not this file's constants, which would let
        // the test agree with a wrong decoder.
        let mut br_data = Vec::new();
        put_attr(&mut br_data, 4, &30_000u32.to_ne_bytes());
        let mut br_info = Vec::new();
        put_attr(&mut br_info, IFLA_INFO_KIND, b"bridge\0");
        put_attr(&mut br_info, 2, &br_data);
        let mut br = ifinfomsg(10);
        put_attr(&mut br, IFLA_IFNAME, b"vmbr1\0");
        put_attr(&mut br, IFLA_LINKINFO, &br_info);
        let b = parse_link(&br).expect("a bridge message parses");
        assert_eq!(b.kind.as_deref(), Some("bridge"));
        assert_eq!(
            b.ageing,
            Some(30_000),
            "the bridge's ageing time has to come out of IFLA_INFO_DATA, \
             in the kernel's clock_t - 30000 is the default five minutes"
        );

        // A bridge that does not report one, and a truncated value, both
        // leave the dating without a number rather than with a wrong one.
        let mut plain = ifinfomsg(10);
        put_attr(&mut plain, IFLA_IFNAME, b"vmbr1\0");
        let mut only_kind = Vec::new();
        put_attr(&mut only_kind, IFLA_INFO_KIND, b"bridge\0");
        put_attr(&mut plain, IFLA_LINKINFO, &only_kind);
        assert_eq!(parse_link(&plain).expect("parses").ageing, None);
        let mut short = Vec::new();
        put_attr(&mut short, 4, &[1u8, 2]);
        let mut short_info = Vec::new();
        put_attr(&mut short_info, IFLA_INFO_KIND, b"bridge\0");
        put_attr(&mut short_info, 2, &short);
        let mut trunc = ifinfomsg(10);
        put_attr(&mut trunc, IFLA_IFNAME, b"vmbr1\0");
        put_attr(&mut trunc, IFLA_LINKINFO, &short_info);
        assert_eq!(parse_link(&trunc).expect("parses").ageing, None);

        let l = parse_link(&body).expect("a well-formed link message parses");
        assert_eq!(l.index, 7);
        assert_eq!(l.name, "nic1", "the kernel's trailing NUL stays out");

        // A parent in another namespace: IFLA_LINK is an index THERE and
        // must not become a local lower edge.
        let mut foreign = ifinfomsg(7);
        put_attr(&mut foreign, IFLA_IFNAME, b"veth0\0");
        put_attr(&mut foreign, IFLA_LINK, &4u32.to_ne_bytes());
        put_attr(&mut foreign, IFLA_LINK_NETNSID, &0u32.to_ne_bytes());
        assert_eq!(
            parse_link(&foreign).expect("parses").link,
            None,
            "a foreign parent's index is not ours to follow"
        );
        assert_eq!(l.mac, Some([2, 0, 0, 0, 0, 9]));
        assert_eq!(l.master, Some(10));
        assert_eq!(l.link, Some(4));
        assert_eq!(l.kind.as_deref(), Some("vlan"));
        assert_eq!(l.parent_dev.as_deref(), Some("0000:01:00.0"));

        // The rejections: no index is no interface; no name is no interface.
        assert!(parse_link(&ifinfomsg(0)).is_none());
        assert!(parse_link(&ifinfomsg(-3)).is_none());
        assert!(parse_link(&ifinfomsg(7)).is_none(), "nameless");
        assert!(parse_link(&[0u8; 8]).is_none(), "shorter than an ifinfomsg");
    }

    /// The kernel validates a classic BPF program at attach time, on any
    /// socket - so a malformed opcode or an out-of-range jump fails right
    /// here instead of on the first packet of a production host.
    #[test]
    fn the_noise_filter_is_a_program_the_kernel_accepts() {
        use std::os::fd::AsRawFd;
        let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("a socket to attach to");
        attach_noise_filter(s.as_raw_fd()).expect("the kernel accepts the filter");
    }

    /// `nla_nest_end()` writes a nest's 16-bit length without checking it
    /// fits: IFLA_VFINFO_LIST on a card with hundreds of VFs is silently
    /// truncated to the low sixteen bits. Nothing can repair such a message;
    /// the decoder must refuse to be led out of the buffer and come out
    /// *short* rather than plausible, because a short answer is what
    /// warn_about_unknowable_vfs compares against sriov_numvfs.
    #[test]
    fn a_nest_that_lies_about_its_length_is_read_short_not_dangerously() {
        let vf_mac = |mac: [u8; 6]| {
            let mut v = Vec::new();
            v.extend_from_slice(&0u32.to_ne_bytes());
            v.extend_from_slice(&mac);
            v.extend_from_slice(&[0u8; 26]);
            v
        };
        let one_vf = |mac: [u8; 6]| {
            let mut info = Vec::new();
            put_attr(&mut info, IFLA_VF_MAC, &vf_mac(mac));
            info
        };
        let mut list = Vec::new();
        let first = one_vf([2, 0, 0, 0, 0, 1]);
        put_attr(&mut list, IFLA_VF_INFO, &first);
        let first_entry = list.len();
        put_attr(&mut list, IFLA_VF_INFO, &one_vf([2, 0, 0, 0, 0, 2]));
        put_attr(&mut list, IFLA_VF_INFO, &one_vf([2, 0, 0, 0, 0, 3]));

        // Honest first, so the truncation below is the only difference.
        let mut body = ifinfomsg(5);
        put_attr(&mut body, IFLA_VFINFO_LIST, &list);
        let mut all = Vec::new();
        collect_vf_macs(&body, &mut all);
        assert_eq!(all.len(), 3, "the undamaged list holds three");

        // What a wrapped length looks like from here: every byte still
        // present, the nest claiming to hold only the first entry.
        let mut cut = body.clone();
        let nest = IFINFOMSG_LEN;
        let stated = (RTATTR_HDR + first_entry) as u16;
        cut[nest..nest + 2].copy_from_slice(&stated.to_ne_bytes());
        let mut short = Vec::new();
        collect_vf_macs(&cut, &mut short);
        assert_eq!(
            short,
            vec![(5, [2, 0, 0, 0, 0, 1])],
            "a nest cut short must yield what it claims and stop, not walk on \
             into the bytes behind it"
        );
        assert!(
            short.len() < all.len(),
            "coming out short is the signal the unknowable-VF check needs"
        );

        // The other direction: a length longer than the message. Nothing may
        // be read past the end - not one address, not a panic.
        let mut over = body.clone();
        over[nest..nest + 2].copy_from_slice(&u16::MAX.to_ne_bytes());
        let mut none = Vec::new();
        collect_vf_macs(&over, &mut none);
        assert!(
            none.is_empty(),
            "an attribute claiming more than the buffer holds must be refused"
        );
    }

    /// collect_vf_macs walks three nesting levels, and nothing asserted any
    /// of them. The all-zero address means "nobody set one" and is passed
    /// through - filtering it is the caller's judgement, not the parser's.
    #[test]
    fn the_virtual_function_addresses_come_out_of_their_triple_nesting() {
        let vf_mac = |mac: [u8; 6]| {
            // struct ifla_vf_mac { u32 vf; u8 mac[32]; }
            let mut v = Vec::new();
            v.extend_from_slice(&0u32.to_ne_bytes());
            v.extend_from_slice(&mac);
            v.extend_from_slice(&[0u8; 26]);
            v
        };
        let mut list = Vec::new();
        let mut info = Vec::new();
        put_attr(&mut info, IFLA_VF_MAC, &vf_mac([2, 0, 0, 0, 0, 1]));
        put_attr(&mut list, IFLA_VF_INFO, &info);
        let mut info = Vec::new();
        put_attr(&mut info, IFLA_VF_MAC, &vf_mac([2, 0, 0, 0, 0, 2]));
        put_attr(&mut list, IFLA_VF_INFO, &info);

        let mut body = ifinfomsg(5);
        put_attr(&mut body, IFLA_VFINFO_LIST, &list);
        let mut out = Vec::new();
        collect_vf_macs(&body, &mut out);
        assert_eq!(out, vec![(5, [2, 0, 0, 0, 0, 1]), (5, [2, 0, 0, 0, 0, 2])]);

        // The same message with NLA_F_NESTED on every nest type - the shape a
        // kernel with strict validation sends one day. The flag mask (`kind &
        // 0x3fff`) makes this come out equal; until this test the mask was
        // the suite's only surviving mutation.
        const NLA_F_NESTED: u16 = 0x8000;
        let mut list = Vec::new();
        let mut info = Vec::new();
        put_attr(&mut info, IFLA_VF_MAC, &vf_mac([2, 0, 0, 0, 0, 1]));
        put_attr(&mut list, IFLA_VF_INFO | NLA_F_NESTED, &info);
        let mut info = Vec::new();
        put_attr(&mut info, IFLA_VF_MAC, &vf_mac([2, 0, 0, 0, 0, 2]));
        put_attr(&mut list, IFLA_VF_INFO | NLA_F_NESTED, &info);
        let mut body = ifinfomsg(5);
        put_attr(&mut body, IFLA_VFINFO_LIST | NLA_F_NESTED, &list);
        let mut out = Vec::new();
        collect_vf_macs(&body, &mut out);
        assert_eq!(
            out,
            vec![(5, [2, 0, 0, 0, 0, 1]), (5, [2, 0, 0, 0, 0, 2])],
            "a kernel that stamps NLA_F_NESTED must not empty the VF list"
        );

        // A message about no interface contributes nothing.
        let mut bad = ifinfomsg(0);
        put_attr(&mut bad, IFLA_VFINFO_LIST, &list);
        let mut out = Vec::new();
        collect_vf_macs(&bad, &mut out);
        assert!(out.is_empty());
    }

    /// The event reader classifies a batch: bridge neighbours in, other
    /// address families out, link messages noted with their index. Nothing
    /// exercised it before.
    #[test]
    fn a_notification_batch_is_read_for_what_it_is() {
        let (mut sock, kernel) = kernel_pair();
        let mut batch = Vec::new();
        // A learned bridge entry.
        batch.extend_from_slice(&msg(
            RTM_NEWNEIGH,
            0,
            &ndmsg(4, 0x02, 0, Some([2, 0, 0, 0, 0, 3]), Some(9)),
        ));
        // An AF_INET neighbour - not ours.
        let mut inet = ndmsg(4, 0x02, 0, Some([2, 0, 0, 0, 0, 4]), None);
        inet[0] = libc::AF_INET as u8;
        batch.extend_from_slice(&msg(RTM_NEWNEIGH, 0, &inet));
        // An interface changing.
        batch.extend_from_slice(&msg(RTM_NEWLINK, 0, &ifinfomsg(31)));
        send_raw(&kernel, &batch);

        let ev = sock.recv_events().unwrap();
        assert_eq!(ev.fdb.len(), 1, "the AF_INET neighbour got in");
        assert_eq!(ev.fdb[0].1.mac, [2, 0, 0, 0, 0, 3]);
        assert!(ev.links_changed);
        assert_eq!(ev.changed_links, vec![31]);

        // Nothing queued reads as nothing, not as an error.
        let quiet = sock.recv_events().unwrap();
        assert!(quiet.fdb.is_empty() && !quiet.links_changed);
    }

    /// The kernel filter's DROP direction had no test: an off-by-one in the
    /// hand-coded jumps degrades silently to accept-everything with every
    /// suite green. AF_UNIX datagram pairs honour SO_ATTACH_FILTER with
    /// production semantics, so the program itself is put on the wire. The
    /// deliver direction needs no twin: a filter that dropped bridge events
    /// would fail every event scenario in the netns suite.
    #[cfg(target_endian = "little")]
    #[test]
    fn the_noise_filter_drops_what_it_exists_to_drop() {
        let (mut sock, kernel) = kernel_pair();
        attach_noise_filter(sock.fd.as_raw_fd()).expect("the filter attaches");

        // An AF_INET neighbour - ARP chatter, the noise the filter is for.
        let mut arp = ndmsg(4, 0x02, 0, Some([2, 0, 0, 0, 0, 7]), None);
        arp[0] = libc::AF_INET as u8;
        send_raw(&kernel, &msg(RTM_NEWNEIGH, 0, &arp));
        // An AF_BRIDGE neighbour - the bridge talking, must get through.
        send_raw(
            &kernel,
            &msg(
                RTM_NEWNEIGH,
                0,
                &ndmsg(4, 0x02, 0, Some([2, 0, 0, 0, 0, 8]), Some(9)),
            ),
        );

        // Only the bridge entry arrives; the ARP datagram never wakes us.
        let ev = sock.recv_events().unwrap();
        assert_eq!(
            ev.fdb.len(),
            1,
            "the ARP neighbour reached userspace - the filter is accept-everything"
        );
        assert_eq!(ev.fdb[0].1.mac, [2, 0, 0, 0, 0, 8]);
        let quiet = sock.recv_events().unwrap();
        assert!(quiet.fdb.is_empty(), "nothing else should be queued");
    }

    /// The registration request byte for byte, and both answers: a wrong flag
    /// (CREATE without EXCL, a missing NTF_SELF) would still "work" against a
    /// kernel and quietly mean something else.
    #[test]
    fn a_registration_is_asked_for_exactly_and_both_answers_are_understood() {
        let (mut sock, kernel) = kernel_pair();
        let answers = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut seen = Vec::new();
            for reply in [0i32, -libc::EEXIST] {
                let n = recv_raw(kernel.as_raw_fd(), &mut buf);
                if n <= 0 {
                    break;
                }
                seen.push(buf[..n as usize].to_vec());
                let seq = u32::from_ne_bytes(buf[8..12].try_into().unwrap());
                let mut err = reply.to_ne_bytes().to_vec();
                err.extend_from_slice(&buf[..NLMSG_HDR.min(n as usize)]);
                send_raw(&kernel, &msg_seq(NLMSG_ERROR, seq, &err));
            }
            seen
        });

        sock.set_self_fdb(7, &[2, 0, 0, 0, 0, 5], true)
            .expect("an acknowledgement of code zero is success");
        let e = sock
            .set_self_fdb(7, &[2, 0, 0, 0, 0, 5], true)
            .expect_err("EEXIST has to reach the caller, who treats it as not-ours");
        assert_eq!(e.raw_os_error(), Some(libc::EEXIST));

        drop(sock);
        let seen = answers.join().unwrap();
        assert_eq!(seen.len(), 2);
        let req = &seen[0];
        assert_eq!(
            u16::from_ne_bytes(req[4..6].try_into().unwrap()),
            RTM_NEWNEIGH
        );
        let flags = u16::from_ne_bytes(req[6..8].try_into().unwrap());
        assert_eq!(
            flags,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            "EXCL is what keeps somebody else's entry from being claimed"
        );
        assert_eq!(req[16], libc::AF_BRIDGE as u8);
        assert_eq!(
            u32::from_ne_bytes(req[20..24].try_into().unwrap()),
            7,
            "the interface index"
        );
        assert_eq!(
            u16::from_ne_bytes(req[24..26].try_into().unwrap()),
            NUD_PERMANENT
        );
        assert_eq!(req[26], NTF_SELF);
        // The address attribute closes the request.
        assert_eq!(&req[32..38], &[2, 0, 0, 0, 0, 5]);
    }

    /// Lengths come off the wire and are believed nowhere: a message claiming
    /// four gigabytes, an attribute past its buffer or shorter than its
    /// header
    /// - each ends the walk, none panics. The kernel does not send these;
    ///   nothing else may abort this daemon by sending them either.
    #[test]
    fn hostile_lengths_end_the_walk_instead_of_the_process() {
        // A message header claiming u32::MAX bytes.
        let mut huge = Vec::new();
        put_nlmsghdr(&mut huge, u32::MAX, RTM_NEWNEIGH, 0, 1);
        assert_eq!(messages(&huge).count(), 0);

        // A message claiming a little more than there is.
        let mut over = Vec::new();
        put_nlmsghdr(&mut over, (NLMSG_HDR + 8) as u32, RTM_NEWNEIGH, 0, 1);
        over.extend_from_slice(&[0u8; 4]); // only 4 of the promised 8
        assert_eq!(messages(&over).count(), 0);

        // An attribute that runs past its buffer, after one good one.
        let mut a = Vec::new();
        put_attr(&mut a, 1, &[1, 2, 3, 4]);
        a.extend_from_slice(&200u16.to_ne_bytes()); // len far past the end
        a.extend_from_slice(&2u16.to_ne_bytes());
        a.extend_from_slice(&[9u8; 4]);
        let got: Vec<_> = attrs(&a).collect();
        assert_eq!(got.len(), 1, "the good attribute, and only it");

        // An attribute shorter than its own header.
        let mut b = Vec::new();
        b.extend_from_slice(&2u16.to_ne_bytes());
        b.extend_from_slice(&1u16.to_ne_bytes());
        assert_eq!(attrs(&b).count(), 0);
    }

    /// A question without NLM_F_DUMP has nothing to end, but a kernel ends it
    /// anyway for an interface that disappears between asking and answering;
    /// falling through to the catch-all arm waited out the five-second
    /// deadline. Verified by mutation: without the NLMSG_DONE arm this takes
    /// five seconds.
    #[test]
    fn a_question_ended_by_the_kernel_returns_at_once() {
        let (mut sock, kernel) = kernel_pair();
        let mut req = Vec::new();
        put_nlmsghdr(&mut req, NLMSG_HDR as u32, RTM_GETLINK, NLM_F_REQUEST, 7);
        send_raw(&kernel, &msg_seq(NLMSG_DONE, 7, &[]));

        let started = Instant::now();
        let mut answers = 0;
        sock.request_one(&req, RTM_NEWLINK, &mut |_| answers += 1)
            .expect("a dump end is an answer, not a failure");
        assert_eq!(answers, 0, "there was nothing to report");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "waited {:?} for an answer that had already arrived",
            started.elapsed()
        );
    }

    /// A dump datagram larger than the buffer is asked for again into a
    /// bigger one; retrying into the same buffer gave six identical failures.
    /// Verified by mutation: with the resize removed the dump fails.
    #[test]
    fn a_dump_that_does_not_fit_grows_rather_than_giving_up() {
        let (mut sock, kernel) = kernel_pair();
        // The kernel side answers every request that arrives, addressed to
        // that request's own sequence number - so the retry gets an answer
        // of its own, after the abandoned attempt has been drained.
        let listener = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut answered = 0;
            loop {
                let n = recv_raw(kernel.as_raw_fd(), &mut buf);
                if n < NLMSG_HDR as isize {
                    return answered;
                }
                let seq = u32::from_ne_bytes(buf[8..12].try_into().unwrap());
                let mut batch = Vec::new();
                for i in 0..8 {
                    batch.extend_from_slice(&msg_seq(
                        RTM_NEWNEIGH,
                        seq,
                        &ndmsg(
                            i + 1,
                            0x02, // NUD_REACHABLE
                            0,
                            Some([0x02, 0, 0, 0, 0, i as u8]),
                            Some(5),
                        ),
                    ));
                }
                send_raw(&kernel, &batch);
                send_raw(&kernel, &msg_seq(NLMSG_DONE, seq, &[]));
                answered += 1;
            }
        });

        let mut req = Vec::new();
        put_nlmsghdr(&mut req, NLMSG_HDR as u32, RTM_GETNEIGH, NLM_F_REQUEST, 0);
        // 64 bytes holds one message and not eight.
        let got: Vec<usize> = sock
            .dump_from(64, &req, RTM_NEWNEIGH, "test", |payload, out| {
                out.push(payload.len())
            })
            .expect("the dump has to survive a buffer that starts too small");
        assert_eq!(got.len(), 8, "every entry has to come back, once");

        drop(sock); // ends the listener's loop
        let attempts = listener.join().unwrap();
        assert!(
            attempts >= 2,
            "the point of the test is that it took a second, bigger attempt"
        );
    }

    /// The one-interface question grows its buffer like a dump: a PF whose VF
    /// list outgrew 64 KiB failed vf_macs_of and the WHOLE pass, for ever -
    /// fail-closed was right, but "this host is too big to reconcile" is a
    /// bug, not a state. Verified by mutation: without the resend after
    /// growing this fails with "the answer outgrew the buffer".
    #[test]
    fn a_one_interface_answer_that_does_not_fit_grows_rather_than_failing() {
        let (mut sock, kernel) = kernel_pair();
        let listener = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut answered = 0;
            loop {
                let n = recv_raw(kernel.as_raw_fd(), &mut buf);
                if n < NLMSG_HDR as isize {
                    return answered;
                }
                let seq = u32::from_ne_bytes(buf[8..12].try_into().unwrap());
                // One answer, 200 bytes of payload - more than the 64 the
                // caller starts with, well under what it grows to.
                send_raw(&kernel, &msg_seq(RTM_NEWLINK, seq, &[7u8; 200]));
                answered += 1;
            }
        });

        let mut req = Vec::new();
        put_nlmsghdr(&mut req, NLMSG_HDR as u32, RTM_GETLINK, NLM_F_REQUEST, 9);
        let mut seen = Vec::new();
        sock.request_one_from(64, &req, RTM_NEWLINK, &mut |payload: &[u8]| {
            seen.push(payload.len())
        })
        .expect("the question has to survive a buffer that starts too small");
        assert_eq!(seen, vec![200], "the answer has to arrive, once");

        drop(sock);
        let attempts = listener.join().unwrap();
        assert!(
            attempts >= 2,
            "the point of the test is that it took a second, bigger attempt"
        );
    }

    /// The VF request has to say it does not want statistics: they come out
    /// of the hardware and were two thirds of the call. A regression here is
    /// invisible in behaviour and shows only as the daemon costing three
    /// times as much.
    /// The link dump skips the statistics too, and must keep skipping the
    /// VF details: the flag mask is the difference between one request and
    /// a firmware question per PF.
    /// An `ndmsg`-sized dump request means "everything" to the kernel, so
    /// the one-interface dump has to be `ifinfomsg`-sized with the index in
    /// ifi_index - or it silently dumps the whole host.
    #[test]
    fn the_one_interface_fdb_dump_is_shaped_so_the_kernel_filters_it() {
        let req = fdb_of_request(42);
        assert_eq!(req.len(), NLMSG_HDR + IFINFOMSG_LEN);
        assert_eq!(
            u32::from_ne_bytes(req[0..4].try_into().unwrap()) as usize,
            req.len()
        );
        assert_eq!(
            u16::from_ne_bytes(req[4..6].try_into().unwrap()),
            RTM_GETNEIGH
        );
        assert_eq!(i32::from_ne_bytes(req[20..24].try_into().unwrap()), 42);
        // The two bytes the kernel routes on: without AF_BRIDGE the request
        // lands in the ARP table's dump, without NLM_F_DUMP in the single-
        // entry getter.
        assert_eq!(req[16], libc::AF_BRIDGE as u8);
        assert_eq!(
            u16::from_ne_bytes(req[6..8].try_into().unwrap()) & NLM_F_DUMP,
            NLM_F_DUMP
        );
    }

    #[test]
    fn the_link_dump_asks_for_no_statistics_and_no_vf_details() {
        let req = link_dump_request();
        let mask = attrs(&req[NLMSG_HDR + IFINFOMSG_LEN..])
            .find(|(kind, _)| *kind == IFLA_EXT_MASK)
            .map(|(_, v)| u32::from_ne_bytes(v[..4].try_into().unwrap()))
            .expect("the dump carries an extended filter mask");
        assert_eq!(mask & RTEXT_FILTER_SKIP_STATS, RTEXT_FILTER_SKIP_STATS);
        assert_eq!(mask & RTEXT_FILTER_VF, 0, "VF details cost 1.35 ms per PF");
        assert_eq!(
            u32::from_ne_bytes(req[0..4].try_into().unwrap()) as usize,
            req.len(),
            "nlmsg_len covers the attribute"
        );
    }

    #[test]
    fn the_virtual_function_request_asks_for_no_statistics() {
        let req = vf_request(7, 3);
        assert_eq!(
            u32::from_ne_bytes(req[8..12].try_into().unwrap()),
            3,
            "the sequence number goes where request_one looks for it"
        );
        assert_eq!(
            i32::from_ne_bytes(req[20..24].try_into().unwrap()),
            7,
            "and the interface index into ifi_index"
        );
        let mask = attrs(&req[NLMSG_HDR + IFINFOMSG_LEN..])
            .find(|(kind, _)| *kind == IFLA_EXT_MASK)
            .map(|(_, v)| u32::from_ne_bytes(v[..4].try_into().unwrap()))
            .expect("the request carries an extended filter mask");
        assert_eq!(
            mask & RTEXT_FILTER_VF,
            RTEXT_FILTER_VF,
            "without this the answer has no virtual functions in it"
        );
        assert_eq!(
            mask & RTEXT_FILTER_SKIP_STATS,
            RTEXT_FILTER_SKIP_STATS,
            "without this the kernel reads traffic counters out of the card \
             for every virtual function, on every pass, for nobody"
        );
    }

    /// A dump the kernel abandons ends with NLMSG_DONE carrying a negative
    /// errno; believing that end is believing a short table is the whole
    /// table. Verified by mutation: without reading the code this returns Ok
    /// and the entries are silently lost.
    #[test]
    fn a_dump_the_kernel_gave_up_on_is_not_a_finished_dump() {
        let (mut sock, kernel) = kernel_pair();
        let listener = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                let n = recv_raw(kernel.as_raw_fd(), &mut buf);
                if n < NLMSG_HDR as isize {
                    return;
                }
                let seq = u32::from_ne_bytes(buf[8..12].try_into().unwrap());
                // One entry, then "done" with -ENOMEM in its body.
                send_raw(
                    &kernel,
                    &msg_seq(
                        RTM_NEWNEIGH,
                        seq,
                        &ndmsg(1, 0x02, 0, Some([0x02, 0, 0, 0, 0, 1]), Some(5)),
                    ),
                );
                send_raw(
                    &kernel,
                    &msg_seq(NLMSG_DONE, seq, &(-libc::ENOMEM).to_ne_bytes()),
                );
            }
        });

        let mut req = Vec::new();
        put_nlmsghdr(&mut req, NLMSG_HDR as u32, RTM_GETNEIGH, NLM_F_REQUEST, 0);
        let got = sock.dump_from(
            64 * 1024,
            &req,
            RTM_NEWNEIGH,
            "test",
            |p, out: &mut Vec<usize>| out.push(p.len()),
        );
        drop(sock);
        let _ = listener.join();

        let err = got.expect_err("a dump that ended in an error is not an answer");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ENOMEM),
            "and it says which error, so the warning names it"
        );
    }
}
