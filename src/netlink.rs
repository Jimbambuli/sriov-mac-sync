//! The little bit of rtnetlink this daemon needs.
//!
//! Four operations - three on `AF_BRIDGE` neighbour messages, which is what
//! the kernel calls forwarding database entries, and one on link messages:
//!
//! * dump every FDB entry the host knows, learnt and permanent alike,
//! * add or remove an entry with `NTF_SELF`, which is the unicast filter list
//!   of the interface itself rather than the bridge's table,
//! * subscribe to `RTNLGRP_NEIGH` and `RTNLGRP_LINK` and read changes as they
//!   happen - interfaces matter as much as addresses, because a VF whose MAC
//!   is set from the host changes what must be excluded without moving a
//!   single forwarding entry,
//! * ask one interface for its virtual functions' addresses.
//!
//! Done by hand rather than through a netlink crate: the message layouts used
//! here are small and stable, and a daemon that writes into a NIC's hardware
//! filters is easier to trust when its dependency list is one crate long.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

pub const RTM_NEWNEIGH: u16 = 28;
pub const RTM_DELNEIGH: u16 = 29;
pub const RTM_GETNEIGH: u16 = 30;
pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;
pub const RTM_GETLINK: u16 = 18;

const NLMSG_NOOP: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

const NLM_F_REQUEST: u16 = 0x001;
const NLM_F_ACK: u16 = 0x004;
const NLM_F_ROOT: u16 = 0x100;
// The same bits mean different things on GET and on NEW requests: MATCH
// belongs to GET (and makes up NLM_F_DUMP), EXCL to NEW. Their sharing 0x200
// is the kernel's doing, not a typo here - as with IFLA_VF_INFO and
// IFLA_VF_MAC below, which are both 1 in their respective nesting levels.
const NLM_F_MATCH: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
/// The kernel sets this on a dump whose result changed underneath it: what
/// came back is a mixture of two states and must not be acted on.
const NLM_F_DUMP_INTR: u16 = 0x10;

pub const NDA_LLADDR: u16 = 2;
pub const NDA_MASTER: u16 = 9;

pub const NTF_SELF: u8 = 0x02;
pub const NTF_EXT_LEARNED: u8 = 0x10;

pub const NUD_PERMANENT: u16 = 0x80;
pub const NUD_NOARP: u16 = 0x40;

const IFLA_EXT_MASK: u16 = 29;
const IFLA_VFINFO_LIST: u16 = 22;
const IFLA_VF_INFO: u16 = 1;
const IFLA_VF_MAC: u16 = 1;
const RTEXT_FILTER_VF: u32 = 1;

const RTNLGRP_LINK: u32 = 1;
const RTNLGRP_NEIGH: u32 = 3;

const NLMSG_HDR: usize = 16;
const NDMSG_LEN: usize = 12;
const IFINFOMSG_LEN: usize = 16;
const RTATTR_HDR: usize = 4;

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
    /// An address the bridge picked up from traffic, as opposed to one that was
    /// configured: a port's own address, or an entry somebody added by hand.
    /// Entries planted by an external agent - an SDN controller, a VXLAN
    /// daemon - count as learnt too: they describe where a peer actually is.
    ///
    /// The final test is NUD_NOARP: a state given to entries that no probe
    /// ever validates - static VXLAN destinations without NTF_EXT_LEARNED,
    /// for instance - which therefore describe configuration, not an
    /// observed peer.
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

/// A batch of notifications: forwarding entries that changed, and whether any
/// interface changed at all.
#[derive(Debug, Default)]
pub struct Events {
    pub fdb: Vec<(u16, FdbEntry)>,
    pub links_changed: bool,
}

pub struct Socket {
    fd: OwnedFd,
    seq: u32,
}

impl Socket {
    pub fn new() -> io::Result<Self> {
        Self::open(0)
    }

    /// A socket that also receives forwarding and interface notifications.
    ///
    /// Interfaces matter as much as addresses here: a NIC that gets virtual
    /// functions, a bridge built after boot, or a VF whose address is set from
    /// the host all change what belongs in the filter, and none of them moves
    /// a single forwarding entry.
    pub fn subscribed() -> io::Result<Self> {
        Self::open((1 << (RTNLGRP_NEIGH - 1)) | (1 << (RTNLGRP_LINK - 1)))
    }

    fn open(groups: u32) -> io::Result<Self> {
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // A dump of a large forwarding database overruns the default receive
        // buffer easily, and netlink answers that with ENOBUFS rather than
        // with short reads.
        //
        // SO_RCVBUF is silently capped at net.core.rmem_max - 208 KiB on a
        // stock kernel against the megabyte asked for here (the kernel then
        // doubles whatever value wins, for its own bookkeeping), and nothing
        // would say so. SO_RCVBUFFORCE ignores that ceiling; it needs
        // CAP_NET_ADMIN, which this program holds for programming the filter
        // anyway. Fall back to the capped request where it is refused, because
        // a smaller buffer still works and losing notifications is survivable -
        // the full pass reads the real state.
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
        Ok(Socket { fd, seq: 1 })
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

    /// Reads one datagram. `MSG_TRUNC` makes the kernel report the real size
    /// even when it did not fit, so a buffer that is too small shows up as a
    /// number larger than the buffer instead of as silently missing entries.
    ///
    /// Only the kernel is listened to. A netlink socket accepts unicast from
    /// any local process, and everything downstream believes what arrives -
    /// a forged NLMSG_DONE would end a dump early and an empty dump reads as
    /// an empty forwarding table, which ends with every entry removed. The
    /// sender's port id says who it was: zero is the kernel.
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut from: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            let mut from_len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            let n = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    libc::MSG_TRUNC,
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
                continue; // not the kernel talking
            }
            return Ok(n as usize);
        }
    }

    /// `recv`, but gives up when the deadline passes instead of blocking for
    /// good. A reply that never comes - a dump whose final message was lost,
    /// an acknowledgement that went missing - would otherwise stop the whole
    /// daemon, and nothing upstream could even say why.
    fn recv_deadline(&self, buf: &mut [u8], deadline: Instant) -> io::Result<usize> {
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "no answer from the kernel in time",
                ));
            }
            if self.wait(left.as_millis().min(i32::MAX as u128) as i32)? {
                return self.recv(buf);
            }
        }
    }

    /// Runs one dump and hands every message body of type `want` to `sink`.
    ///
    /// Returns `false` when the answer cannot be trusted - either the kernel
    /// flagged the dump as interrupted, or a datagram did not fit the buffer.
    /// Either way the caller should enlarge and try again rather than work
    /// from half a picture.
    fn run_dump(
        &self,
        buf: &mut [u8],
        want: u16,
        seq: u32,
        deadline: Instant,
        sink: &mut impl FnMut(&[u8]),
    ) -> io::Result<bool> {
        loop {
            let n = self.recv_deadline(buf, deadline)?;
            if n > buf.len() {
                return Ok(false); // did not fit
            }
            for msg in messages(&buf[..n]) {
                // An answer to something else, or left over from a dump that
                // was abandoned half-read. Netlink asks callers to check.
                if msg.seq != seq {
                    continue;
                }
                if msg.flags & NLM_F_DUMP_INTR != 0 {
                    return Ok(false); // inconsistent
                }
                match msg.kind {
                    NLMSG_DONE => return Ok(true),
                    NLMSG_ERROR => {
                        // The request asks for no acknowledgement, so an error
                        // message is only ever bad news. One whose code reads
                        // as zero - or one too short to carry a code - must
                        // not pass for a finished dump: an "empty" forwarding
                        // table would have every registration removed.
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

    /// One question about one interface, and the single answer to it.
    ///
    /// `RTM_GETLINK` with `NLM_F_DUMP` ignores the index it is given and
    /// describes every interface in the system. Without the flag the index is
    /// honoured and one message comes back - no `NLMSG_DONE` to wait for, so
    /// the first matching answer ends it.
    fn request_one(
        &mut self,
        request: &[u8],
        want: u16,
        sink: &mut impl FnMut(&[u8]),
    ) -> io::Result<()> {
        let seq = u32::from_ne_bytes(request[8..12].try_into().unwrap());
        self.send(request)?;
        let mut buf = vec![0u8; 128 * 1024];
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let n = self.recv_deadline(&mut buf, deadline)?;
            if n > buf.len() {
                // Whatever else the kernel sent for this question is still
                // queued and would be read as the answer to the next one.
                self.drain();
                return Err(io::Error::other("the answer outgrew the buffer"));
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
                        return Ok(());
                    }
                    NLMSG_NOOP => continue,
                    k if k == want => {
                        sink(msg.payload);
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }
    }

    /// Runs a dump to completion, retrying when the kernel flags it as
    /// interrupted, and returns everything `parse` collected.
    ///
    /// The result belongs to this function so a retry starts from nothing -
    /// collecting into a caller's list would keep the half-read attempt's
    /// entries in front of the real ones. Each retry sends under a fresh
    /// sequence number, so whatever an abandoned attempt left queued cannot
    /// pass for the new answer. The buffer is one fixed 256 KiB: the kernel
    /// caps a dump datagram far below that, so growing it never helped -
    /// the retries only ever defend against NLM_F_DUMP_INTR.
    fn dump<T>(
        &mut self,
        request: &[u8],
        want: u16,
        what: &str,
        mut parse: impl FnMut(&[u8], &mut Vec<T>),
    ) -> io::Result<Vec<T>> {
        let mut req = request.to_vec();
        let mut buf = vec![0u8; 256 * 1024];
        let mut out = Vec::new();
        for _ in 0..6 {
            out.clear();
            self.seq = self.seq.wrapping_add(1);
            req[8..12].copy_from_slice(&self.seq.to_ne_bytes());
            self.send(&req)?;
            let deadline = Instant::now() + Duration::from_secs(5);
            match self.run_dump(&mut buf, want, self.seq, deadline, &mut |payload| {
                parse(payload, &mut out)
            }) {
                Ok(true) => return Ok(out),
                Ok(false) => self.drain(),
                Err(e) => {
                    self.drain();
                    return Err(e);
                }
            }
        }
        Err(io::Error::other(format!(
            "{what} dump kept being interrupted"
        )))
    }

    /// Throws away whatever is still queued from an abandoned request.
    ///
    /// A signal must not end the draining early: what stays queued would be
    /// read as the answer to the next question - the sequence number cannot
    /// tell them apart when a retry reuses it, and an acknowledgement read
    /// one question late misreports every call after it.
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
            if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if n <= 0 {
                return;
            }
        }
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

    /// The addresses administratively set on the virtual functions of the
    /// named interfaces.
    ///
    /// Only the physical functions of the pairs contribute exclusions, and
    /// there are as many of those as there are uplinks. Asking by index costs
    /// one question each; the dump this replaced had the kernel describe
    /// every interface on the host to reach the few that have VFs, and the
    /// serialisation dominated the cost.
    ///
    /// An interface that has gone away answers ENODEV. That is not a failure
    /// worth stopping for: the dump would simply not have listed it, and an
    /// uplink that no longer exists has no virtual functions to exclude.
    pub fn vf_macs_of(&mut self, indices: &[u32]) -> io::Result<Vec<(u32, [u8; 6])>> {
        let mut out = Vec::new();
        for &index in indices {
            self.seq = self.seq.wrapping_add(1);
            let len = NLMSG_HDR + IFINFOMSG_LEN + RTATTR_HDR + 4;
            let mut req = Vec::with_capacity(len);
            put_nlmsghdr(&mut req, len as u32, RTM_GETLINK, NLM_F_REQUEST, self.seq);
            req.push(libc::AF_UNSPEC as u8);
            req.push(0);
            req.extend_from_slice(&0u16.to_ne_bytes()); // ifi_type
            req.extend_from_slice(&(index as i32).to_ne_bytes());
            req.extend_from_slice(&0u32.to_ne_bytes()); // ifi_flags
            req.extend_from_slice(&0u32.to_ne_bytes()); // ifi_change
            put_attr_u32(&mut req, IFLA_EXT_MASK, RTEXT_FILTER_VF);

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

        // The request asks for an acknowledgement, so one message with this
        // sequence number is coming. Reading exactly one datagram and hoping
        // it is the right one is not the same thing: a stray message left
        // over from an earlier error path would be read instead, the real
        // acknowledgement would stay queued, and every call after this one
        // would judge itself by its predecessor's answer.
        let mut buf = [0u8; 8192];
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let n = self.recv_deadline(&mut buf, deadline)?.min(buf.len());
            for msg in messages(&buf[..n]) {
                if msg.seq != seq {
                    continue;
                }
                if msg.kind == NLMSG_ERROR {
                    return match nlmsg_error(msg.payload) {
                        Some(e) => Err(e),
                        None => Ok(()), // the acknowledgement: an error of code zero
                    };
                }
            }
        }
    }

    /// What arrived on the subscription since the last look.
    pub fn recv_events(&self) -> io::Result<Events> {
        let mut buf = vec![0u8; 64 * 1024];
        // A notification that did not fit is a loss like ENOBUFS: what was in
        // it is unknowable, so the caller has to stop trusting what it holds
        // and read the real state - saying so is the difference between that
        // and quietly working from half a batch.
        let n = self.recv(&mut buf)?;
        if n > buf.len() {
            return Err(io::Error::other("a notification batch outgrew the buffer"));
        }
        let mut out = Events::default();
        for msg in messages(&buf[..n]) {
            if msg.kind == RTM_NEWLINK || msg.kind == RTM_DELLINK {
                out.links_changed = true;
                continue;
            }
            if msg.kind != RTM_NEWNEIGH && msg.kind != RTM_DELNEIGH {
                continue;
            }
            // RTNLGRP_NEIGH carries the whole neighbour table, not just the
            // bridge's. On a normal host the ARP and ND cache churns several
            // times a second - every failed lookup for a machine that is
            // switched off is one - and none of it concerns us. Dropping it
            // here is the difference between waking constantly and waking when
            // a bridge actually learns something.
            if msg.payload.first() != Some(&(libc::AF_BRIDGE as u8)) {
                continue;
            }
            if let Some(e) = parse_fdb(msg.payload) {
                out.fdb.push((msg.kind, e));
            }
        }
        Ok(out)
    }

    /// Wait for a notification, giving up after `millis`. False on timeout.
    pub fn wait(&self, millis: i32) -> io::Result<bool> {
        let mut pfd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // A deadline, not a restart: a signal in the middle must not push
        // the wait out again from the beginning, or a steady trickle of
        // signals postpones the timed pass forever.
        let deadline = Instant::now() + Duration::from_millis(millis.max(0) as u64);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let rc =
                unsafe { libc::poll(&mut pfd, 1, left.as_millis().min(i32::MAX as u128) as i32) };
            if rc < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    if left.is_zero() {
                        return Ok(false);
                    }
                    continue;
                }
                return Err(e);
            }
            return Ok(rc > 0);
        }
    }
}

fn put_nlmsghdr(buf: &mut Vec<u8>, len: u32, kind: u16, flags: u16, seq: u32) {
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(&flags.to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes()); // pid: let the kernel fill it in
}

fn put_attr(buf: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let len = RTATTR_HDR + value.len();
    buf.extend_from_slice(&(len as u16).to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(value);
    buf.resize(buf.len() + align4(len) - len, 0);
}

fn put_attr_u32(buf: &mut Vec<u8>, kind: u16, value: u32) {
    put_attr(buf, kind, &value.to_ne_bytes());
}

pub struct Message<'a> {
    pub kind: u16,
    pub flags: u16,
    pub seq: u32,
    pub payload: &'a [u8],
}

/// Walks the netlink messages in a received buffer. A trailing fragment that
/// does not fit is dropped rather than parsed, so a short read cannot turn into
/// nonsense. An iterator rather than a list: a dump of a large forwarding
/// database arrives as thousands of messages per datagram, and none of them
/// needs to be kept.
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
        if len < NLMSG_HDR || self.off + len > self.buf.len() {
            return None;
        }
        let payload = &self.buf[self.off + NLMSG_HDR..self.off + len];
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

fn nlmsg_error(payload: &[u8]) -> Option<io::Error> {
    if payload.len() < 4 {
        return None;
    }
    let code = i32::from_ne_bytes(payload[0..4].try_into().unwrap());
    if code == 0 {
        None // an acknowledgement, not a failure
    } else {
        Some(io::Error::from_raw_os_error(-code))
    }
}

/// Walks the attributes of a message body, without collecting them: this runs
/// once per forwarding entry, and there can be thousands.
struct Attrs<'a> {
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
        Some((kind, value))
    }
}

fn attrs(buf: &[u8]) -> Attrs<'_> {
    Attrs { buf, off: 0 }
}

fn parse_fdb(payload: &[u8]) -> Option<FdbEntry> {
    if payload.len() < NDMSG_LEN {
        return None;
    }
    let ifindex = i32::from_ne_bytes(payload[4..8].try_into().unwrap()) as u32;
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

fn collect_vf_macs(payload: &[u8], out: &mut Vec<(u32, [u8; 6])>) {
    if payload.len() < IFINFOMSG_LEN {
        return;
    }
    let ifindex = i32::from_ne_bytes(payload[4..8].try_into().unwrap()) as u32;
    for (kind, value) in attrs(&payload[IFINFOMSG_LEN..]) {
        if kind != IFLA_VFINFO_LIST {
            continue;
        }
        for (vf_kind, vf_info) in attrs(value) {
            if vf_kind != IFLA_VF_INFO {
                continue;
            }
            for (mac_kind, mac_value) in attrs(vf_info) {
                // struct ifla_vf_mac { __u32 vf; __u8 mac[32]; } - the vf
                // number first, then the address, of which only the usual six
                // bytes carry meaning. Anything shorter than number-plus-six
                // cannot be that struct.
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
