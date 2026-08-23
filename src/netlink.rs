//! The little bit of rtnetlink this daemon needs.
//!
//! Three operations, all on `AF_BRIDGE` neighbour messages - which is what the
//! kernel calls forwarding database entries:
//!
//! * dump every FDB entry the host knows, learnt and permanent alike,
//! * add or remove an entry with `NTF_SELF`, which is the unicast filter list
//!   of the interface itself rather than the bridge's table,
//! * subscribe to `RTNLGRP_NEIGH` and read changes as they happen.
//!
//! Done by hand rather than through a netlink crate: the message layouts used
//! here are small and stable, and a daemon that writes into a NIC's hardware
//! filters is easier to trust when its dependency list is one crate long.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub const RTM_NEWNEIGH: u16 = 28;
pub const RTM_DELNEIGH: u16 = 29;
pub const RTM_GETNEIGH: u16 = 30;
pub const RTM_NEWLINK: u16 = 16;
pub const RTM_GETLINK: u16 = 18;

const NLMSG_NOOP: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

const NLM_F_REQUEST: u16 = 0x001;
const NLM_F_ACK: u16 = 0x004;
const NLM_F_ROOT: u16 = 0x100;
const NLM_F_MATCH: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

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

pub struct Socket {
    fd: OwnedFd,
    seq: u32,
}

impl Socket {
    pub fn new() -> io::Result<Self> {
        Self::open(0)
    }

    /// A socket that also receives FDB change notifications.
    pub fn subscribed() -> io::Result<Self> {
        Self::open(1 << (RTNLGRP_NEIGH - 1))
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
        let size: libc::c_int = 1 << 20;
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &size as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
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
        Ok(())
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let n = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            return Ok(n as usize);
        }
    }

    /// Every forwarding database entry on the host, learnt and configured.
    pub fn dump_fdb(&mut self) -> io::Result<Vec<FdbEntry>> {
        self.seq += 1;
        let seq = self.seq;
        let mut req = Vec::with_capacity(NLMSG_HDR + NDMSG_LEN);
        put_nlmsghdr(
            &mut req,
            (NLMSG_HDR + NDMSG_LEN) as u32,
            RTM_GETNEIGH,
            NLM_F_REQUEST | NLM_F_DUMP,
            seq,
        );
        req.push(libc::AF_BRIDGE as u8); // ndm_family
        req.push(0); // pad1
        req.extend_from_slice(&0u16.to_ne_bytes()); // pad2
        req.extend_from_slice(&0i32.to_ne_bytes()); // ifindex
        req.extend_from_slice(&0u16.to_ne_bytes()); // state
        req.push(0); // flags
        req.push(0); // type
        self.send(&req)?;

        let mut out = Vec::new();
        let mut buf = vec![0u8; 256 * 1024];
        'outer: loop {
            let n = self.recv(&mut buf)?;
            for (kind, payload) in messages(&buf[..n]) {
                match kind {
                    NLMSG_DONE => break 'outer,
                    NLMSG_ERROR => {
                        if let Some(e) = nlmsg_error(payload) {
                            return Err(e);
                        }
                        break 'outer;
                    }
                    NLMSG_NOOP => continue,
                    RTM_NEWNEIGH => {
                        if let Some(e) = parse_fdb(payload) {
                            out.push(e);
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(out)
    }

    /// The administratively set MAC of every VF of every interface, keyed by
    /// the PF's interface index. This is the address the guest will use, and
    /// it exists whether or not the VF is bound on the host.
    pub fn dump_vf_macs(&mut self) -> io::Result<Vec<(u32, [u8; 6])>> {
        self.seq += 1;
        let seq = self.seq;
        let len = NLMSG_HDR + IFINFOMSG_LEN + RTATTR_HDR + 4;
        let mut req = Vec::with_capacity(len);
        put_nlmsghdr(&mut req, len as u32, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, seq);
        req.push(libc::AF_UNSPEC as u8);
        req.push(0);
        req.extend_from_slice(&0u16.to_ne_bytes()); // ifi_type
        req.extend_from_slice(&0i32.to_ne_bytes()); // ifi_index
        req.extend_from_slice(&0u32.to_ne_bytes()); // ifi_flags
        req.extend_from_slice(&0u32.to_ne_bytes()); // ifi_change
        put_attr_u32(&mut req, IFLA_EXT_MASK, RTEXT_FILTER_VF);
        self.send(&req)?;

        let mut out = Vec::new();
        let mut buf = vec![0u8; 256 * 1024];
        'outer: loop {
            let n = self.recv(&mut buf)?;
            for (kind, payload) in messages(&buf[..n]) {
                match kind {
                    NLMSG_DONE => break 'outer,
                    NLMSG_ERROR => {
                        if let Some(e) = nlmsg_error(payload) {
                            return Err(e);
                        }
                        break 'outer;
                    }
                    RTM_NEWLINK => collect_vf_macs(payload, &mut out),
                    _ => {}
                }
            }
        }
        Ok(out)
    }

    /// Add or remove an address in an interface's own unicast filter list -
    /// the `bridge fdb ... self permanent` of iproute2.
    pub fn set_self_fdb(&mut self, ifindex: u32, mac: &[u8; 6], add: bool) -> io::Result<()> {
        self.seq += 1;
        let seq = self.seq;
        let len = NLMSG_HDR + NDMSG_LEN + RTATTR_HDR + 6 + 2; // lladdr is padded to 8
        let mut req = Vec::with_capacity(len);
        let (kind, flags) = if add {
            (RTM_NEWNEIGH, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL)
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

        let mut buf = vec![0u8; 8192];
        let n = self.recv(&mut buf)?;
        for (k, payload) in messages(&buf[..n]) {
            if k == NLMSG_ERROR {
                if let Some(e) = nlmsg_error(payload) {
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Block until the kernel reports a change, then return everything that
    /// arrived. `None` means the notification was of no interest.
    pub fn recv_events(&self) -> io::Result<Vec<(u16, FdbEntry)>> {
        let mut buf = vec![0u8; 64 * 1024];
        let n = self.recv(&mut buf)?;
        let mut out = Vec::new();
        for (kind, payload) in messages(&buf[..n]) {
            if kind == RTM_NEWNEIGH || kind == RTM_DELNEIGH {
                if let Some(e) = parse_fdb(payload) {
                    out.push((kind, e));
                }
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
        loop {
            let rc = unsafe { libc::poll(&mut pfd, 1, millis) };
            if rc < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
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

/// Walk the netlink messages in a received buffer.
fn messages(buf: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + NLMSG_HDR <= buf.len() {
        let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
        if len < NLMSG_HDR || off + len > buf.len() {
            break;
        }
        out.push((kind, &buf[off + NLMSG_HDR..off + len]));
        off += align4(len);
    }
    out
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

/// Walk the attributes of a message body.
fn attrs(buf: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + RTATTR_HDR <= buf.len() {
        let len = u16::from_ne_bytes(buf[off..off + 2].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(buf[off + 2..off + 4].try_into().unwrap());
        if len < RTATTR_HDR || off + len > buf.len() {
            break;
        }
        out.push((kind, &buf[off + RTATTR_HDR..off + len]));
        off += align4(len);
    }
    out
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
                // struct ifla_vf_mac { __u32 vf; __u8 mac[32]; }
                if mac_kind == IFLA_VF_MAC && mac_value.len() >= 4 + 6 {
                    let mut m = [0u8; 6];
                    m.copy_from_slice(&mac_value[4..10]);
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
        if n == 6 || part.len() != 2 {
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
