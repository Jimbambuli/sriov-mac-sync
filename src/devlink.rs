//! One question, asked over generic netlink: how many unicast addresses does
//! this card's filter actually hold?
//!
//! Everything else this daemon does is rtnetlink, and stays rtnetlink -
//! devlink has no forwarding database, no unicast filter and no neighbour
//! notifications, so it cannot do the work. What it does have is the one
//! number this program otherwise guesses: `max_macs`, a generic devlink
//! parameter meaning the per-port MAC capacity. On a ConnectX-4 Lx it reads
//! 128, which is exactly the figure this project arrived at by experiment -
//! with 257 entries a given address still worked, with 513 it did not.
//!
//! The list is finite, silently drops addresses past its end, and its size
//! was documented here as unqueryable. It is queryable, on the drivers that
//! register the parameter, and warning against a card's real capacity beats
//! warning against a constant.

use crate::netlink::{attrs, put_attr, put_nlmsghdr, Socket, NLMSG_HDR, NLM_F_DUMP, NLM_F_REQUEST};
use std::io;
use std::path::Path;

/// `NLMSG_MIN_TYPE`: the controller answers on a fixed message type, and it
/// is the only generic family whose number is known in advance.
const GENL_ID_CTRL: u16 = 0x10;
const GENL_HDR: usize = 4; // struct genlmsghdr { u8 cmd; u8 version; u16 pad; }

const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

const DEVLINK_GENL_NAME: &[u8] = b"devlink\0";
const DEVLINK_GENL_VERSION: u8 = 1;
const DEVLINK_CMD_PARAM_GET: u8 = 38;

const DEVLINK_ATTR_BUS_NAME: u16 = 1;
const DEVLINK_ATTR_DEV_NAME: u16 = 2;
const DEVLINK_ATTR_PARAM: u16 = 80;
const DEVLINK_ATTR_PARAM_NAME: u16 = 81;
const DEVLINK_ATTR_PARAM_VALUES_LIST: u16 = 84;
const DEVLINK_ATTR_PARAM_VALUE: u16 = 85;
const DEVLINK_ATTR_PARAM_VALUE_DATA: u16 = 86;
#[cfg(test)]
const DEVLINK_ATTR_PARAM_VALUE_CMODE: u16 = 87; // the tests still emit it, as the kernel does

const MAX_MACS: &str = "max_macs";

/// A capacity as one device reported it. A parameter can be offered
/// several times - what is in effect now, what the driver would start
/// with, what is burnt in - and the lowest number wins, because it is the
/// one a filter can actually be pushed past. Which mode said it does not
/// matter for that: only the value is ever read out.
struct Reported {
    bus: String,
    dev: String,
    value: u32,
}

/// The PCI address behind a network interface, and the one behind its
/// physical function if it has one.
///
/// The uplink here is often a virtual function - that is the arrangement that
/// survives an unplugged switch - and on `mlx5` a VF answers for `max_macs`
/// itself. Where a driver only registers the parameter on the physical
/// function, asking that instead is the difference between an answer and none.
fn pci_addresses(netdev: &str) -> Vec<String> {
    let base = Path::new("/sys/class/net").join(netdev);
    let mut out = Vec::new();
    let mut push = |p: std::path::PathBuf| {
        if let Ok(target) = std::fs::read_link(&p) {
            if let Some(name) = target.file_name().and_then(|n| n.to_str()) {
                let name = name.to_string();
                if !out.contains(&name) {
                    out.push(name);
                }
            }
        }
    };
    push(base.join("device"));
    push(base.join("device/physfn"));
    out
}

fn family_request(seq: u32) -> Vec<u8> {
    let len = NLMSG_HDR + GENL_HDR + crate::netlink::RTATTR_HDR + DEVLINK_GENL_NAME.len();
    let mut req = Vec::with_capacity(len);
    put_nlmsghdr(&mut req, len as u32, GENL_ID_CTRL, NLM_F_REQUEST, seq);
    req.push(CTRL_CMD_GETFAMILY);
    req.push(1); // controller version
    req.extend_from_slice(&0u16.to_ne_bytes());
    put_attr(&mut req, CTRL_ATTR_FAMILY_NAME, DEVLINK_GENL_NAME);
    req
}

fn param_dump_request(family: u16) -> Vec<u8> {
    let len = NLMSG_HDR + GENL_HDR;
    let mut req = Vec::with_capacity(len);
    put_nlmsghdr(
        &mut req,
        len as u32,
        family,
        NLM_F_REQUEST | NLM_F_DUMP,
        0, // dump() assigns a fresh sequence number per attempt
    );
    req.push(DEVLINK_CMD_PARAM_GET);
    req.push(DEVLINK_GENL_VERSION);
    req.extend_from_slice(&0u16.to_ne_bytes());
    req
}

/// The family number devlink was given at registration. It is assigned at
/// boot and differs between hosts, which is why it has to be asked for.
fn resolve_family(sock: &mut Socket) -> io::Result<Option<u16>> {
    let mut id = None;
    // One request on a fresh socket, so the sequence number is a constant
    // rather than a parameter: it used to be one, and no caller ever
    // passed anything but 1.
    sock.request_one(&family_request(1), GENL_ID_CTRL, &mut |payload| {
        if payload.len() < GENL_HDR {
            return;
        }
        for (kind, value) in attrs(&payload[GENL_HDR..]) {
            if kind == CTRL_ATTR_FAMILY_ID && value.len() >= 2 {
                id = Some(u16::from_ne_bytes([value[0], value[1]]));
            }
        }
    })?;
    Ok(id)
}

/// One `DEVLINK_CMD_PARAM_GET` answer, kept only if it is about `max_macs`.
///
/// Nesting, outermost first: the message carries the bus and device it is
/// about and a `PARAM` nest; that holds the name and a `VALUES_LIST`; each
/// `VALUE` in it holds the number and the mode it applies in.
fn collect_param(payload: &[u8], out: &mut Vec<Reported>) {
    if payload.len() < GENL_HDR {
        return;
    }
    let (mut bus, mut dev) = (None, None);
    let mut param = None;
    for (kind, value) in attrs(&payload[GENL_HDR..]) {
        match kind {
            DEVLINK_ATTR_BUS_NAME => bus = cstr(value),
            DEVLINK_ATTR_DEV_NAME => dev = cstr(value),
            DEVLINK_ATTR_PARAM => param = Some(value),
            _ => {}
        }
    }
    let (Some(bus), Some(dev), Some(param)) = (bus, dev, param) else {
        return;
    };

    let mut named = false;
    let mut values = None;
    for (kind, value) in attrs(param) {
        match kind {
            DEVLINK_ATTR_PARAM_NAME => named = cstr(value).as_deref() == Some(MAX_MACS),
            DEVLINK_ATTR_PARAM_VALUES_LIST => values = Some(value),
            _ => {}
        }
    }
    if !named {
        return;
    }
    let Some(values) = values else { return };

    for (kind, value) in attrs(values) {
        if kind != DEVLINK_ATTR_PARAM_VALUE {
            continue;
        }
        let mut number = None;
        for (vkind, vvalue) in attrs(value) {
            // Read by length rather than by the declared type: the type
            // enum has been renumbered in the kernel's history and this
            // parameter is a number in every version of it.
            if vkind == DEVLINK_ATTR_PARAM_VALUE_DATA {
                // Any other width is a parameter this is not about - the
                // arm stays because this is the least exercised code in
                // the tree, and a strange kernel would find it first.
                number = match vvalue.len() {
                    1 => Some(vvalue[0] as u32),
                    2 => Some(u16::from_ne_bytes([vvalue[0], vvalue[1]]) as u32),
                    4 => Some(u32::from_ne_bytes([
                        vvalue[0], vvalue[1], vvalue[2], vvalue[3],
                    ])),
                    _ => None,
                }
            }
        }
        if let Some(value) = number {
            out.push(Reported {
                bus: bus.clone(),
                dev: dev.clone(),
                value,
            });
        }
    }
}

/// A netlink string attribute, which carries its terminating NUL.
fn cstr(value: &[u8]) -> Option<String> {
    let end = value.iter().position(|&b| b == 0).unwrap_or(value.len());
    std::str::from_utf8(&value[..end]).ok().map(str::to_string)
}

/// Everything the dump reported about `max_macs`, read once and asked per
/// netdev - the answer is device-independent, and re-running the dump per
/// uplink was identical, discarded work from the second pair on.
pub struct Capacities {
    reported: Vec<Reported>,
}

/// One devlink reading. `Ok(None)` is a kernel without devlink - the
/// controller answers the family question with ENOENT, which is the
/// ordinary state of most hosts, not an error. Everything else that goes
/// wrong says why: "the card did not answer" and "this program asked
/// wrongly" look identical from the threshold and are not the same bug.
pub fn read() -> Result<Option<Capacities>, String> {
    let mut sock = Socket::generic().map_err(|e| format!("no generic netlink socket: {e}"))?;
    let family = match resolve_family(&mut sock) {
        Ok(Some(f)) => f,
        Ok(None) => return Ok(None),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
        Err(e) => return Err(format!("devlink family: {e}")),
    };
    let reported = sock
        .dump(
            &param_dump_request(family),
            family,
            "devlink parameter",
            collect_param,
        )
        .map_err(|e| format!("devlink parameters: {e}"))?;
    Ok(Some(Capacities { reported }))
}

impl Capacities {
    /// What the driver says this netdev's unicast filter holds, or `None`
    /// when it does not say.
    pub fn for_netdev(&self, netdev: &str) -> Option<u32> {
        self.for_pci(&pci_addresses(netdev))
    }

    /// The device itself first, its physical function only if that said
    /// nothing: a virtual function that answers for itself is answering
    /// about the vport this daemon actually writes to. Per device the
    /// smallest of the offered modes binds - it is the one a filter can
    /// actually be pushed past.
    fn for_pci(&self, wanted: &[String]) -> Option<u32> {
        for pci in wanted {
            let best = self
                .reported
                .iter()
                .filter(|r| r.bus == "pci" && &r.dev == pci)
                .min_by_key(|r| r.value)
                .map(|r| r.value);
            if best.is_some() {
                return best;
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::RTATTR_HDR;

    fn nest(kind: u16, inner: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        put_attr(&mut v, kind, inner);
        v
    }

    /// A whole `DEVLINK_CMD_PARAM_GET` answer as the kernel sends one, built
    /// from the outside in, so the four levels of nesting this has to walk
    /// are asserted rather than hoped for.
    fn param_message(bus: &str, dev: &str, name: &str, values: &[(u8, u32)]) -> Vec<u8> {
        let mut list = Vec::new();
        for (cmode, value) in values {
            let mut one = Vec::new();
            put_attr(
                &mut one,
                DEVLINK_ATTR_PARAM_VALUE_DATA,
                &value.to_ne_bytes(),
            );
            put_attr(&mut one, DEVLINK_ATTR_PARAM_VALUE_CMODE, &[*cmode]);
            list.extend_from_slice(&nest(DEVLINK_ATTR_PARAM_VALUE, &one));
        }
        let mut param = Vec::new();
        put_attr(
            &mut param,
            DEVLINK_ATTR_PARAM_NAME,
            format!("{name}\0").as_bytes(),
        );
        param.extend_from_slice(&nest(DEVLINK_ATTR_PARAM_VALUES_LIST, &list));

        let mut body = vec![0u8; GENL_HDR];
        put_attr(
            &mut body,
            DEVLINK_ATTR_BUS_NAME,
            format!("{bus}\0").as_bytes(),
        );
        put_attr(
            &mut body,
            DEVLINK_ATTR_DEV_NAME,
            format!("{dev}\0").as_bytes(),
        );
        body.extend_from_slice(&nest(DEVLINK_ATTR_PARAM, &param));
        body
    }

    fn capacities(messages: &[Vec<u8>]) -> Capacities {
        let mut reported = Vec::new();
        for m in messages {
            collect_param(m, &mut reported);
        }
        Capacities { reported }
    }

    #[test]
    fn the_capacity_is_read_out_of_its_four_nestings() {
        let mut out = Vec::new();
        collect_param(
            &param_message("pci", "0000:01:00.1", "max_macs", &[(1, 128)]),
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].bus, "pci");
        assert_eq!(out[0].dev, "0000:01:00.1");
        assert_eq!(out[0].value, 128);
    }

    /// The dump carries every parameter of every device - `enable_roce`,
    /// `io_eq_size`, a dozen more. Taking a number from the wrong one would
    /// set the threshold to something meaningless without ever failing.
    #[test]
    fn another_parameter_contributes_nothing() {
        let mut out = Vec::new();
        collect_param(
            &param_message("pci", "0000:01:00.1", "io_eq_size", &[(1, 4096)]),
            &mut out,
        );
        assert!(out.is_empty(), "io_eq_size is not a filter capacity");
    }

    /// Through the production selection, not a re-implementation of it: this
    /// test used to apply its own min_by_key and would have stayed green had
    /// the real one changed.
    #[test]
    fn the_smallest_of_several_modes_is_the_one_that_binds() {
        let caps = capacities(&[param_message(
            "pci",
            "0000:01:00.1",
            "max_macs",
            &[(0, 256), (1, 128)],
        )]);
        assert_eq!(caps.for_pci(&["0000:01:00.1".into()]), Some(128));
    }

    /// The device itself answers before its physical function, and a bus
    /// that is not pci does not answer at all.
    #[test]
    fn the_device_answers_before_its_physical_function() {
        let caps = capacities(&[
            param_message("pci", "0000:01:00.4", "max_macs", &[(1, 64)]),
            param_message("pci", "0000:01:00.1", "max_macs", &[(1, 128)]),
            param_message("auxiliary", "mlx5_core.eth.4", "max_macs", &[(1, 7)]),
        ]);
        let vf_then_pf = ["0000:01:00.4".to_string(), "0000:01:00.1".to_string()];
        assert_eq!(
            caps.for_pci(&vf_then_pf),
            Some(64),
            "the VF's own answer wins"
        );
        let pf_only = ["0000:01:00.9".to_string(), "0000:01:00.1".to_string()];
        assert_eq!(
            caps.for_pci(&pf_only),
            Some(128),
            "a silent device falls through to its physical function"
        );
        assert_eq!(caps.for_pci(&["mlx5_core.eth.4".to_string()]), None);
    }

    /// Truncated messages arrive - a dump cut off, a kernel that stops
    /// filling. Nothing here may read past what it was handed.
    #[test]
    fn a_message_cut_anywhere_is_survived() {
        let whole = param_message("pci", "0000:01:00.1", "max_macs", &[(1, 128)]);
        for cut in 0..whole.len() {
            let mut out = Vec::new();
            collect_param(&whole[..cut], &mut out);
            // Anything it does manage to read must still be the truth.
            for r in &out {
                assert_eq!(r.value, 128, "a short read invented a capacity");
            }
        }
    }

    /// The header the family answers with is four bytes; an attribute needs
    /// four more. Neither may be assumed present.
    #[test]
    fn a_message_too_short_to_hold_anything_is_refused() {
        let mut out = Vec::new();
        collect_param(&[], &mut out);
        collect_param(&[0u8; GENL_HDR], &mut out);
        collect_param(&[0u8; GENL_HDR + RTATTR_HDR - 1], &mut out);
        assert!(out.is_empty());
    }
}
