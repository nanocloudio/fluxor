//! `fluxor-lane-loopback` — the provider the lane's tests drive.
//!
//! Echoes every port record back on the port it came in on, echoes every
//! dynamic-lane record back on its lane with the key in front, and serves
//! the loopback test contract ([`fluxor_host_lane::served::loopback`]). Its
//! argument, `;`-separated words, selects what a test observes:
//! `lie-digest` states another ABI surface digest in its `HELLO`;
//! `require=net_admin` makes `CAP_NET_ADMIN` a capability it cannot serve
//! without; `no-lanes` takes no dynamic lanes.

#![allow(
    clippy::print_stderr,
    reason = "a provider process reports why it stopped on its stderr, the runtime's"
)]

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::os::fd::OwnedFd;
use std::time::Duration;

use fluxor_host_lane::control::{lane, wants, OwnerFact};
use fluxor_host_lane::privilege::cap;
use fluxor_host_lane::provider::{args, Call, Handler, Identity, Outbox, Poll, Provider, Reply};
use fluxor_host_lane::served::loopback;

#[derive(Default)]
struct Loopback {
    next_handle: i32,
    destroyed: u32,
    released: u32,
    last_released: u16,
    held: VecDeque<(usize, Vec<u8>)>,
    /// `(slot, generation, pid, the netlink socket's protocol or -1)`.
    owners: Vec<(u16, u32, u32, i32)>,
    owners_gone: u32,
    /// `(key, draining)`.
    lanes: Vec<(u8, bool)>,
    lane_held: VecDeque<(u8, Vec<u8>)>,
    incarnation: [u8; 16],
}

/// `CapEff`, `CapBnd`, `CapAmb` and `NoNewPrivs` of this process.
fn status_facts(out: &mut String) {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        for key in ["CapEff", "CapBnd", "CapAmb", "NoNewPrivs"] {
            if let Some(v) = line.strip_prefix(key).and_then(|r| r.strip_prefix(':')) {
                let _ = write!(out, "{key}={};", v.trim());
            }
        }
    }
}

impl Handler for Loopback {
    fn call(&mut self, call: &Call<'_>, out: &mut [u8]) -> (i32, usize) {
        match call.opcode {
            loopback::ECHO => (call.arg.len() as i32, call.arg.len()),
            loopback::SLOW => {
                let ms = call
                    .arg
                    .get(..4)
                    .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
                std::thread::sleep(Duration::from_millis(u64::from(ms)));
                (0, 0)
            }
            loopback::MINT => {
                self.next_handle += 1;
                (self.next_handle, 0)
            }
            loopback::DESTROY => {
                self.destroyed += 1;
                (0, 0)
            }
            loopback::TALLY => {
                let mut t = [0u8; 10];
                t[..4].copy_from_slice(&self.destroyed.to_le_bytes());
                t[4..8].copy_from_slice(&self.released.to_le_bytes());
                t[8..10].copy_from_slice(&self.last_released.to_le_bytes());
                let n = t.len().min(out.len());
                out[..n].copy_from_slice(&t[..n]);
                (10, n)
            }
            loopback::FACTS => {
                let mut f = String::new();
                for &(s, g, pid, proto) in &self.owners {
                    let _ = write!(f, "owner={s}.{g}:{pid}:{proto};");
                }
                let _ = write!(f, "gone={};", self.owners_gone);
                for &(k, d) in &self.lanes {
                    let _ = write!(f, "lane={k}{};", if d { ":drain" } else { "" });
                }
                let inc: String = self
                    .incarnation
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                let _ = write!(f, "inc={inc};");
                status_facts(&mut f);
                let n = f.len().min(out.len());
                out[..n].copy_from_slice(&f.as_bytes()[..n]);
                (n as i32, n)
            }
            _ => (fluxor_abi::errno::ENOSYS, 0),
        }
    }

    fn call_data(&mut self, call: &Call<'_>, out: &mut [u8], data: &mut [u8]) -> Reply {
        match call.opcode {
            loopback::SUM => {
                let sum = call
                    .data
                    .iter()
                    .fold(0u32, |a, &b| a.wrapping_add(u32::from(b)));
                let len = (call.data.len() as u32).to_le_bytes();
                let n = out.len().min(4);
                out[..n].copy_from_slice(&len[..n]);
                Reply {
                    rc: (sum & 0x7FFF_FFFF) as i32,
                    out_len: n,
                    data_len: 0,
                }
            }
            loopback::FILL => {
                let want = call
                    .arg
                    .get(..4)
                    .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                    as usize;
                let seed = call.arg.get(4).copied().unwrap_or(0);
                let n = want.min(data.len());
                for (i, b) in data[..n].iter_mut().enumerate() {
                    *b = seed.wrapping_add(i as u8);
                }
                let rc = if want > data.len() {
                    fluxor_abi::errno::ERANGE
                } else {
                    want as i32
                };
                Reply {
                    rc,
                    out_len: 0,
                    data_len: want,
                }
            }
            loopback::XOR => {
                let k = call.arg.first().copied().unwrap_or(0);
                for b in data.iter_mut() {
                    *b ^= k;
                }
                Reply {
                    rc: data.len() as i32,
                    out_len: 0,
                    data_len: data.len(),
                }
            }
            _ => {
                let (rc, out_len) = self.call(call, out);
                Reply {
                    rc,
                    out_len,
                    data_len: 0,
                }
            }
        }
    }

    fn record(&mut self, i: usize, rec: &[u8], out: &mut Outbox<'_>) {
        if !self.held.is_empty() || out.send(i, rec).is_err() {
            self.held.push_back((i, rec.to_vec()));
        }
    }

    fn released(&mut self, slot: u16, _generation: u32) {
        self.released += 1;
        self.last_released = slot;
    }

    fn owner(&mut self, fact: OwnerFact, netlink: Option<OwnedFd>) {
        let proto = netlink
            .as_ref()
            .and_then(fluxor_host_lane::control::socket_protocol)
            .unwrap_or(-1);
        self.owners
            .retain(|&(s, g, ..)| (s, g) != (fact.slot, fact.generation));
        self.owners
            .push((fact.slot, fact.generation, fact.pid, proto));
    }

    fn owner_gone(&mut self, slot: u16, generation: u32) {
        self.owners_gone += 1;
        self.owners
            .retain(|&(s, g, ..)| (s, g) != (slot, generation));
    }

    fn lane(&mut self, op: u8, key: u8, _owner_slot: u16, _owner_generation: u32) {
        match op {
            lane::ADD => self.lanes.push((key, false)),
            lane::DEL => {
                self.lanes.retain(|&(k, _)| k != key);
                self.lane_held.retain(|(k, _)| *k != key);
            }
            lane::DRAIN => {
                if let Some(l) = self.lanes.iter_mut().find(|l| l.0 == key) {
                    l.1 = true;
                }
            }
            _ => {}
        }
    }

    fn lane_record(&mut self, key: u8, rec: &[u8], out: &mut Outbox<'_>) {
        let mut back = Vec::with_capacity(rec.len() + 1);
        back.push(key);
        back.extend_from_slice(rec);
        if !self.lane_held.is_empty() || out.lane_send(key, &back).is_err() {
            self.lane_held.push_back((key, back));
        }
    }

    fn poll(&mut self, out: &mut Outbox<'_>) -> Poll {
        while let Some((i, rec)) = self.held.front() {
            if out.send(*i, rec).is_err() {
                break;
            }
            self.held.pop_front();
        }
        while let Some((k, rec)) = self.lane_held.front() {
            if out.lane_send(*k, rec).is_err() {
                break;
            }
            self.lane_held.pop_front();
        }
        if self.held.is_empty() && self.lane_held.is_empty() {
            Poll::Idle
        } else {
            Poll::Holding
        }
    }
}

fn main() {
    let a = args();
    let words: Vec<&str> = a.split(';').map(str::trim).collect();
    let mut digest = fluxor_host_lane::ABI_SURFACE_DIGEST;
    if words.contains(&"lie-digest") {
        digest[0] ^= 0xFF;
    }
    let requires: &[u32] = if words.contains(&"require=net_admin") {
        &[cap::NET_ADMIN]
    } else {
        &[]
    };
    let takes = if words.contains(&"no-lanes") {
        wants::OWNERS
    } else {
        wants::OWNERS | wants::LANES
    };
    let id = Identity {
        contracts: &[loopback::CONTRACT],
        ports: loopback::PORTS,
        requires_caps: requires,
        wants: takes,
    };
    let mut p = match Provider::connect(&id, digest) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("fluxor-lane-loopback: {e}");
            std::process::exit(2);
        }
    };
    let mut h = Loopback {
        incarnation: p.incarnation(),
        ..Loopback::default()
    };
    if let Err(e) = p.serve(&mut h) {
        eprintln!("fluxor-lane-loopback: {e}");
        std::process::exit(1);
    }
}
