//! Held addresses (`net.route` HOLD): addresses the node answers for on its
//! uplink, realized here.
//!
//! Only `deliver` mode is realized on bare metal — the node accepts traffic
//! to the address as its own, for node-terminated services. `announce`
//! (answering for an address and routing it on to workloads) is refused
//! `unsupported`, as is an address off the primary's link; one another
//! identity already holds is refused `conflict`, and one the address table
//! has no room for `table_full`.
//!
//! A held address is installed into the address table as a node-owned
//! secondary, armed or fenced as the writer asks, with the token this module
//! minted for it kept here: no coordinator holds it, because on a workload
//! node the kernel is `addr_ctl`'s only writer. Fencing closes the emission
//! gate as an `ADDR_FENCE` does, and the evidence — the install generation,
//! the frame count at the cutoff, and whether that cutoff is the wire (the
//! driver answered that everything handed over has left the NIC) or only the
//! ring hand-off — goes back with the entry's state through `REPORT`.

use super::*;
use abi::contracts::net::route as nr;

/// Whether held entry `h` is one this module realizes, and if not why.
fn realizable(s: &IpState, h: &nr::Held) -> Result<u32, u8> {
    if h.family != nr::FAM_IPV4 || h.mode != nr::held::MODE_DELIVER {
        return Err(nr::reason::UNSUPPORTED);
    }
    let ip = route::ip_of(&h.addr);
    if ip == 0 || s.local_ip == 0 || !route::on_link(s, ip) {
        return Err(nr::reason::UNSUPPORTED);
    }
    Ok(ip)
}

/// Bring the address table in line with the held-address table: install
/// what is new, arm and fence as asked, remove what is gone.
pub(crate) unsafe fn realize(s: &mut IpState) {
    // Gone from the table: removed.
    let mut i = 1;
    while i < MAX_LOCAL_ADDRS {
        let a = s.local_addrs[i];
        if a.is_active() && a.flags & ADDR_FLAG_HELD != 0 {
            let ip = a.ipv4();
            let mut wanted = false;
            for h in route::held(s) {
                if realizable(s, h) == Ok(ip) {
                    wanted = true;
                }
            }
            if !wanted {
                addr_ctl_del(s, ip);
            }
        }
        i += 1;
    }
    let n = s.rt_nheld as usize;
    let mut j = 0;
    while j < n {
        let h = *s.rt_held.add(j);
        j += 1;
        let Ok(ip) = realizable(s, &h) else { continue };
        let armed = h.state_req == nr::held::ARMED;
        match local_slot_for_dst(s, ip) {
            None => install(s, ip, armed),
            Some(slot) if slot != 0 && s.local_addrs[slot as usize].flags & ADDR_FLAG_HELD != 0 => {
                let is_armed = s.local_addrs[slot as usize].flags & ADDR_FLAG_ARMED != 0;
                if armed && !is_armed {
                    arm(s, slot as usize);
                } else if !armed && is_armed {
                    fence(s, slot as usize);
                }
            }
            // Another identity's address: a conflict, reported.
            Some(_) => {}
        }
    }
}

/// Whether every secondary address slot is taken.
fn addr_table_full(s: &IpState) -> bool {
    let mut i = 1;
    while i < MAX_LOCAL_ADDRS {
        if !s.local_addrs[i].is_active() {
            return false;
        }
        i += 1;
    }
    true
}

/// Install `ip` as a held, node-owned address.
unsafe fn install(s: &mut IpState, ip: u32, armed: bool) {
    let mut i = 1;
    while i < MAX_LOCAL_ADDRS && s.local_addrs[i].is_active() {
        i += 1;
    }
    if i >= MAX_LOCAL_ADDRS {
        // Reported `table_full` (`entry_state`).
        return;
    }
    let Some(token) = mint_token(s) else {
        return;
    };
    s.addr_generation = s.addr_generation.wrapping_add(1);
    s.addr_epoch = s.addr_epoch.wrapping_add(1).max(1);
    let a = &mut s.local_addrs[i];
    *a = LocalAddr::empty();
    a.set_ipv4(ip);
    a.token = token;
    a.generation = s.addr_generation;
    a.prefix_len = 32;
    a.owner_tag = 0;
    a.flags = ADDR_FLAG_HELD | if armed { ADDR_FLAG_ARMED } else { 0 };
    if !armed {
        // Installed fenced: nothing ever left from it.
        a.fence_kind = netid::cutoff::WIRE;
        a.fence_cutoff = u64::from(s.tx_frame_count);
    }
    let _ = index::insert(&mut s.addr_index, index::mix32(ip ^ s.index_seed), i);
    log_info(s, b"[ip] held address installed");
    if armed {
        send_gratuitous_arp(s, ip);
    }
}

unsafe fn arm(s: &mut IpState, slot: usize) {
    let a = &mut s.local_addrs[slot];
    a.flags |= ADDR_FLAG_ARMED;
    a.fence_kind = 0;
    a.fence_cutoff = 0;
    let ip = a.ipv4();
    log_info(s, b"[ip] held address armed");
    send_gratuitous_arp(s, ip);
}

/// Close the emission gate for held slot `slot` and start settling its
/// evidence: the wire when the driver answers the drain, the ring hand-off
/// when it cannot or the wait runs out.
unsafe fn fence(s: &mut IpState, slot: usize) {
    s.local_addrs[slot].flags &= !ADDR_FLAG_ARMED;
    if s.pending_tx_len > 0 {
        let f = s.pending_tx_buf.as_ptr().add(2);
        let flen = s.pending_tx_len as usize - 2;
        if !emission_allowed(s, f, flen) {
            s.pending_tx_len = 0;
            s.tx_fenced = s.tx_fenced.wrapping_add(1);
        }
    }
    let a = &mut s.local_addrs[slot];
    a.fence_kind = FENCE_OPEN;
    a.fence_deadline_ms = (dev_millis(&*s.syscalls) as u32)
        .wrapping_add(FENCE_WIRE_WAIT_MS)
        .max(1);
    log_info(s, b"[ip] held address fenced");
    settle(s, slot);
}

/// Settle an open fence's evidence, if it can be now. `true` when it was.
unsafe fn settle(s: &mut IpState, slot: usize) -> bool {
    let now = dev_millis(&*s.syscalls) as u32;
    let expired = now.wrapping_sub(s.local_addrs[slot].fence_deadline_ms) < 0x8000_0000;
    let (cut, kind) = match driver_tx_drained(s) {
        DrainAnswer::Drained(i) => (i, netid::cutoff::WIRE),
        DrainAnswer::Draining if !expired => return false,
        _ => {
            s.fence_ring_handoff = s.fence_ring_handoff.wrapping_add(1);
            (u64::from(s.tx_frame_count), netid::cutoff::RING_HANDOFF)
        }
    };
    let a = &mut s.local_addrs[slot];
    a.fence_cutoff = cut;
    a.fence_kind = kind;
    true
}

/// Settle open fences, and report when one settles.
pub(crate) unsafe fn step(s: &mut IpState) {
    if s.rt_nheld == 0 {
        return;
    }
    let mut settled = false;
    let n = s.rt_nheld as usize;
    let mut j = 0;
    while j < n {
        let h = *s.rt_held.add(j);
        j += 1;
        let Ok(ip) = realizable(s, &h) else { continue };
        if let Some(slot) = local_slot_for_dst(s, ip) {
            let slot = slot as usize;
            if slot != 0
                && s.local_addrs[slot].flags & ADDR_FLAG_HELD != 0
                && s.local_addrs[slot].fence_kind == FENCE_OPEN
                && settle(s, slot)
            {
                settled = true;
            }
        }
    }
    if settled {
        route::report(s);
    }
}

/// Held entry `i`'s state and evidence, for `REPORT`.
pub(crate) unsafe fn entry_state(s: &IpState, i: usize) -> nr::EntryState {
    let mut e = nr::EntryState {
        kind: nr::entry::KIND_HELD,
        state: nr::state::PENDING,
        reason: nr::reason::NONE,
        cutoff_kind: 0,
        index: i as u16,
        install_gen: 0,
        cutoff: 0,
    };
    if i >= s.rt_nheld as usize {
        return e;
    }
    let h = *s.rt_held.add(i);
    let ip = match realizable(s, &h) {
        Ok(ip) => ip,
        Err(why) => {
            e.state = nr::state::REFUSED;
            e.reason = why;
            return e;
        }
    };
    let Some(slot) = local_slot_for_dst(s, ip) else {
        // Not installed: the address table had no room for it, or it is
        // still to be (no token could be minted yet).
        if addr_table_full(s) {
            e.state = nr::state::REFUSED;
            e.reason = nr::reason::TABLE_FULL;
        }
        return e;
    };
    let a = &s.local_addrs[slot as usize];
    if slot == 0 || a.flags & ADDR_FLAG_HELD == 0 {
        e.state = nr::state::REFUSED;
        e.reason = nr::reason::CONFLICT;
        return e;
    }
    e.install_gen = a.generation;
    if a.flags & ADDR_FLAG_ARMED != 0 {
        e.state = nr::state::REALIZED;
    } else if a.fence_kind != FENCE_OPEN {
        e.state = nr::state::FENCED;
        e.cutoff = a.fence_cutoff;
        e.cutoff_kind = a.fence_kind;
    }
    e
}
