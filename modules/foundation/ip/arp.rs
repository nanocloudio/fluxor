//! ARP protocol — address resolution for IPv4 over Ethernet.
//!
//! Maintains a small ARP table and handles request/reply.
//! All array access uses raw pointer arithmetic to avoid
//! panic_bounds_check in PIC modules.

use super::eth;

/// ARP header length (hardware type through target protocol addr)
pub const ARP_HEADER_LEN: usize = 28;

/// ARP opcodes
pub const ARP_REQUEST: u16 = 1;
pub const ARP_REPLY: u16 = 2;

/// ARP table entry
#[derive(Clone, Copy)]
pub struct ArpEntry {
    pub ip: u32,
    pub mac: [u8; 6],
    pub valid: bool,
    /// Age in step counts (for eviction)
    pub age: u16,
    /// Pinned by active TCP connection — rejects MAC changes while pinned
    pub pinned: bool,
    /// Number of connections using this entry (0 = unpinned, 255 = permanent)
    pub pin_count: u8,
    /// Step count of last MAC change (for rate limiting)
    pub last_update: u16,
    /// Set when a permanent pin has outlived `ARP_PIN_REVALIDATE_AGE` and
    /// must be reconfirmed by a fresh ARP exchange. Permanent pins are
    /// exempt from ordinary expiry, so without this they would never be
    /// re-checked against the segment.
    pub revalidate: bool,
}

/// Minimum steps between MAC address changes for a given IP (rate limiting).
/// Default ~2 minutes at 20ms step rate = 6000 ticks.
pub const ARP_UPDATE_COOLDOWN: u16 = 6000;

impl ArpEntry {
    pub const fn empty() -> Self {
        Self {
            ip: 0,
            mac: [0; 6],
            valid: false,
            age: 0,
            pinned: false,
            pin_count: 0,
            last_update: 0,
            revalidate: false,
        }
    }
}

/// ARP table size
pub const ARP_TABLE_SIZE: usize = 16;

/// ARP pending request state
pub const ARP_PENDING_NONE: u8 = 0;
pub const ARP_PENDING_WAITING: u8 = 1;

/// Look up MAC address for an IPv4 address.
/// Returns Some(mac) if found, None if not in table.
///
/// # Safety
/// Uses raw pointer access to avoid bounds checks in PIC.
pub fn lookup(table: &[ArpEntry; ARP_TABLE_SIZE], ip: u32) -> Option<[u8; 6]> {
    // SAFETY: `i < ARP_TABLE_SIZE` is the loop invariant; `table.as_ptr().add(i)`
    // therefore points into the fixed-size array. `&*` materialises a shared
    // reference that lives only for the iteration.
    unsafe {
        let mut i = 0;
        while i < ARP_TABLE_SIZE {
            let entry = &*table.as_ptr().add(i);
            if entry.valid && entry.ip == ip {
                return Some(entry.mac);
            }
            i += 1;
        }
    }
    None
}

/// Refresh an existing mapping whose MAC is unchanged.
///
/// This is the only ARP-table mutation ordinary IPv4 traffic is allowed to
/// perform. It keeps a busy peer's entry from aging out without letting
/// unauthenticated L3 traffic install a mapping or move one to a new MAC —
/// those require a correlated ARP exchange (see [`insert`]).
///
/// Returns `true` iff a matching entry was found and refreshed; `false`
/// means the caller observed a mapping it is not permitted to create or
/// change.
pub fn refresh_same_mac(table: &mut [ArpEntry; ARP_TABLE_SIZE], ip: u32, mac: [u8; 6]) -> bool {
    // SAFETY: `i < ARP_TABLE_SIZE` bounds every `add(i)` into the fixed-size
    // array; the unique re-borrow is safe because the loop holds no other
    // live reference into `table`.
    unsafe {
        let mut i = 0;
        while i < ARP_TABLE_SIZE {
            let entry = &mut *table.as_mut_ptr().add(i);
            if entry.valid && entry.ip == ip {
                if entry.mac == mac {
                    entry.age = 0;
                    return true;
                }
                return false;
            }
            i += 1;
        }
    }
    false
}

/// Invalidate the entry for `ip`, if any. Used to force a fresh resolution
/// before a mapping is granted elevated status.
pub fn invalidate(table: &mut [ArpEntry; ARP_TABLE_SIZE], ip: u32) {
    // SAFETY: as for `refresh_same_mac`.
    unsafe {
        let mut i = 0;
        while i < ARP_TABLE_SIZE {
            let entry = &mut *table.as_mut_ptr().add(i);
            if entry.valid && entry.ip == ip {
                *entry = ArpEntry::empty();
                return;
            }
            i += 1;
        }
    }
}

/// Report whether a MAC change for `ip` would be refused by a pin. Lets the
/// caller distinguish "the segment moved and we rejected it" from an
/// ordinary cache miss in its metrics.
pub fn pin_would_reject(table: &[ArpEntry; ARP_TABLE_SIZE], ip: u32, mac: [u8; 6]) -> bool {
    // SAFETY: as for `refresh_same_mac`; shared borrow only.
    unsafe {
        let mut i = 0;
        while i < ARP_TABLE_SIZE {
            let entry = &*table.as_ptr().add(i);
            if entry.valid && entry.ip == ip {
                return entry.pinned && entry.mac != mac;
            }
            i += 1;
        }
    }
    false
}

/// Insert or update an ARP table entry from a correlated ARP exchange.
/// Respects pinning (active TCP connections) and rate limiting.
///
/// # Safety
/// Uses raw pointer access to avoid bounds checks in PIC.
pub fn insert(table: &mut [ArpEntry; ARP_TABLE_SIZE], ip: u32, mac: [u8; 6], step_count: u16) {
    // SAFETY: every `add(i)` is bounded by `i < ARP_TABLE_SIZE`. The `&mut *`
    // re-borrow is unique because the loop holds no other live reference into
    // `table`. `oldest_idx` is sentinel-checked against `ARP_TABLE_SIZE`
    // before the eviction-slot write.
    unsafe {
        // Check if already exists
        let mut i = 0;
        while i < ARP_TABLE_SIZE {
            let entry = &mut *table.as_mut_ptr().add(i);
            if entry.valid && entry.ip == ip {
                // If MAC is unchanged, refresh age and clear any outstanding
                // revalidation — the segment has just reconfirmed the entry.
                if entry.mac == mac {
                    entry.age = 0;
                    entry.revalidate = false;
                    return;
                }
                // Reject MAC change if entry is pinned (active TCP connection)
                if entry.pinned {
                    return;
                }
                // Rate-limit MAC changes
                let elapsed = step_count.wrapping_sub(entry.last_update);
                if elapsed < ARP_UPDATE_COOLDOWN {
                    return; // reject rapid MAC changes
                }
                entry.mac = mac;
                entry.age = 0;
                entry.last_update = step_count;
                return;
            }
            i += 1;
        }

        // Find empty slot
        i = 0;
        while i < ARP_TABLE_SIZE {
            let entry = &*table.as_ptr().add(i);
            if !entry.valid {
                *table.as_mut_ptr().add(i) = ArpEntry {
                    ip,
                    mac,
                    valid: true,
                    age: 0,
                    pinned: false,
                    pin_count: 0,
                    last_update: step_count,
                    revalidate: false,
                };
                return;
            }
            i += 1;
        }

        // Evict oldest non-pinned entry
        let mut oldest_idx: usize = ARP_TABLE_SIZE; // sentinel: no candidate
        let mut oldest_age = 0u16;
        i = 0;
        while i < ARP_TABLE_SIZE {
            let entry = &*table.as_ptr().add(i);
            if !entry.pinned && entry.age > oldest_age {
                oldest_age = entry.age;
                oldest_idx = i;
            }
            i += 1;
        }
        if oldest_idx < ARP_TABLE_SIZE {
            *table.as_mut_ptr().add(oldest_idx) = ArpEntry {
                ip,
                mac,
                valid: true,
                age: 0,
                pinned: false,
                pin_count: 0,
                last_update: step_count,
                revalidate: false,
            };
        }
        // If all entries are pinned, drop the new entry (defence: don't evict pinned)
    }
}

/// Pin an ARP entry for the given IP (called when TCP connection established).
pub fn pin(table: &mut [ArpEntry; ARP_TABLE_SIZE], ip: u32) {
    // SAFETY: `i < ARP_TABLE_SIZE` bounds every `add(i)` into the fixed-size
    // array; the unique re-borrow is safe because the loop holds no other
    // live reference into `table`.
    unsafe {
        let mut i = 0;
        while i < ARP_TABLE_SIZE {
            let entry = &mut *table.as_mut_ptr().add(i);
            if entry.valid && entry.ip == ip {
                entry.pinned = true;
                entry.pin_count = entry.pin_count.saturating_add(1);
                return;
            }
            i += 1;
        }
    }
}

/// Unpin an ARP entry (called when TCP connection closed).
pub fn unpin(table: &mut [ArpEntry; ARP_TABLE_SIZE], ip: u32) {
    // SAFETY: `i < ARP_TABLE_SIZE` bounds every `add(i)` into the fixed-size
    // array; the unique re-borrow is safe because the loop holds no other
    // live reference into `table`.
    unsafe {
        let mut i = 0;
        while i < ARP_TABLE_SIZE {
            let entry = &mut *table.as_mut_ptr().add(i);
            if entry.valid && entry.ip == ip && entry.pin_count > 0 && entry.pin_count < 255 {
                entry.pin_count -= 1;
                if entry.pin_count == 0 {
                    entry.pinned = false;
                }
                return;
            }
            i += 1;
        }
    }
}

/// Permanently pin the gateway ARP entry (set pin_count = 255).
///
/// Callers must resolve `ip` afresh first: pinning is what makes a mapping
/// immune to later MAC changes, so promoting an entry that was already in
/// the cache would make whatever installed it authoritative for the rest of
/// the lease. Returns `true` iff an entry was found and pinned.
pub fn pin_gateway(table: &mut [ArpEntry; ARP_TABLE_SIZE], ip: u32) -> bool {
    // SAFETY: `i < ARP_TABLE_SIZE` bounds every `add(i)` into the fixed-size
    // array; the unique re-borrow is safe because the loop holds no other
    // live reference into `table`.
    unsafe {
        let mut i = 0;
        while i < ARP_TABLE_SIZE {
            let entry = &mut *table.as_mut_ptr().add(i);
            if entry.valid && entry.ip == ip {
                entry.pinned = true;
                entry.pin_count = 255; // permanent
                entry.revalidate = false;
                entry.age = 0;
                return true;
            }
            i += 1;
        }
    }
    false
}

/// Steps a permanent pin may go unconfirmed before it must be reconfirmed by
/// a fresh ARP exchange. Permanent pins are exempt from ordinary expiry, so
/// without an explicit revalidation term a pin taken once at lease time
/// would stay authoritative for the life of the boot.
pub const ARP_PIN_REVALIDATE_AGE: u16 = 12000;

/// Address of an entry needing revalidation, or `None`.
pub fn revalidation_due(table: &[ArpEntry; ARP_TABLE_SIZE]) -> Option<u32> {
    // SAFETY: `i < ARP_TABLE_SIZE` bounds every `add(i)`; shared borrow only.
    unsafe {
        let mut i = 0;
        while i < ARP_TABLE_SIZE {
            let entry = &*table.as_ptr().add(i);
            if entry.valid && entry.revalidate {
                return Some(entry.ip);
            }
            i += 1;
        }
    }
    None
}

/// Age all ARP table entries (call periodically). Returns the number of
/// permanent pins that entered revalidation on this pass.
///
/// # Safety
/// Uses raw pointer access to avoid bounds checks in PIC.
pub fn age_entries(table: &mut [ArpEntry; ARP_TABLE_SIZE]) -> u32 {
    let mut revalidations = 0u32;
    // SAFETY: `i < ARP_TABLE_SIZE` bounds every `add(i)` into the fixed-size
    // array; the unique re-borrow is safe because the loop holds no other
    // live reference into `table`.
    unsafe {
        let mut i = 0;
        while i < ARP_TABLE_SIZE {
            let entry = &mut *table.as_mut_ptr().add(i);
            if entry.valid {
                entry.age = entry.age.saturating_add(1);
                if entry.pin_count == 255 {
                    // Permanent: never expires, but must be reconfirmed.
                    if entry.age > ARP_PIN_REVALIDATE_AGE && !entry.revalidate {
                        entry.revalidate = true;
                        revalidations += 1;
                    }
                } else if entry.age > 15000 {
                    // Expire ordinary entries after ~5 minutes (at ~20ms step
                    // rate = 15000 steps).
                    entry.valid = false;
                }
            }
            i += 1;
        }
    }
    revalidations
}

/// How many table slots hold a live mapping. What a unicast send resolves
/// against comes from this table and nowhere else, so its occupancy is the
/// one number that separates "nothing has been learned" from "the wrong
/// thing was learned".
pub fn live_entries(table: &[ArpEntry; ARP_TABLE_SIZE]) -> u32 {
    let mut live = 0u32;
    // SAFETY: `i < ARP_TABLE_SIZE` bounds every `add(i)` into the
    // fixed-size array.
    unsafe {
        let mut i = 0;
        while i < ARP_TABLE_SIZE {
            if (*table.as_ptr().add(i)).valid {
                live += 1;
            }
            i += 1;
        }
    }
    live
}

/// A parsed ARP packet. `target_mac` is retained because correlating a reply
/// needs the whole addressing quad, not just the sender's claim.
pub struct ArpPacket {
    pub opcode: u16,
    pub sender_ip: u32,
    pub sender_mac: [u8; 6],
    pub target_ip: u32,
    pub target_mac: [u8; 6],
}

/// Parse an ARP packet.
///
/// # Safety
/// `data` must point to at least `len` valid bytes of ARP payload (after eth header).
pub unsafe fn parse_arp(data: *const u8, len: usize) -> Option<ArpPacket> {
    if len < ARP_HEADER_LEN {
        return None;
    }

    // Hardware type must be Ethernet (1)
    let hw_type = (*data as u16) << 8 | (*data.add(1) as u16);
    if hw_type != 1 {
        return None;
    }

    // Protocol type must be IPv4 (0x0800)
    let proto_type = (*data.add(2) as u16) << 8 | (*data.add(3) as u16);
    if proto_type != eth::ETHERTYPE_IPV4 {
        return None;
    }

    // Hardware addr len = 6, protocol addr len = 4
    if *data.add(4) != 6 || *data.add(5) != 4 {
        return None;
    }

    let opcode = (*data.add(6) as u16) << 8 | (*data.add(7) as u16);

    // Sender hardware address (MAC) at offset 8
    let mut sender_mac = [0u8; 6];
    let mut i = 0;
    while i < 6 {
        *sender_mac.as_mut_ptr().add(i) = *data.add(8 + i);
        i += 1;
    }

    // Sender protocol address (IP) at offset 14
    let sender_ip =
        u32::from_be_bytes([*data.add(14), *data.add(15), *data.add(16), *data.add(17)]);

    // Target hardware address (MAC) at offset 18
    let mut target_mac = [0u8; 6];
    i = 0;
    while i < 6 {
        *target_mac.as_mut_ptr().add(i) = *data.add(18 + i);
        i += 1;
    }

    // Target protocol address (IP) at offset 24
    let target_ip =
        u32::from_be_bytes([*data.add(24), *data.add(25), *data.add(26), *data.add(27)]);

    Some(ArpPacket {
        opcode,
        sender_ip,
        sender_mac,
        target_ip,
        target_mac,
    })
}

/// Build an ARP reply or request in `buf`.
/// Returns total frame length (eth header + ARP).
///
/// # Safety
/// `buf` must point to at least `ETH_HEADER_LEN + ARP_HEADER_LEN` writable bytes.
pub unsafe fn build_arp(
    buf: *mut u8,
    opcode: u16,
    src_mac: &[u8; 6],
    src_ip: u32,
    dst_mac: &[u8; 6],
    dst_ip: u32,
) -> usize {
    // Ethernet header
    let eth_dst = if opcode == ARP_REQUEST {
        &eth::BROADCAST_MAC
    } else {
        dst_mac
    };
    eth::build_eth_header(buf, eth_dst, src_mac, eth::ETHERTYPE_ARP);

    let p = buf.add(eth::ETH_HEADER_LEN);

    // All stores use write_volatile to prevent LLVM from merging them into
    // word stores with constants from .rodata (PIC relocation issue on aarch64).
    use core::ptr::write_volatile;

    // Hardware type: Ethernet (1)
    write_volatile(p.add(0), 0x00u8);
    write_volatile(p.add(1), 0x01u8);
    // Protocol type: IPv4
    write_volatile(p.add(2), 0x08u8);
    write_volatile(p.add(3), 0x00u8);
    // Hardware addr len, protocol addr len
    write_volatile(p.add(4), 6u8);
    write_volatile(p.add(5), 4u8);
    // Opcode
    write_volatile(p.add(6), (opcode >> 8) as u8);
    write_volatile(p.add(7), (opcode & 0xFF) as u8);

    // Sender hardware address
    let mut i = 0;
    while i < 6 {
        write_volatile(
            p.add(8 + i),
            core::ptr::read_volatile(src_mac.as_ptr().add(i)),
        );
        i += 1;
    }

    // Sender protocol address
    let src_ip_bytes = src_ip.to_be_bytes();
    write_volatile(p.add(14), src_ip_bytes[0]);
    write_volatile(p.add(15), src_ip_bytes[1]);
    write_volatile(p.add(16), src_ip_bytes[2]);
    write_volatile(p.add(17), src_ip_bytes[3]);

    // Target hardware address
    i = 0;
    while i < 6 {
        write_volatile(
            p.add(18 + i),
            core::ptr::read_volatile(dst_mac.as_ptr().add(i)),
        );
        i += 1;
    }

    // Target protocol address
    let dst_ip_bytes = dst_ip.to_be_bytes();
    write_volatile(p.add(24), dst_ip_bytes[0]);
    write_volatile(p.add(25), dst_ip_bytes[1]);
    write_volatile(p.add(26), dst_ip_bytes[2]);
    write_volatile(p.add(27), dst_ip_bytes[3]);

    eth::ETH_HEADER_LEN + ARP_HEADER_LEN
}
