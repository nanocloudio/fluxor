//! Scheduler responsibility module (real module boundary; parent statics and
//! helpers reach us via `super`). Each domain's order: the composer's order projected per domain, spliced
//! and unspliced as graphs come and go; and the contract-readiness gate.
use super::*;

/// The contract-readiness gate: a module that requires a contract whose
/// default provider is a deferred-ready MODULE waits for that provider to
/// signal `Ready`, exactly as a module downstream of it on an edge would.
///
/// The edge gate above cannot see this dependency: a consumer reaches its
/// provider through `provider_call`, not a channel. And it matters wherever a
/// provider cannot be ready at construction — a store whose disk mounts only
/// once the graph steps (bare metal: nvme, then fat32, then the store) answers
/// `EAGAIN` until then, and a consumer that subscribes or reads once at its
/// first step concludes it was refused and never asks again.
///
/// Runs after instantiation, when providers have registered (the edge mask
/// is computed before it). Deferred-ready consumers are left ungated, as the
/// edge gate leaves them, so providers that require each other's contracts
/// still step to readiness. `owner`, when given, limits the gates to that
/// owner's modules: a live add never touches a running module's gate.
/// Returns how many consumer→provider gates it set.
pub(crate) fn gate_contract_consumers(owner: Option<OwnerHandle>) -> usize {
    // SAFETY: scheduler-thread context, after instantiation.
    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };
    let mut gated = 0usize;
    // One bit per contract in the first grant word.
    for contract in 0..u64::BITS as usize {
        let Some(provider) = crate::kernel::module::provider::default_module_provider(contract)
        else {
            continue;
        };
        if provider >= module_slots() || !sched.deferred_ready[provider] {
            continue;
        }
        let mut n = 0usize;
        for m in 0..module_slots() {
            if m == provider
                || owner.is_some_and(|o| module_owner(m) != o)
                || sched.deferred_ready[m]
                || sched.grants[m][0] & (1u64 << contract) == 0
            {
                continue;
            }
            sched.upstream_mask[m].set(provider);
            n += 1;
        }
        if n > 0 {
            log::info!(
                "[ready] contract 0x{contract:02x}: {n} consumer(s) wait on provider module {provider}"
            );
            gated += n;
        }
    }
    gated
}

/// Append `slot` to its domain's order (its pre-pass order when it runs
/// there), the composer's order being the order slots are appended in.
/// Returns the domain's bit.
///
/// Boot, single-threaded, or with every peer domain core parked.
pub(crate) fn splice_into_order(slot: usize) -> u32 {
    // SAFETY: scheduler-thread-exclusive; peers parked (the caller's
    // contract).
    let sched = unsafe { &mut *core::ptr::addr_of_mut!(SCHED) };
    let d = (sched.domain_id[slot] as usize).min(MAX_DOMAINS - 1);
    let dom = &mut sched.domains[d];
    if sched.pre_pass[slot] {
        // The splice admitted the domain's pre-pass capacity.
        let p = dom.pre_pass_count as usize;
        if p < MAX_PRE_PASS_PER_DOMAIN {
            dom.pre_pass_order[p] = slot as ModuleId;
            dom.pre_pass_count = (p + 1) as u8;
        }
    } else {
        let c = dom.module_count as usize;
        sched.domain_exec_order[d][c] = slot as ModuleId;
        dom.module_count = (c + 1) as ModuleId;
    }
    1u32 << d
}

/// Drop every slot in `gone` from the orders of the domains in `affected`
/// (bit per domain), keeping the rest in order.
///
/// Single-threaded or with every peer domain core parked.
pub(crate) fn unsplice_from_orders(gone: &ModuleMask, affected: u32) {
    // SAFETY: as `splice_into_order`.
    let sched = unsafe { &mut *core::ptr::addr_of_mut!(SCHED) };
    for d in 0..MAX_DOMAINS {
        if affected & (1u32 << d) == 0 {
            continue;
        }
        let count = sched.domains[d].module_count as usize;
        let mut w = 0usize;
        for r in 0..count {
            let m = sched.domain_exec_order[d][r];
            if gone.test(usize::from(m)) {
                continue;
            }
            sched.domain_exec_order[d][w] = m;
            w += 1;
        }
        sched.domains[d].module_count = w as ModuleId;
        let dom = &mut sched.domains[d];
        let pcount = dom.pre_pass_count as usize;
        let mut w = 0usize;
        for r in 0..pcount {
            let m = dom.pre_pass_order[r];
            if gone.test(usize::from(m)) {
                continue;
            }
            dom.pre_pass_order[w] = m;
            w += 1;
        }
        dom.pre_pass_count = w as u8;
    }
}

/// Rebuild the module masks of the domains in `affected` (bit per domain)
/// over the occupied slots, and grow `domain_count` to cover every occupied
/// domain (it never shrinks).
pub(crate) fn refresh_domains(affected: u32) {
    // SAFETY: as `splice_into_order`.
    let sched = unsafe { &mut *core::ptr::addr_of_mut!(SCHED) };
    for d in 0..MAX_DOMAINS {
        if affected & (1u32 << d) != 0 {
            sched.domains[d].module_mask = ModuleMask::EMPTY;
        }
    }
    let mut max_domain: u8 = 0;
    for i in 0..module_slots() {
        if !slot_resident(sched, i) {
            continue;
        }
        let did = sched.domain_id[i];
        let d = (did as usize).min(MAX_DOMAINS - 1);
        if affected & (1u32 << d) != 0 {
            sched.domains[d].module_mask.set(i);
        }
        max_domain = max_domain.max(did);
    }
    let want = ((max_domain as usize + 1).min(MAX_DOMAINS)) as u8;
    if want > sched.domain_count {
        sched.domain_count = want;
    }
}

/// Log every edge of `edges[base..base + count]` tagged
/// `EdgeClass::DmaOwned`.
///
/// Pure observability: confirms that the YAML-level annotation reached the
/// scheduler edge table. The scheduler does not issue cache maintenance on
/// DmaOwned handoffs — that belongs with zero-copy mailbox edges, where the
/// payload buffer is actually shared between producer and consumer.
/// Streaming-arena buffers live inside the module (see nvme `write_bufs[]`)
/// and do their own DC CVAC via the `DMA_FLUSH` syscall before device
/// submission.
pub fn log_dma_owned_edges(base: usize, count: usize) {
    // SAFETY: scheduler-thread-only read.
    let sched = unsafe { &*core::ptr::addr_of!(SCHED) };
    let mut n = 0usize;
    for e in sched.edges[base..base + count].iter() {
        if let crate::kernel::boot::config::EdgeClass::DmaOwned = e.edge_class {
            log::info!(
                "[sched] DmaOwned edge {}→{} (group={})",
                e.from_module,
                e.to_module,
                e.buffer_group,
            );
            n += 1;
        }
    }
    if n > 0 {
        log::info!("[sched] {n} DmaOwned edges declared (maintenance deferred)");
    }
}
