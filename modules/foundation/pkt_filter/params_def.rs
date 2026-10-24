use super::SCHEMA_MAX;
use super::{flows, p_u16, p_u8, FilterState, MAX_RULES};

/// Apply static rule `idx` from its six bytes
/// `[action][proto][port_lo:u16 LE][port_hi:u16 LE]`.
unsafe fn set_rule(s: &mut FilterState, idx: usize, d: *const u8, len: usize) {
    if idx >= MAX_RULES || len < 6 {
        return;
    }
    let lo = p_u16(d, len, 2, 0);
    let hi = p_u16(d, len, 4, 0);
    if let Some(r) = s.rules.get_mut(idx) {
        r.action = p_u8(d, len, 0, 1);
        r.proto_match = p_u8(d, len, 1, 0);
        r.dst_port_lo = lo;
        r.dst_port_hi = if hi == 0 { lo } else { hi };
        r._reserved = 0;
    }
}

define_params! {
    FilterState;

    // Static mode: the rules in force (at most eight), and what a frame no
    // rule matches meets.
    1, rule_count, u8, 0
        => |s, d, len| {
            let v = p_u8(d, len, 0, 0);
            s.rule_count = if v as usize > MAX_RULES { MAX_RULES as u8 } else { v };
        };
    2, default_action, u8, 1, enum { drop=0, accept=1 }
        => |s, d, len| { s.default_action = p_u8(d, len, 0, 1); };
    // net.policy mode: the table this instance enforces.
    3, table, str, 0
        => |s, d, len| {
            let n = if len > s.table.len() { s.table.len() } else { len };
            let mut i = 0usize;
            while i < n {
                if let Some(b) = s.table.get_mut(i) {
                    *b = *d.add(i);
                }
                i += 1;
            }
            s.table_len = n as u8;
        };
    // Flows the table records at once (net.policy mode): sized into the
    // module heap at construction.
    4, max_flows, u16, flows::FLOWS_DEFAULT
        => |s, d, len| { s.max_flows = p_u16(d, len, 0, flows::FLOWS_DEFAULT); };
    10, rule_0, blob, 0 => |s, d, len| { set_rule(s, 0, d, len); };
    11, rule_1, blob, 0 => |s, d, len| { set_rule(s, 1, d, len); };
    12, rule_2, blob, 0 => |s, d, len| { set_rule(s, 2, d, len); };
    13, rule_3, blob, 0 => |s, d, len| { set_rule(s, 3, d, len); };
    14, rule_4, blob, 0 => |s, d, len| { set_rule(s, 4, d, len); };
    15, rule_5, blob, 0 => |s, d, len| { set_rule(s, 5, d, len); };
    16, rule_6, blob, 0 => |s, d, len| { set_rule(s, 6, d, len); };
    17, rule_7, blob, 0 => |s, d, len| { set_rule(s, 7, d, len); };
}
