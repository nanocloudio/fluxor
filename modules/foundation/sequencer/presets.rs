//! Preset loading for the sequencer.

use super::{Sequencer, MAX_SEQUENCE_LEN, MAX_PRESETS, MAX_PRESET_LEN};

/// Load presets from params into preset storage.
pub unsafe fn init_from_params(seq: &mut Sequencer, params: *const u8, params_len: usize, preset_count: u8) {
    seq.preset_count = preset_count;

    let lengths_ptr = seq.preset_lengths.as_mut_ptr();
    let values_base = seq.preset_values.as_mut_ptr() as *mut u16;

    // Read preset lengths from params[8..8+preset_count]
    for i in 0..preset_count as usize {
        let plen = (*params.add(8 + i)).min(MAX_PRESET_LEN as u8);
        core::ptr::write_volatile(lengths_ptr.add(i), plen);
    }

    // Read preset values starting after the lengths block
    let mut param_offset = 8 + preset_count as usize;
    for i in 0..preset_count as usize {
        let plen = *lengths_ptr.add(i) as usize;
        for j in 0..plen {
            if param_offset + 2 <= params_len {
                let p = params.add(param_offset);
                let val = u16::from_le_bytes([*p, *p.add(1)]);
                core::ptr::write_volatile(values_base.add(i * MAX_PRESET_LEN + j), val);
                param_offset += 2;
            }
        }
    }
}

/// Load a preset into the sequencer's active sequence.
pub unsafe fn load_preset(seq: &mut Sequencer, preset_index: u8) {
    if seq.preset_count == 0 {
        return;
    }

    let index = (preset_index as usize) % (seq.preset_count as usize);
    let plen = *seq.preset_lengths.as_ptr().add(index) as usize;

    let values_ptr = seq.values.as_mut_ptr();
    let preset_ptr = seq.preset_values.as_ptr().add(index) as *const u16;
    let copy_len = if plen < MAX_SEQUENCE_LEN { plen } else { MAX_SEQUENCE_LEN };
    for i in 0..copy_len {
        core::ptr::write_volatile(values_ptr.add(i), *preset_ptr.add(i));
    }
    seq.length = plen as u8;

    seq.current_preset = index as u8;
    seq.position = 0;
    seq.direction = 1;
    seq.current_value = if plen > 0 { *preset_ptr } else { 0 };
    seq.last_value_sent = 0xFFFF; // Force resend
}
