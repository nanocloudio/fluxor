//! Preset loading for the sequencer.

use super::{Sequencer, MAX_PRESETS, MAX_PRESET_LEN, MAX_SEQUENCE_LEN};

/// Load presets from params into preset storage.
pub unsafe fn load_preset(seq: &mut Sequencer, preset_index: u8) {
    if seq.preset_count == 0 {
        return;
    }

    let index = (preset_index as usize) % (seq.preset_count as usize);
    let plen = *seq.preset_lengths.as_ptr().add(index) as usize;

    let values_ptr = seq.values.as_mut_ptr();
    let preset_ptr = seq.preset_values.as_ptr().add(index) as *const u16;
    let copy_len = if plen < MAX_SEQUENCE_LEN {
        plen
    } else {
        MAX_SEQUENCE_LEN
    };
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
