// SVF (State Variable Filter) processing.

/// Process one sample through the SVF lowpass filter.
///
/// Returns the filtered sample. Updates filter_low and filter_band state.
/// When cutoff >= 255 and resonance == 0, caller should bypass this function.
#[inline(always)]
pub fn svf_process(
    input: i32,
    cutoff: u8,
    resonance: u8,
    filter_low: &mut i32,
    filter_band: &mut i32,
) -> i32 {
    let f = ((cutoff as i32) * 200 >> 8).clamp(1, 200);
    let q = (256 - (resonance as i32)).clamp(10, 256);
    *filter_low = *filter_low + ((f * *filter_band) >> 8);
    let high = input - *filter_low - ((q * *filter_band) >> 8);
    *filter_band = *filter_band + ((f * high) >> 8);
    (*filter_low).clamp(-32768, 32767)
}
