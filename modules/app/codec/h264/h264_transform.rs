// Mechanical Rust port of h264bsd_transform.c (h264bsd, Apache-2.0),
// per the port rules in PORT_RULES.md. Bit-exact vs the C reference:
// operation order of the 4x4 inverse transform butterflies and the DC
// transforms preserved exactly (shifts/adds match bit-for-bit), tables
// copied verbatim. No functions skipped.
//
// Functions:
//   h264bsdProcessBlock    - inverse zig-zag scan, inverse scaling and
//                            inverse transform for a luma/chroma residual block
//   h264bsdProcessLumaDc   - inverse zig-zag scan, inverse transform and
//                            inverse scaling for a luma DC coefficients block
//   h264bsdProcessChromaDc - inverse transform and inverse scaling for a
//                            chroma DC coefficients block

#![allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code,
    unused_assignments,
    unused_mut,
    clippy::all
)]

use super::*;

/* LevelScale function */
static levelScale: [[i32; 3]; 6] = [
    [10, 13, 16],
    [11, 14, 18],
    [13, 16, 20],
    [14, 18, 23],
    [16, 20, 25],
    [18, 23, 29],
];

/* qp % 6 as a function of qp */
static qpMod6: [u8; 52] = [
    0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 5,
    0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 5,
    0, 1, 2, 3,
];

/* qp / 6 as a function of qp */
static qpDiv6: [u8; 52] = [
    0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3,
    4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7,
    8, 8, 8, 8,
];

/// Function performs inverse zig-zag scan, inverse scaling and
/// inverse transform for a luma or a chroma residual block.
///
/// Inputs:
///   data      pointer to data to be processed
///   qp        quantization parameter
///   skip      skip processing of data[0], set to non-zero value
///             if dc coeff handled separately
///   coeffMap  16 lsb's indicate which coeffs are non-zero,
///             bit 0 (lsb) for coeff 0, bit 1 for coeff 1 etc.
///
/// Returns HANTRO_OK on success, HANTRO_NOK if processed data not in
/// valid range [-512, 511].
pub unsafe fn h264bsdProcessBlock(data: *mut i32, qp: u32, skip: u32, coeffMap: u32) -> u32 {
    let mut data = data;

    let mut tmp0: i32;
    let mut tmp1: i32;
    let mut tmp2: i32;
    let mut tmp3: i32;
    let mut d1: i32;
    let mut d2: i32;
    let mut d3: i32;
    let qpDiv: u32;
    let mut ptr: *mut i32;

    qpDiv = qpDiv6[qp as usize] as u32;
    tmp1 = levelScale[qpMod6[qp as usize] as usize][0] << qpDiv;
    tmp2 = levelScale[qpMod6[qp as usize] as usize][1] << qpDiv;
    tmp3 = levelScale[qpMod6[qp as usize] as usize][2] << qpDiv;

    if skip == 0 {
        *data.add(0) = *data.add(0) * tmp1;
    }

    /* at least one of the rows 1, 2 or 3 contain non-zero coeffs, mask takes
     * the scanning order into account */
    if coeffMap & 0xFF9C != 0 {
        /* do the zig-zag scan and inverse quantization */
        d1 = *data.add(1);
        d2 = *data.add(14);
        d3 = *data.add(15);
        *data.add(1) = d1 * tmp2;
        *data.add(14) = d2 * tmp2;
        *data.add(15) = d3 * tmp3;

        d1 = *data.add(2);
        d2 = *data.add(5);
        d3 = *data.add(4);
        *data.add(4) = d1 * tmp2;
        *data.add(2) = d2 * tmp1;
        *data.add(5) = d3 * tmp3;

        d1 = *data.add(8);
        d2 = *data.add(3);
        d3 = *data.add(6);
        tmp0 = d1 * tmp2;
        *data.add(8) = d2 * tmp1;
        *data.add(3) = d3 * tmp2;
        d1 = *data.add(7);
        d2 = *data.add(12);
        d3 = *data.add(9);
        *data.add(6) = d1 * tmp2;
        *data.add(7) = d2 * tmp3;
        *data.add(12) = d3 * tmp2;
        *data.add(9) = tmp0;

        d1 = *data.add(10);
        d2 = *data.add(11);
        d3 = *data.add(13);
        *data.add(13) = d1 * tmp3;
        *data.add(10) = d2 * tmp1;
        *data.add(11) = d3 * tmp2;

        /* horizontal transform */
        let mut row: u32 = 4;
        ptr = data;
        while row != 0 {
            row -= 1;
            tmp0 = *ptr.add(0) + *ptr.add(2);
            tmp1 = *ptr.add(0) - *ptr.add(2);
            tmp2 = (*ptr.add(1) >> 1) - *ptr.add(3);
            tmp3 = *ptr.add(1) + (*ptr.add(3) >> 1);
            *ptr.add(0) = tmp0 + tmp3;
            *ptr.add(1) = tmp1 + tmp2;
            *ptr.add(2) = tmp1 - tmp2;
            *ptr.add(3) = tmp0 - tmp3;
            ptr = ptr.add(4);
        }

        /* then vertical transform */
        let mut col: u32 = 4;
        while col != 0 {
            col -= 1;
            tmp0 = *data.add(0) + *data.add(8);
            tmp1 = *data.add(0) - *data.add(8);
            tmp2 = (*data.add(4) >> 1) - *data.add(12);
            tmp3 = *data.add(4) + (*data.add(12) >> 1);
            *data.add(0) = (tmp0 + tmp3 + 32) >> 6;
            *data.add(4) = (tmp1 + tmp2 + 32) >> 6;
            *data.add(8) = (tmp1 - tmp2 + 32) >> 6;
            *data.add(12) = (tmp0 - tmp3 + 32) >> 6;
            /* check that each value is in the range [-512,511] */
            if ((*data.add(0)).wrapping_add(512) as u32 > 1023)
                || ((*data.add(4)).wrapping_add(512) as u32 > 1023)
                || ((*data.add(8)).wrapping_add(512) as u32 > 1023)
                || ((*data.add(12)).wrapping_add(512) as u32 > 1023)
            {
                return HANTRO_NOK;
            }
            data = data.add(1);
        }
    } else
    /* rows 1, 2 and 3 are zero */
    {
        /* only dc-coeff is non-zero, i.e. coeffs at original positions
         * 1, 5 and 6 are zero */
        if (coeffMap & 0x62) == 0 {
            tmp0 = (*data.add(0) + 32) >> 6;
            /* check that value is in the range [-512,511] */
            if tmp0.wrapping_add(512) as u32 > 1023 {
                return HANTRO_NOK;
            }
            *data.add(0) = tmp0;
            *data.add(1) = tmp0;
            *data.add(2) = tmp0;
            *data.add(3) = tmp0;
            *data.add(4) = tmp0;
            *data.add(5) = tmp0;
            *data.add(6) = tmp0;
            *data.add(7) = tmp0;
            *data.add(8) = tmp0;
            *data.add(9) = tmp0;
            *data.add(10) = tmp0;
            *data.add(11) = tmp0;
            *data.add(12) = tmp0;
            *data.add(13) = tmp0;
            *data.add(14) = tmp0;
            *data.add(15) = tmp0;
        } else
        /* at least one of the coeffs 1, 5 or 6 is non-zero */
        {
            *data.add(1) = *data.add(1) * tmp2;
            *data.add(2) = *data.add(5) * tmp1;
            *data.add(3) = *data.add(6) * tmp2;
            tmp0 = *data.add(0) + *data.add(2);
            tmp1 = *data.add(0) - *data.add(2);
            tmp2 = (*data.add(1) >> 1) - *data.add(3);
            tmp3 = *data.add(1) + (*data.add(3) >> 1);
            *data.add(0) = (tmp0 + tmp3 + 32) >> 6;
            *data.add(1) = (tmp1 + tmp2 + 32) >> 6;
            *data.add(2) = (tmp1 - tmp2 + 32) >> 6;
            *data.add(3) = (tmp0 - tmp3 + 32) >> 6;
            *data.add(4) = *data.add(0);
            *data.add(8) = *data.add(0);
            *data.add(12) = *data.add(0);
            *data.add(5) = *data.add(1);
            *data.add(9) = *data.add(1);
            *data.add(13) = *data.add(1);
            *data.add(6) = *data.add(2);
            *data.add(10) = *data.add(2);
            *data.add(14) = *data.add(2);
            *data.add(7) = *data.add(3);
            *data.add(11) = *data.add(3);
            *data.add(15) = *data.add(3);
            /* check that each value is in the range [-512,511] */
            if ((*data.add(0)).wrapping_add(512) as u32 > 1023)
                || ((*data.add(1)).wrapping_add(512) as u32 > 1023)
                || ((*data.add(2)).wrapping_add(512) as u32 > 1023)
                || ((*data.add(3)).wrapping_add(512) as u32 > 1023)
            {
                return HANTRO_NOK;
            }
        }
    }

    HANTRO_OK
}

/// Function performs inverse zig-zag scan, inverse transform and
/// inverse scaling for a luma DC coefficients block.
///
/// Inputs:
///   data  pointer to data to be processed
///   qp    quantization parameter
pub unsafe fn h264bsdProcessLumaDc(data: *mut i32, qp: u32) {
    let mut data = data;

    let mut tmp0: i32;
    let mut tmp1: i32;
    let mut tmp2: i32;
    let mut tmp3: i32;
    let qpMod: u32;
    let qpDiv: u32;
    let mut levScale: i32;
    let mut ptr: *mut i32;

    qpMod = qpMod6[qp as usize] as u32;
    qpDiv = qpDiv6[qp as usize] as u32;

    /* zig-zag scan */
    tmp0 = *data.add(2);
    *data.add(2) = *data.add(5);
    *data.add(5) = *data.add(4);
    *data.add(4) = tmp0;

    tmp0 = *data.add(8);
    *data.add(8) = *data.add(3);
    *data.add(3) = *data.add(6);
    *data.add(6) = *data.add(7);
    *data.add(7) = *data.add(12);
    *data.add(12) = *data.add(9);
    *data.add(9) = tmp0;

    tmp0 = *data.add(10);
    *data.add(10) = *data.add(11);
    *data.add(11) = *data.add(13);
    *data.add(13) = tmp0;

    /* horizontal transform */
    let mut row: u32 = 4;
    ptr = data;
    while row != 0 {
        row -= 1;
        tmp0 = *ptr.add(0) + *ptr.add(2);
        tmp1 = *ptr.add(0) - *ptr.add(2);
        tmp2 = *ptr.add(1) - *ptr.add(3);
        tmp3 = *ptr.add(1) + *ptr.add(3);
        *ptr.add(0) = tmp0 + tmp3;
        *ptr.add(1) = tmp1 + tmp2;
        *ptr.add(2) = tmp1 - tmp2;
        *ptr.add(3) = tmp0 - tmp3;
        ptr = ptr.add(4);
    }

    /* then vertical transform and inverse scaling */
    levScale = levelScale[qpMod as usize][0];
    if qp >= 12 {
        levScale <<= qpDiv - 2;
        let mut col: u32 = 4;
        while col != 0 {
            col -= 1;
            tmp0 = *data.add(0) + *data.add(8);
            tmp1 = *data.add(0) - *data.add(8);
            tmp2 = *data.add(4) - *data.add(12);
            tmp3 = *data.add(4) + *data.add(12);
            *data.add(0) = (tmp0 + tmp3) * levScale;
            *data.add(4) = (tmp1 + tmp2) * levScale;
            *data.add(8) = (tmp1 - tmp2) * levScale;
            *data.add(12) = (tmp0 - tmp3) * levScale;
            data = data.add(1);
        }
    } else {
        let tmp: i32 = if (1 - qpDiv as i32) == 0 { 1 } else { 2 };
        let mut col: u32 = 4;
        while col != 0 {
            col -= 1;
            tmp0 = *data.add(0) + *data.add(8);
            tmp1 = *data.add(0) - *data.add(8);
            tmp2 = *data.add(4) - *data.add(12);
            tmp3 = *data.add(4) + *data.add(12);
            *data.add(0) = ((tmp0 + tmp3) * levScale + tmp) >> (2 - qpDiv);
            *data.add(4) = ((tmp1 + tmp2) * levScale + tmp) >> (2 - qpDiv);
            *data.add(8) = ((tmp1 - tmp2) * levScale + tmp) >> (2 - qpDiv);
            *data.add(12) = ((tmp0 - tmp3) * levScale + tmp) >> (2 - qpDiv);
            data = data.add(1);
        }
    }
}

/// Function performs inverse transform and inverse scaling for a
/// chroma DC coefficients block.
///
/// Inputs:
///   data  pointer to data to be processed
///   qp    quantization parameter
pub unsafe fn h264bsdProcessChromaDc(data: *mut i32, qp: u32) {
    let mut tmp0: i32;
    let mut tmp1: i32;
    let mut tmp2: i32;
    let mut tmp3: i32;
    let qpDiv: u32;
    let mut levScale: i32;
    let levShift: u32;

    qpDiv = qpDiv6[qp as usize] as u32;
    levScale = levelScale[qpMod6[qp as usize] as usize][0];

    if qp >= 6 {
        levScale <<= qpDiv - 1;
        levShift = 0;
    } else {
        levShift = 1;
    }

    tmp0 = *data.add(0) + *data.add(2);
    tmp1 = *data.add(0) - *data.add(2);
    tmp2 = *data.add(1) - *data.add(3);
    tmp3 = *data.add(1) + *data.add(3);
    *data.add(0) = ((tmp0 + tmp3) * levScale) >> levShift;
    *data.add(1) = ((tmp0 - tmp3) * levScale) >> levShift;
    *data.add(2) = ((tmp1 + tmp2) * levScale) >> levShift;
    *data.add(3) = ((tmp1 - tmp2) * levScale) >> levShift;
    tmp0 = *data.add(4) + *data.add(6);
    tmp1 = *data.add(4) - *data.add(6);
    tmp2 = *data.add(5) - *data.add(7);
    tmp3 = *data.add(5) + *data.add(7);
    *data.add(4) = ((tmp0 + tmp3) * levScale) >> levShift;
    *data.add(5) = ((tmp0 - tmp3) * levScale) >> levShift;
    *data.add(6) = ((tmp1 + tmp2) * levScale) >> levShift;
    *data.add(7) = ((tmp1 - tmp2) * levScale) >> levShift;
}
