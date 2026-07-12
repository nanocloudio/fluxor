// Mechanical Rust port of h264bsd_neighbour.c and
// h264bsd_slice_group_map.c (h264bsd, Apache-2.0), per the port rules
// in PORT_RULES.md. C names kept verbatim; logic translated 1:1.
//
// Per h264bsd_neighbour.h the Neighbour4x4Block* functions return
// `const neighbour_t*` in C — ported as `&'static neighbour_t`.
//
// No functions skipped; everything in both translation units is live.

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

// ============================================================================
// h264bsd_neighbour.c
// ============================================================================

/* Following four tables indicate neighbours of each block of a macroblock.
 * First 16 values are for luma blocks, next 4 values for Cb and last 4
 * values for Cr. Elements of the table indicate to which macroblock the
 * neighbour block belongs and the index of the neighbour block in question.
 * Indexing of the blocks goes as follows
 *
 *          Y             Cb       Cr
 *      0  1  4  5      16 17    20 21
 *      2  3  6  7      18 19    22 23
 *      8  9 12 13
 *     10 11 14 15
 */

/* left neighbour for each block */
static N_A_4x4B: [neighbour_t; 24] = [
    neighbour_t { mb: MB_A, index: 5 },
    neighbour_t { mb: MB_CURR, index: 0 },
    neighbour_t { mb: MB_A, index: 7 },
    neighbour_t { mb: MB_CURR, index: 2 },
    neighbour_t { mb: MB_CURR, index: 1 },
    neighbour_t { mb: MB_CURR, index: 4 },
    neighbour_t { mb: MB_CURR, index: 3 },
    neighbour_t { mb: MB_CURR, index: 6 },
    neighbour_t { mb: MB_A, index: 13 },
    neighbour_t { mb: MB_CURR, index: 8 },
    neighbour_t { mb: MB_A, index: 15 },
    neighbour_t { mb: MB_CURR, index: 10 },
    neighbour_t { mb: MB_CURR, index: 9 },
    neighbour_t { mb: MB_CURR, index: 12 },
    neighbour_t { mb: MB_CURR, index: 11 },
    neighbour_t { mb: MB_CURR, index: 14 },
    neighbour_t { mb: MB_A, index: 17 },
    neighbour_t { mb: MB_CURR, index: 16 },
    neighbour_t { mb: MB_A, index: 19 },
    neighbour_t { mb: MB_CURR, index: 18 },
    neighbour_t { mb: MB_A, index: 21 },
    neighbour_t { mb: MB_CURR, index: 20 },
    neighbour_t { mb: MB_A, index: 23 },
    neighbour_t { mb: MB_CURR, index: 22 },
];

/* above neighbour for each block */
static N_B_4x4B: [neighbour_t; 24] = [
    neighbour_t { mb: MB_B, index: 10 },
    neighbour_t { mb: MB_B, index: 11 },
    neighbour_t { mb: MB_CURR, index: 0 },
    neighbour_t { mb: MB_CURR, index: 1 },
    neighbour_t { mb: MB_B, index: 14 },
    neighbour_t { mb: MB_B, index: 15 },
    neighbour_t { mb: MB_CURR, index: 4 },
    neighbour_t { mb: MB_CURR, index: 5 },
    neighbour_t { mb: MB_CURR, index: 2 },
    neighbour_t { mb: MB_CURR, index: 3 },
    neighbour_t { mb: MB_CURR, index: 8 },
    neighbour_t { mb: MB_CURR, index: 9 },
    neighbour_t { mb: MB_CURR, index: 6 },
    neighbour_t { mb: MB_CURR, index: 7 },
    neighbour_t { mb: MB_CURR, index: 12 },
    neighbour_t { mb: MB_CURR, index: 13 },
    neighbour_t { mb: MB_B, index: 18 },
    neighbour_t { mb: MB_B, index: 19 },
    neighbour_t { mb: MB_CURR, index: 16 },
    neighbour_t { mb: MB_CURR, index: 17 },
    neighbour_t { mb: MB_B, index: 22 },
    neighbour_t { mb: MB_B, index: 23 },
    neighbour_t { mb: MB_CURR, index: 20 },
    neighbour_t { mb: MB_CURR, index: 21 },
];

/* above-right neighbour for each block */
static N_C_4x4B: [neighbour_t; 24] = [
    neighbour_t { mb: MB_B, index: 11 },
    neighbour_t { mb: MB_B, index: 14 },
    neighbour_t { mb: MB_CURR, index: 1 },
    neighbour_t { mb: MB_NA, index: 4 },
    neighbour_t { mb: MB_B, index: 15 },
    neighbour_t { mb: MB_C, index: 10 },
    neighbour_t { mb: MB_CURR, index: 5 },
    neighbour_t { mb: MB_NA, index: 0 },
    neighbour_t { mb: MB_CURR, index: 3 },
    neighbour_t { mb: MB_CURR, index: 6 },
    neighbour_t { mb: MB_CURR, index: 9 },
    neighbour_t { mb: MB_NA, index: 12 },
    neighbour_t { mb: MB_CURR, index: 7 },
    neighbour_t { mb: MB_NA, index: 2 },
    neighbour_t { mb: MB_CURR, index: 13 },
    neighbour_t { mb: MB_NA, index: 8 },
    neighbour_t { mb: MB_B, index: 19 },
    neighbour_t { mb: MB_C, index: 18 },
    neighbour_t { mb: MB_CURR, index: 17 },
    neighbour_t { mb: MB_NA, index: 16 },
    neighbour_t { mb: MB_B, index: 23 },
    neighbour_t { mb: MB_C, index: 22 },
    neighbour_t { mb: MB_CURR, index: 21 },
    neighbour_t { mb: MB_NA, index: 20 },
];

/* above-left neighbour for each block */
static N_D_4x4B: [neighbour_t; 24] = [
    neighbour_t { mb: MB_D, index: 15 },
    neighbour_t { mb: MB_B, index: 10 },
    neighbour_t { mb: MB_A, index: 5 },
    neighbour_t { mb: MB_CURR, index: 0 },
    neighbour_t { mb: MB_B, index: 11 },
    neighbour_t { mb: MB_B, index: 14 },
    neighbour_t { mb: MB_CURR, index: 1 },
    neighbour_t { mb: MB_CURR, index: 4 },
    neighbour_t { mb: MB_A, index: 7 },
    neighbour_t { mb: MB_CURR, index: 2 },
    neighbour_t { mb: MB_A, index: 13 },
    neighbour_t { mb: MB_CURR, index: 8 },
    neighbour_t { mb: MB_CURR, index: 3 },
    neighbour_t { mb: MB_CURR, index: 6 },
    neighbour_t { mb: MB_CURR, index: 9 },
    neighbour_t { mb: MB_CURR, index: 12 },
    neighbour_t { mb: MB_D, index: 19 },
    neighbour_t { mb: MB_B, index: 18 },
    neighbour_t { mb: MB_A, index: 17 },
    neighbour_t { mb: MB_CURR, index: 16 },
    neighbour_t { mb: MB_D, index: 23 },
    neighbour_t { mb: MB_B, index: 22 },
    neighbour_t { mb: MB_A, index: 21 },
    neighbour_t { mb: MB_CURR, index: 20 },
];

/// Initialize macroblock neighbours. Function sets neighbour macroblock
/// pointers in macroblock structures to point to macroblocks on the
/// left, above, above-right and above-left. Pointers are set NULL if
/// the neighbour does not fit into the picture.
pub unsafe fn h264bsdInitMbNeighbours(pMbStorage: *mut mbStorage_t, picWidth: u32, picSizeInMbs: u32) {
    let mut row: u32;
    let mut col: u32;

    row = 0;
    col = 0;

    let mut i: u32 = 0;
    while i < picSizeInMbs {
        if col != 0 {
            (*pMbStorage.add(i as usize)).mbA = pMbStorage.add(i as usize - 1);
        } else {
            (*pMbStorage.add(i as usize)).mbA = core::ptr::null_mut();
        }

        if row != 0 {
            (*pMbStorage.add(i as usize)).mbB = pMbStorage.add((i - picWidth) as usize);
        } else {
            (*pMbStorage.add(i as usize)).mbB = core::ptr::null_mut();
        }

        if row != 0 && (col < picWidth - 1) {
            (*pMbStorage.add(i as usize)).mbC = pMbStorage.add((i - (picWidth - 1)) as usize);
        } else {
            (*pMbStorage.add(i as usize)).mbC = core::ptr::null_mut();
        }

        if row != 0 && col != 0 {
            (*pMbStorage.add(i as usize)).mbD = pMbStorage.add((i - (picWidth + 1)) as usize);
        } else {
            (*pMbStorage.add(i as usize)).mbD = core::ptr::null_mut();
        }

        col += 1;
        if col == picWidth {
            col = 0;
            row += 1;
        }

        i += 1;
    }
}

/// Get pointer to neighbour macroblock. Returns NULL if not available.
pub unsafe fn h264bsdGetNeighbourMb(pMb: *mut mbStorage_t, neighbour: neighbourMb_e) -> *mut mbStorage_t {
    if neighbour == MB_A {
        (*pMb).mbA
    } else if neighbour == MB_B {
        (*pMb).mbB
    } else if neighbour == MB_C {
        (*pMb).mbC
    } else if neighbour == MB_D {
        (*pMb).mbD
    } else if neighbour == MB_CURR {
        pMb
    } else {
        core::ptr::null_mut()
    }
}

/// Get left neighbour of the block. Function returns pointer to the
/// table defined in the beginning of the file.
pub fn h264bsdNeighbour4x4BlockA(blockIndex: u32) -> &'static neighbour_t {
    &N_A_4x4B[blockIndex as usize]
}

/// Get above neighbour of the block. Function returns pointer to the
/// table defined in the beginning of the file.
pub fn h264bsdNeighbour4x4BlockB(blockIndex: u32) -> &'static neighbour_t {
    &N_B_4x4B[blockIndex as usize]
}

/// Get above-right neighbour of the block. Function returns pointer to
/// the table defined in the beginning of the file.
pub fn h264bsdNeighbour4x4BlockC(blockIndex: u32) -> &'static neighbour_t {
    &N_C_4x4B[blockIndex as usize]
}

/// Get above-left neighbour of the block. Function returns pointer to
/// the table defined in the beginning of the file.
pub fn h264bsdNeighbour4x4BlockD(blockIndex: u32) -> &'static neighbour_t {
    &N_D_4x4B[blockIndex as usize]
}

/// Check if neighbour macroblock is available. Neighbour macroblock is
/// considered available if it is within the picture and belongs to the
/// same slice as the current macroblock.
pub unsafe fn h264bsdIsNeighbourAvailable(pMb: &mbStorage_t, pNeighbour: *mut mbStorage_t) -> u32 {
    if pNeighbour.is_null() || pMb.sliceId != (*pNeighbour).sliceId {
        HANTRO_FALSE
    } else {
        HANTRO_TRUE
    }
}

// ============================================================================
// h264bsd_slice_group_map.c
// ============================================================================

/// Function to decode interleaved slice group map type, i.e. slice
/// group map type 0.
unsafe fn DecodeInterleavedMap(map: *mut u32, numSliceGroups: u32, runLength: *const u32, picSize: u32) {
    let mut i: u32;
    let mut j: u32;
    let mut group: u32;

    i = 0;

    loop {
        /* C: for (group = 0; group < numSliceGroups && i < picSize;
         *          i += runLength[group++]) */
        group = 0;
        while group < numSliceGroups && i < picSize {
            j = 0;
            while j < *runLength.add(group as usize) && i.wrapping_add(j) < picSize {
                *map.add(i.wrapping_add(j) as usize) = group;
                j += 1;
            }
            i = i.wrapping_add(*runLength.add(group as usize));
            group += 1;
        }
        if !(i < picSize) {
            break;
        }
    }
}

/// Function to decode dispersed slice group map type, i.e. slice group
/// map type 1.
unsafe fn DecodeDispersedMap(map: *mut u32, numSliceGroups: u32, picWidth: u32, picHeight: u32) {
    let picSize: u32 = picWidth * picHeight;

    let mut i: u32 = 0;
    while i < picSize {
        *map.add(i as usize) =
            urem(urem(i, picWidth) + ((udiv(i, picWidth) * numSliceGroups) >> 1), numSliceGroups);
        i += 1;
    }
}

/// Function to decode foreground with left-over slice group map type,
/// i.e. slice group map type 2.
unsafe fn DecodeForegroundLeftOverMap(
    map: *mut u32,
    numSliceGroups: u32,
    topLeft: *const u32,
    bottomRight: *const u32,
    picWidth: u32,
    picHeight: u32,
) {
    let mut y: u32;
    let mut x: u32;
    let mut yTopLeft: u32;
    let mut yBottomRight: u32;
    let mut xTopLeft: u32;
    let mut xBottomRight: u32;
    let picSize: u32;
    let mut group: u32;

    picSize = picWidth * picHeight;

    let mut i: u32 = 0;
    while i < picSize {
        *map.add(i as usize) = numSliceGroups - 1;
        i += 1;
    }

    /* C: for (group = numSliceGroups - 1; group--; ) — post-decrement in
     * the condition: loop body sees numSliceGroups-2 down to 0. */
    group = numSliceGroups - 1;
    loop {
        let cond = group;
        group = group.wrapping_sub(1);
        if cond == 0 {
            break;
        }

        yTopLeft = udiv(*topLeft.add(group as usize), picWidth);
        xTopLeft = urem(*topLeft.add(group as usize), picWidth);
        yBottomRight = udiv(*bottomRight.add(group as usize), picWidth);
        xBottomRight = urem(*bottomRight.add(group as usize), picWidth);

        y = yTopLeft;
        while y <= yBottomRight {
            x = xTopLeft;
            while x <= xBottomRight {
                *map.add((y * picWidth + x) as usize) = group;
                x += 1;
            }
            y += 1;
        }
    }
}

/// Function to decode box-out slice group map type, i.e. slice group
/// map type 3.
unsafe fn DecodeBoxOutMap(
    map: *mut u32,
    sliceGroupChangeDirectionFlag: u32,
    unitsInSliceGroup0: u32,
    picWidth: u32,
    picHeight: u32,
) {
    let mut k: u32;
    let picSize: u32;
    let mut x: i32;
    let mut y: i32;
    let mut xDir: i32;
    let mut yDir: i32;
    let mut leftBound: i32;
    let mut topBound: i32;
    let mut rightBound: i32;
    let mut bottomBound: i32;
    let mut mapUnitVacant: u32;

    picSize = picWidth * picHeight;

    let mut i: u32 = 0;
    while i < picSize {
        *map.add(i as usize) = 1;
        i += 1;
    }

    x = ((picWidth - sliceGroupChangeDirectionFlag) >> 1) as i32;
    y = ((picHeight - sliceGroupChangeDirectionFlag) >> 1) as i32;

    leftBound = x;
    topBound = y;

    rightBound = x;
    bottomBound = y;

    xDir = sliceGroupChangeDirectionFlag as i32 - 1;
    yDir = sliceGroupChangeDirectionFlag as i32;

    /* C: for (k = 0; k < unitsInSliceGroup0; k += mapUnitVacant ? 1 : 0) */
    k = 0;
    while k < unitsInSliceGroup0 {
        mapUnitVacant = if *map.add((y as u32 * picWidth + x as u32) as usize) == 1 {
            HANTRO_TRUE
        } else {
            HANTRO_FALSE
        };

        if mapUnitVacant != 0 {
            *map.add((y as u32 * picWidth + x as u32) as usize) = 0;
        }

        if xDir == -1 && x == leftBound {
            leftBound = MAX!(leftBound - 1, 0);
            x = leftBound;
            xDir = 0;
            yDir = 2 * sliceGroupChangeDirectionFlag as i32 - 1;
        } else if xDir == 1 && x == rightBound {
            rightBound = MIN!(rightBound + 1, picWidth as i32 - 1);
            x = rightBound;
            xDir = 0;
            yDir = 1 - 2 * sliceGroupChangeDirectionFlag as i32;
        } else if yDir == -1 && y == topBound {
            topBound = MAX!(topBound - 1, 0);
            y = topBound;
            xDir = 1 - 2 * sliceGroupChangeDirectionFlag as i32;
            yDir = 0;
        } else if yDir == 1 && y == bottomBound {
            bottomBound = MIN!(bottomBound + 1, picHeight as i32 - 1);
            y = bottomBound;
            xDir = 2 * sliceGroupChangeDirectionFlag as i32 - 1;
            yDir = 0;
        } else {
            x += xDir;
            y += yDir;
        }

        k += if mapUnitVacant != 0 { 1 } else { 0 };
    }
}

/// Function to decode raster scan slice group map type, i.e. slice
/// group map type 4.
unsafe fn DecodeRasterScanMap(
    map: *mut u32,
    sliceGroupChangeDirectionFlag: u32,
    sizeOfUpperLeftGroup: u32,
    picSize: u32,
) {
    let mut i: u32 = 0;
    while i < picSize {
        if i < sizeOfUpperLeftGroup {
            *map.add(i as usize) = sliceGroupChangeDirectionFlag;
        } else {
            *map.add(i as usize) = 1 - sliceGroupChangeDirectionFlag;
        }
        i += 1;
    }
}

/// Function to decode wipe slice group map type, i.e. slice group map
/// type 5.
unsafe fn DecodeWipeMap(
    map: *mut u32,
    sliceGroupChangeDirectionFlag: u32,
    sizeOfUpperLeftGroup: u32,
    picWidth: u32,
    picHeight: u32,
) {
    let mut i: u32;
    let mut j: u32;
    let mut k: u32;

    k = 0;
    j = 0;
    while j < picWidth {
        i = 0;
        while i < picHeight {
            let kCur = k;
            k += 1;
            if kCur < sizeOfUpperLeftGroup {
                *map.add((i * picWidth + j) as usize) = sliceGroupChangeDirectionFlag;
            } else {
                *map.add((i * picWidth + j) as usize) = 1 - sliceGroupChangeDirectionFlag;
            }
            i += 1;
        }
        j += 1;
    }
}

/// Function to decode macroblock to slice group map. Construction of
/// different slice group map types is handled by separate functions
/// defined above. See standard for details how slice group maps are
/// computed.
pub unsafe fn h264bsdDecodeSliceGroupMap(
    map: *mut u32,
    pps: &picParamSet_t,
    sliceGroupChangeCycle: u32,
    picWidth: u32,
    picHeight: u32,
) {
    let picSize: u32;
    let mut unitsInSliceGroup0: u32 = 0;
    let mut sizeOfUpperLeftGroup: u32 = 0;

    picSize = picWidth * picHeight;

    /* just one slice group -> all macroblocks belong to group 0 */
    if pps.numSliceGroups == 1 {
        core::ptr::write_bytes(map as *mut u8, 0, (picSize as usize) * core::mem::size_of::<u32>());
        return;
    }

    if pps.sliceGroupMapType > 2 && pps.sliceGroupMapType < 6 {
        unitsInSliceGroup0 = MIN!(sliceGroupChangeCycle * pps.sliceGroupChangeRate, picSize);

        if pps.sliceGroupMapType == 4 || pps.sliceGroupMapType == 5 {
            sizeOfUpperLeftGroup = if pps.sliceGroupChangeDirectionFlag != 0 {
                picSize - unitsInSliceGroup0
            } else {
                unitsInSliceGroup0
            };
        }
    }

    match pps.sliceGroupMapType {
        0 => {
            DecodeInterleavedMap(map, pps.numSliceGroups, pps.runLength, picSize);
        }

        1 => {
            DecodeDispersedMap(map, pps.numSliceGroups, picWidth, picHeight);
        }

        2 => {
            DecodeForegroundLeftOverMap(
                map,
                pps.numSliceGroups,
                pps.topLeft,
                pps.bottomRight,
                picWidth,
                picHeight,
            );
        }

        3 => {
            DecodeBoxOutMap(
                map,
                pps.sliceGroupChangeDirectionFlag,
                unitsInSliceGroup0,
                picWidth,
                picHeight,
            );
        }

        4 => {
            DecodeRasterScanMap(
                map,
                pps.sliceGroupChangeDirectionFlag,
                sizeOfUpperLeftGroup,
                picSize,
            );
        }

        5 => {
            DecodeWipeMap(
                map,
                pps.sliceGroupChangeDirectionFlag,
                sizeOfUpperLeftGroup,
                picWidth,
                picHeight,
            );
        }

        _ => {
            let mut i: u32 = 0;
            while i < picSize {
                *map.add(i as usize) = *pps.sliceGroupId.add(i as usize);
                i += 1;
            }
        }
    }
}
