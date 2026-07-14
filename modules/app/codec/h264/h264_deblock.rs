// Mechanical Rust port of h264bsd_deblocking.c (h264bsd H.264 baseline
// decoder), PLAIN path: H264DEC_OMXDL undefined. Ported per the rules in
// PORT_RULES.md (bit-exact, C names verbatim).
//
// Skipped (dead in this build):
// - OMXDL-only variants: InnerBoundaryStrength2, EdgeBoundaryStrengthTop,
//   EdgeBoundaryStrengthLeft, the OMXDL h264bsdFilterPicture /
//   GetBoundaryStrengths / GetLumaEdgeThresholds / GetChromaEdgeThresholds
//   and the tc0[52][5] table variant.
// - Dead debug globals `sample`, `hashA`..`hashD` (only referenced from
//   commented-out code in the C).
//
// The clipping table h264bsdClip is defined in h264bsd_intra_prediction.c
// and imported here from the h264_intra sibling module.

#![allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code,
    unused_assignments,
    unused_mut,
    clippy::all,
    reason = "mechanical port of h264bsd keeps C names verbatim for stage-by-stage parity diffing against the reference decoder"
)]

use super::*;
use super::h264_intra::*;
use super::h264_macroblock::*;

/*------------------------------------------------------------------------------
    3. Module defines
------------------------------------------------------------------------------*/

/* array of alpha values, from the standard */
static alphas: [u8; 52] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 5, 6, 7, 8, 9, 10, 12, 13, 15, 17,
    20, 22, 25, 28, 32, 36, 40, 45, 50, 56, 63, 71, 80, 90, 101, 113, 127, 144, 162, 182, 203,
    226, 255, 255,
];

/* array of beta values, from the standard */
static betas: [u8; 52] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 6, 6, 7, 7,
    8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14, 15, 15, 16, 16, 17, 17, 18, 18,
];

/* array of tc0 values, from the standard, each triplet corresponds to a
 * column in the table. Indexing goes as tc0[indexA][bS-1] */
static tc0: [[u8; 3]; 52] = [
    [0, 0, 0], [0, 0, 0], [0, 0, 0], [0, 0, 0], [0, 0, 0], [0, 0, 0], [0, 0, 0], [0, 0, 0],
    [0, 0, 0], [0, 0, 0], [0, 0, 0], [0, 0, 0], [0, 0, 0], [0, 0, 0], [0, 0, 0], [0, 0, 0],
    [0, 0, 0], [0, 0, 1], [0, 0, 1], [0, 0, 1], [0, 0, 1], [0, 1, 1], [0, 1, 1], [1, 1, 1],
    [1, 1, 1], [1, 1, 1], [1, 1, 1], [1, 1, 2], [1, 1, 2], [1, 1, 2], [1, 1, 2], [1, 2, 3],
    [1, 2, 3], [2, 2, 3], [2, 2, 4], [2, 3, 4], [2, 3, 4], [3, 3, 5], [3, 4, 6], [3, 4, 6],
    [4, 5, 7], [4, 5, 8], [4, 6, 9], [5, 7, 10], [6, 8, 11], [6, 8, 13], [7, 10, 14],
    [8, 11, 16], [9, 12, 18], [10, 13, 20], [11, 15, 23], [13, 17, 25],
];

/* mapping of raster scan block index to 4x4 block index */
static mb4x4Index: [u32; 16] = [0, 1, 4, 5, 2, 3, 6, 7, 8, 9, 12, 13, 10, 11, 14, 15];

#[derive(Clone, Copy)]
struct edgeThreshold_t {
    tc0: *const u8,
    alpha: u32,
    beta: u32,
}

#[derive(Clone, Copy)]
struct bS_t {
    top: u32,
    left: u32,
}

const TOP: u32 = 0;
const LEFT: u32 = 1;
const INNER: u32 = 2;

const FILTER_LEFT_EDGE: u32 = 0x04;
const FILTER_TOP_EDGE: u32 = 0x02;
const FILTER_INNER_EDGE: u32 = 0x01;

/*------------------------------------------------------------------------------

    Function: IsSliceBoundaryOnLeft

        Functional description:
            Function to determine if there is a slice boundary on the left side
            of a macroblock.

------------------------------------------------------------------------------*/
unsafe fn IsSliceBoundaryOnLeft(mb: *mut mbStorage_t) -> u32 {
    if (*mb).sliceId != (*(*mb).mbA).sliceId {
        HANTRO_TRUE
    } else {
        HANTRO_FALSE
    }
}

/*------------------------------------------------------------------------------

    Function: IsSliceBoundaryOnTop

        Functional description:
            Function to determine if there is a slice boundary above the
            current macroblock.

------------------------------------------------------------------------------*/
unsafe fn IsSliceBoundaryOnTop(mb: *mut mbStorage_t) -> u32 {
    if (*mb).sliceId != (*(*mb).mbB).sliceId {
        HANTRO_TRUE
    } else {
        HANTRO_FALSE
    }
}

/*------------------------------------------------------------------------------

    Function: GetMbFilteringFlags

        Functional description:
          Function to determine which edges of a macroblock has to be
          filtered. Output is a bit-wise OR of FILTER_LEFT_EDGE,
          FILTER_TOP_EDGE and FILTER_INNER_EDGE, depending on which edges
          shall be filtered.

------------------------------------------------------------------------------*/
unsafe fn GetMbFilteringFlags(mb: *mut mbStorage_t) -> u32 {
    let mut flags: u32 = 0;

    /* nothing will be filtered if disableDeblockingFilterIdc == 1 */
    if (*mb).disableDeblockingFilterIdc != 1 {
        flags |= FILTER_INNER_EDGE;

        /* filterLeftMbEdgeFlag, left mb is MB_A */
        if !(*mb).mbA.is_null()
            && (((*mb).disableDeblockingFilterIdc != 2) || IsSliceBoundaryOnLeft(mb) == 0)
        {
            flags |= FILTER_LEFT_EDGE;
        }

        /* filterTopMbEdgeFlag */
        if !(*mb).mbB.is_null()
            && (((*mb).disableDeblockingFilterIdc != 2) || IsSliceBoundaryOnTop(mb) == 0)
        {
            flags |= FILTER_TOP_EDGE;
        }
    }

    flags
}

/*------------------------------------------------------------------------------

    Function: InnerBoundaryStrength

        Functional description:
            Function to calculate boundary strength value bs for an inner
            edge of a macroblock. Macroblock type is checked before this is
            called -> no intra mb condition here.

------------------------------------------------------------------------------*/
unsafe fn InnerBoundaryStrength(mb1: *mut mbStorage_t, ind1: u32, ind2: u32) -> u32 {
    let tmp1: i32;
    let tmp2: i32;
    let mv1: i32;
    let mv2: i32;
    let mv3: i32;
    let mv4: i32;

    tmp1 = (*mb1).totalCoeff[ind1 as usize] as i32;
    tmp2 = (*mb1).totalCoeff[ind2 as usize] as i32;
    mv1 = (*mb1).mv[ind1 as usize].hor as i32;
    mv2 = (*mb1).mv[ind2 as usize].hor as i32;
    mv3 = (*mb1).mv[ind1 as usize].ver as i32;
    mv4 = (*mb1).mv[ind2 as usize].ver as i32;

    if tmp1 != 0 || tmp2 != 0 {
        2
    } else if ((ABS!(mv1 - mv2) as u32) >= 4)
        || ((ABS!(mv3 - mv4) as u32) >= 4)
        || ((*mb1).refAddr[(ind1 >> 2) as usize] != (*mb1).refAddr[(ind2 >> 2) as usize])
    {
        1
    } else {
        0
    }
}

/*------------------------------------------------------------------------------

    Function: EdgeBoundaryStrength

        Functional description:
            Function to calculate boundary strength value bs for left- or
            top-most edge of a macroblock. Macroblock types are checked
            before this is called -> no intra mb conditions here.

------------------------------------------------------------------------------*/
unsafe fn EdgeBoundaryStrength(
    mb1: *mut mbStorage_t,
    mb2: *mut mbStorage_t,
    ind1: u32,
    ind2: u32,
) -> u32 {
    if (*mb1).totalCoeff[ind1 as usize] != 0 || (*mb2).totalCoeff[ind2 as usize] != 0 {
        2
    } else if ((*mb1).refAddr[(ind1 >> 2) as usize] != (*mb2).refAddr[(ind2 >> 2) as usize])
        || ((ABS!((*mb1).mv[ind1 as usize].hor as i32 - (*mb2).mv[ind2 as usize].hor as i32)
            as u32)
            >= 4)
        || ((ABS!((*mb1).mv[ind1 as usize].ver as i32 - (*mb2).mv[ind2 as usize].ver as i32)
            as u32)
            >= 4)
    {
        1
    } else {
        0
    }
}

/*------------------------------------------------------------------------------

    Function: h264bsdFilterPicture

        Functional description:
          Perform deblocking filtering for a picture. Filter does not copy
          the original picture anywhere but filtering is performed directly
          on the original image. Parameters controlling the filtering process
          are computed based on information in macroblock structures of the
          filtered macroblock, macroblock above and macroblock on the left of
          the filtered one.

        Inputs:
          image         pointer to image to be filtered
          mb            pointer to macroblock data structure of the top-left
                        macroblock of the picture

        Outputs:
          image         filtered image stored here

------------------------------------------------------------------------------*/
pub unsafe fn h264bsdFilterPicture(image: &mut image_t, mb: *mut mbStorage_t) {
    let mut flags: u32;
    let picSizeInMbs: u32;
    let mut mbRow: u32;
    let mut mbCol: u32;
    let picWidthInMbs: u32;
    let mut data: *mut u8;
    let mut pMb: *mut mbStorage_t;
    let mut bS: [bS_t; 16] = [bS_t { top: 0, left: 0 }; 16];
    let mut thresholds: [edgeThreshold_t; 3] = [edgeThreshold_t {
        tc0: core::ptr::null(),
        alpha: 0,
        beta: 0,
    }; 3];

    picWidthInMbs = image.width;
    data = image.data;
    picSizeInMbs = picWidthInMbs * image.height;

    pMb = mb;

    mbRow = 0;
    mbCol = 0;
    while mbRow < image.height {
        flags = GetMbFilteringFlags(pMb);

        if flags != 0 {
            /* GetBoundaryStrengths function returns non-zero value if any of
             * the bS values for the macroblock being processed was non-zero */
            if GetBoundaryStrengths(pMb, bS.as_mut_ptr(), flags) != 0 {
                /* luma */
                GetLumaEdgeThresholds(thresholds.as_mut_ptr(), pMb, flags);
                data = image
                    .data
                    .add((mbRow * picWidthInMbs * 256 + mbCol * 16) as usize);

                FilterLuma(data, bS.as_ptr(), thresholds.as_ptr(), picWidthInMbs * 16);

                /* chroma */
                GetChromaEdgeThresholds(
                    thresholds.as_mut_ptr(),
                    pMb,
                    flags,
                    (*pMb).chromaQpIndexOffset,
                );
                data = image.data.add(
                    (picSizeInMbs * 256 + mbRow * picWidthInMbs * 64 + mbCol * 8) as usize,
                );

                FilterChroma(
                    data,
                    data.add((64 * picSizeInMbs) as usize),
                    bS.as_ptr(),
                    thresholds.as_ptr(),
                    picWidthInMbs * 8,
                );
            }
        }

        mbCol += 1;
        if mbCol == picWidthInMbs {
            mbCol = 0;
            mbRow += 1;
        }
        pMb = pMb.add(1);
    }
}

/*------------------------------------------------------------------------------

    Function: FilterVerLumaEdge

        Functional description:
            Filter one vertical 4-pixel luma edge.

------------------------------------------------------------------------------*/
unsafe fn FilterVerLumaEdge(
    mut data: *mut u8,
    bS: u32,
    thresholds: *const edgeThreshold_t,
    imageWidth: u32,
) {
    let mut delta: i32;
    let tc: i32;
    let mut tmp: i32;
    let mut i: u32;
    let mut p0: i32;
    let mut q0: i32;
    let mut p1: i32;
    let mut q1: i32;
    let mut p2: i32;
    let mut q2: i32;
    let mut tmpFlag: u32;
    let clp: *const u8 = h264bsdClip.as_ptr().add(512);

    let alpha: u32 = (*thresholds).alpha;
    let beta: u32 = (*thresholds).beta;
    let mut val: i32;

    if bS < 4 {
        tc = *(*thresholds).tc0.add((bS - 1) as usize) as i32;
        tmp = tc;
        i = 4;
        while i != 0 {
            p1 = *data.offset(-2) as i32;
            p0 = *data.offset(-1) as i32;
            q0 = *data.offset(0) as i32;
            q1 = *data.offset(1) as i32;

            if ((ABS!(p0 - q0) as u32) < alpha)
                && ((ABS!(p1 - p0) as u32) < beta)
                && ((ABS!(q1 - q0) as u32) < beta)
            {
                p2 = *data.offset(-3) as i32;
                q2 = *data.offset(2) as i32;

                if (ABS!(p2 - p0) as u32) < beta {
                    val = (p2 + ((p0 + q0 + 1) >> 1) - (p1 << 1)) >> 1;
                    *data.offset(-2) = (p1 + CLIP3!(-tc, tc, val)) as u8;
                    tmp += 1;
                }

                if (ABS!(q2 - q0) as u32) < beta {
                    val = (q2 + ((p0 + q0 + 1) >> 1) - (q1 << 1)) >> 1;
                    *data.offset(1) = (q1 + CLIP3!(-tc, tc, val)) as u8;
                    tmp += 1;
                }

                val = (((q0 - p0) << 2) + (p1 - q1) + 4) >> 3;
                delta = CLIP3!(-tmp, tmp, val);

                p0 = *clp.offset((p0 + delta) as isize) as i32;
                q0 = *clp.offset((q0 - delta) as isize) as i32;
                tmp = tc;
                *data.offset(-1) = p0 as u8;
                *data.offset(0) = q0 as u8;
            }

            i -= 1;
            data = data.add(imageWidth as usize);
        }
    } else {
        i = 4;
        while i != 0 {
            p1 = *data.offset(-2) as i32;
            p0 = *data.offset(-1) as i32;
            q0 = *data.offset(0) as i32;
            q1 = *data.offset(1) as i32;
            if ((ABS!(p0 - q0) as u32) < alpha)
                && ((ABS!(p1 - p0) as u32) < beta)
                && ((ABS!(q1 - q0) as u32) < beta)
            {
                tmpFlag = if (ABS!(p0 - q0) as u32) < ((alpha >> 2) + 2) {
                    HANTRO_TRUE
                } else {
                    HANTRO_FALSE
                };

                p2 = *data.offset(-3) as i32;
                q2 = *data.offset(2) as i32;

                if tmpFlag != 0 && (ABS!(p2 - p0) as u32) < beta {
                    tmp = p1 + p0 + q0;
                    *data.offset(-1) = ((p2 + 2 * tmp + q1 + 4) >> 3) as u8;
                    *data.offset(-2) = ((p2 + tmp + 2) >> 2) as u8;
                    *data.offset(-3) =
                        ((2 * (*data.offset(-4) as i32) + 3 * p2 + tmp + 4) >> 3) as u8;
                } else {
                    *data.offset(-1) = ((2 * p1 + p0 + q1 + 2) >> 2) as u8;
                }

                if tmpFlag != 0 && (ABS!(q2 - q0) as u32) < beta {
                    tmp = p0 + q0 + q1;
                    *data.offset(0) = ((p1 + 2 * tmp + q2 + 4) >> 3) as u8;
                    *data.offset(1) = ((tmp + q2 + 2) >> 2) as u8;
                    *data.offset(2) =
                        ((2 * (*data.offset(3) as i32) + 3 * q2 + tmp + 4) >> 3) as u8;
                } else {
                    *data.offset(0) = ((2 * q1 + q0 + p1 + 2) >> 2) as u8;
                }
            }

            i -= 1;
            data = data.add(imageWidth as usize);
        }
    }
}

/*------------------------------------------------------------------------------

    Function: FilterHorLumaEdge

        Functional description:
            Filter one horizontal 4-pixel luma edge

------------------------------------------------------------------------------*/
unsafe fn FilterHorLumaEdge(
    mut data: *mut u8,
    bS: u32,
    thresholds: *const edgeThreshold_t,
    imageWidth: i32,
) {
    let mut delta: i32;
    let tc: i32;
    let mut tmp: i32;
    let mut i: u32;
    let mut p0: u8;
    let mut q0: u8;
    let mut p1: u8;
    let mut q1: u8;
    let mut p2: u8;
    let mut q2: u8;
    let clp: *const u8 = h264bsdClip.as_ptr().add(512);
    let mut val: i32;

    tc = *(*thresholds).tc0.add((bS - 1) as usize) as i32;
    tmp = tc;
    i = 4;
    while i != 0 {
        p1 = *data.offset((-imageWidth * 2) as isize);
        p0 = *data.offset(-imageWidth as isize);
        q0 = *data.offset(0);
        q1 = *data.offset(imageWidth as isize);
        if ((ABS!(p0 as i32 - q0 as i32) as u32) < (*thresholds).alpha)
            && ((ABS!(p1 as i32 - p0 as i32) as u32) < (*thresholds).beta)
            && ((ABS!(q1 as i32 - q0 as i32) as u32) < (*thresholds).beta)
        {
            p2 = *data.offset((-imageWidth * 3) as isize);

            if (ABS!(p2 as i32 - p0 as i32) as u32) < (*thresholds).beta {
                val = (p2 as i32 + ((p0 as i32 + q0 as i32 + 1) >> 1) - ((p1 as i32) << 1)) >> 1;
                *data.offset((-imageWidth * 2) as isize) =
                    (p1 as i32 + CLIP3!(-tc, tc, val)) as u8;
                tmp += 1;
            }

            q2 = *data.offset((imageWidth * 2) as isize);

            if (ABS!(q2 as i32 - q0 as i32) as u32) < (*thresholds).beta {
                val = (q2 as i32 + ((p0 as i32 + q0 as i32 + 1) >> 1) - ((q1 as i32) << 1)) >> 1;
                *data.offset(imageWidth as isize) = (q1 as i32 + CLIP3!(-tc, tc, val)) as u8;
                tmp += 1;
            }

            val = (((q0 as i32 - p0 as i32) << 2) + (p1 as i32 - q1 as i32) + 4) >> 3;
            delta = CLIP3!(-tmp, tmp, val);

            p0 = *clp.offset((p0 as i32 + delta) as isize);
            q0 = *clp.offset((q0 as i32 - delta) as isize);
            tmp = tc;
            *data.offset(-imageWidth as isize) = p0;
            *data.offset(0) = q0;
        }

        i -= 1;
        data = data.add(1);
    }
}

/*------------------------------------------------------------------------------

    Function: FilterHorLuma

        Functional description:
            Filter all four successive horizontal 4-pixel luma edges. This can
            be done when bS is equal to all four edges.

------------------------------------------------------------------------------*/
unsafe fn FilterHorLuma(
    mut data: *mut u8,
    bS: u32,
    thresholds: *const edgeThreshold_t,
    imageWidth: i32,
) {
    let mut delta: i32;
    let tc: i32;
    let mut tmp: i32;
    let mut i: u32;
    let mut p0: i32;
    let mut q0: i32;
    let mut p1: i32;
    let mut q1: i32;
    let mut p2: i32;
    let mut q2: i32;
    let mut tmpFlag: u32;
    let clp: *const u8 = h264bsdClip.as_ptr().add(512);
    let alpha: u32 = (*thresholds).alpha;
    let beta: u32 = (*thresholds).beta;
    let mut val: i32;

    if bS < 4 {
        tc = *(*thresholds).tc0.add((bS - 1) as usize) as i32;
        tmp = tc;
        i = 16;
        while i != 0 {
            p1 = *data.offset((-imageWidth * 2) as isize) as i32;
            p0 = *data.offset(-imageWidth as isize) as i32;
            q0 = *data.offset(0) as i32;
            q1 = *data.offset(imageWidth as isize) as i32;
            if ((ABS!(p0 - q0) as u32) < alpha)
                && ((ABS!(p1 - p0) as u32) < beta)
                && ((ABS!(q1 - q0) as u32) < beta)
            {
                p2 = *data.offset((-imageWidth * 3) as isize) as i32;

                if (ABS!(p2 - p0) as u32) < beta {
                    val = (p2 + ((p0 + q0 + 1) >> 1) - (p1 << 1)) >> 1;
                    *data.offset((-imageWidth * 2) as isize) =
                        (p1 + CLIP3!(-tc, tc, val)) as u8;
                    tmp += 1;
                }

                q2 = *data.offset((imageWidth * 2) as isize) as i32;

                if (ABS!(q2 - q0) as u32) < beta {
                    val = (q2 + ((p0 + q0 + 1) >> 1) - (q1 << 1)) >> 1;
                    *data.offset(imageWidth as isize) = (q1 + CLIP3!(-tc, tc, val)) as u8;
                    tmp += 1;
                }

                val = (((q0 - p0) << 2) + (p1 - q1) + 4) >> 3;
                delta = CLIP3!(-tmp, tmp, val);

                p0 = *clp.offset((p0 + delta) as isize) as i32;
                q0 = *clp.offset((q0 - delta) as isize) as i32;
                tmp = tc;
                *data.offset(-imageWidth as isize) = p0 as u8;
                *data.offset(0) = q0 as u8;
            }

            i -= 1;
            data = data.add(1);
        }
    } else {
        i = 16;
        while i != 0 {
            p1 = *data.offset((-imageWidth * 2) as isize) as i32;
            p0 = *data.offset(-imageWidth as isize) as i32;
            q0 = *data.offset(0) as i32;
            q1 = *data.offset(imageWidth as isize) as i32;
            if ((ABS!(p0 - q0) as u32) < alpha)
                && ((ABS!(p1 - p0) as u32) < beta)
                && ((ABS!(q1 - q0) as u32) < beta)
            {
                tmpFlag = if (ABS!(p0 - q0) as u32) < ((alpha >> 2) + 2) {
                    HANTRO_TRUE
                } else {
                    HANTRO_FALSE
                };

                p2 = *data.offset((-imageWidth * 3) as isize) as i32;
                q2 = *data.offset((imageWidth * 2) as isize) as i32;

                if tmpFlag != 0 && (ABS!(p2 - p0) as u32) < beta {
                    tmp = p1 + p0 + q0;
                    *data.offset(-imageWidth as isize) = ((p2 + 2 * tmp + q1 + 4) >> 3) as u8;
                    *data.offset((-imageWidth * 2) as isize) = ((p2 + tmp + 2) >> 2) as u8;
                    *data.offset((-imageWidth * 3) as isize) = ((2
                        * (*data.offset((-imageWidth * 4) as isize) as i32)
                        + 3 * p2
                        + tmp
                        + 4)
                        >> 3) as u8;
                } else {
                    *data.offset(-imageWidth as isize) = ((2 * p1 + p0 + q1 + 2) >> 2) as u8;
                }

                if tmpFlag != 0 && (ABS!(q2 - q0) as u32) < beta {
                    tmp = p0 + q0 + q1;
                    *data.offset(0) = ((p1 + 2 * tmp + q2 + 4) >> 3) as u8;
                    *data.offset(imageWidth as isize) = ((tmp + q2 + 2) >> 2) as u8;
                    *data.offset((imageWidth * 2) as isize) = ((2
                        * (*data.offset((imageWidth * 3) as isize) as i32)
                        + 3 * q2
                        + tmp
                        + 4)
                        >> 3) as u8;
                } else {
                    *data.offset(0) = ((2 * q1 + q0 + p1 + 2) >> 2) as u8;
                }
            }

            i -= 1;
            data = data.add(1);
        }
    }
}

/*------------------------------------------------------------------------------

    Function: FilterVerChromaEdge

        Functional description:
            Filter one vertical 2-pixel chroma edge

------------------------------------------------------------------------------*/
unsafe fn FilterVerChromaEdge(
    mut data: *mut u8,
    bS: u32,
    thresholds: *const edgeThreshold_t,
    width: u32,
) {
    let mut delta: i32;
    let mut tc: i32;
    let mut p0: u8;
    let mut q0: u8;
    let mut p1: u8;
    let mut q1: u8;
    let clp: *const u8 = h264bsdClip.as_ptr().add(512);

    p1 = *data.offset(-2);
    p0 = *data.offset(-1);
    q0 = *data.offset(0);
    q1 = *data.offset(1);
    if ((ABS!(p0 as i32 - q0 as i32) as u32) < (*thresholds).alpha)
        && ((ABS!(p1 as i32 - p0 as i32) as u32) < (*thresholds).beta)
        && ((ABS!(q1 as i32 - q0 as i32) as u32) < (*thresholds).beta)
    {
        if bS < 4 {
            tc = *(*thresholds).tc0.add((bS - 1) as usize) as i32 + 1;
            delta = CLIP3!(
                -tc,
                tc,
                (((q0 as i32 - p0 as i32) << 2) + (p1 as i32 - q1 as i32) + 4) >> 3
            );
            p0 = *clp.offset((p0 as i32 + delta) as isize);
            q0 = *clp.offset((q0 as i32 - delta) as isize);
            *data.offset(-1) = p0;
            *data.offset(0) = q0;
        } else {
            *data.offset(-1) = ((2 * p1 as i32 + p0 as i32 + q1 as i32 + 2) >> 2) as u8;
            *data.offset(0) = ((2 * q1 as i32 + q0 as i32 + p1 as i32 + 2) >> 2) as u8;
        }
    }
    data = data.add(width as usize);
    p1 = *data.offset(-2);
    p0 = *data.offset(-1);
    q0 = *data.offset(0);
    q1 = *data.offset(1);
    if ((ABS!(p0 as i32 - q0 as i32) as u32) < (*thresholds).alpha)
        && ((ABS!(p1 as i32 - p0 as i32) as u32) < (*thresholds).beta)
        && ((ABS!(q1 as i32 - q0 as i32) as u32) < (*thresholds).beta)
    {
        if bS < 4 {
            tc = *(*thresholds).tc0.add((bS - 1) as usize) as i32 + 1;
            delta = CLIP3!(
                -tc,
                tc,
                (((q0 as i32 - p0 as i32) << 2) + (p1 as i32 - q1 as i32) + 4) >> 3
            );
            p0 = *clp.offset((p0 as i32 + delta) as isize);
            q0 = *clp.offset((q0 as i32 - delta) as isize);
            *data.offset(-1) = p0;
            *data.offset(0) = q0;
        } else {
            *data.offset(-1) = ((2 * p1 as i32 + p0 as i32 + q1 as i32 + 2) >> 2) as u8;
            *data.offset(0) = ((2 * q1 as i32 + q0 as i32 + p1 as i32 + 2) >> 2) as u8;
        }
    }
}

/*------------------------------------------------------------------------------

    Function: FilterHorChromaEdge

        Functional description:
            Filter one horizontal 2-pixel chroma edge

------------------------------------------------------------------------------*/
unsafe fn FilterHorChromaEdge(
    mut data: *mut u8,
    bS: u32,
    thresholds: *const edgeThreshold_t,
    width: i32,
) {
    let mut delta: i32;
    let tc: i32;
    let mut i: u32;
    let mut p0: u8;
    let mut q0: u8;
    let mut p1: u8;
    let mut q1: u8;
    let clp: *const u8 = h264bsdClip.as_ptr().add(512);

    tc = *(*thresholds).tc0.add((bS - 1) as usize) as i32 + 1;
    i = 2;
    while i != 0 {
        p1 = *data.offset((-width * 2) as isize);
        p0 = *data.offset(-width as isize);
        q0 = *data.offset(0);
        q1 = *data.offset(width as isize);
        if ((ABS!(p0 as i32 - q0 as i32) as u32) < (*thresholds).alpha)
            && ((ABS!(p1 as i32 - p0 as i32) as u32) < (*thresholds).beta)
            && ((ABS!(q1 as i32 - q0 as i32) as u32) < (*thresholds).beta)
        {
            delta = CLIP3!(
                -tc,
                tc,
                (((q0 as i32 - p0 as i32) << 2) + (p1 as i32 - q1 as i32) + 4) >> 3
            );
            p0 = *clp.offset((p0 as i32 + delta) as isize);
            q0 = *clp.offset((q0 as i32 - delta) as isize);
            *data.offset(-width as isize) = p0;
            *data.offset(0) = q0;
        }
        i -= 1;
        data = data.add(1);
    }
}

/*------------------------------------------------------------------------------

    Function: FilterHorChroma

        Functional description:
            Filter all four successive horizontal 2-pixel chroma edges. This
            can be done if bS is equal for all four edges.

------------------------------------------------------------------------------*/
unsafe fn FilterHorChroma(
    mut data: *mut u8,
    bS: u32,
    thresholds: *const edgeThreshold_t,
    width: i32,
) {
    let mut delta: i32;
    let tc: i32;
    let mut i: u32;
    let mut p0: u8;
    let mut q0: u8;
    let mut p1: u8;
    let mut q1: u8;
    let clp: *const u8 = h264bsdClip.as_ptr().add(512);

    if bS < 4 {
        tc = *(*thresholds).tc0.add((bS - 1) as usize) as i32 + 1;
        i = 8;
        while i != 0 {
            p1 = *data.offset((-width * 2) as isize);
            p0 = *data.offset(-width as isize);
            q0 = *data.offset(0);
            q1 = *data.offset(width as isize);
            if ((ABS!(p0 as i32 - q0 as i32) as u32) < (*thresholds).alpha)
                && ((ABS!(p1 as i32 - p0 as i32) as u32) < (*thresholds).beta)
                && ((ABS!(q1 as i32 - q0 as i32) as u32) < (*thresholds).beta)
            {
                delta = CLIP3!(
                    -tc,
                    tc,
                    (((q0 as i32 - p0 as i32) << 2) + (p1 as i32 - q1 as i32) + 4) >> 3
                );
                p0 = *clp.offset((p0 as i32 + delta) as isize);
                q0 = *clp.offset((q0 as i32 - delta) as isize);
                *data.offset(-width as isize) = p0;
                *data.offset(0) = q0;
            }
            i -= 1;
            data = data.add(1);
        }
    } else {
        i = 8;
        while i != 0 {
            p1 = *data.offset((-width * 2) as isize);
            p0 = *data.offset(-width as isize);
            q0 = *data.offset(0);
            q1 = *data.offset(width as isize);
            if ((ABS!(p0 as i32 - q0 as i32) as u32) < (*thresholds).alpha)
                && ((ABS!(p1 as i32 - p0 as i32) as u32) < (*thresholds).beta)
                && ((ABS!(q1 as i32 - q0 as i32) as u32) < (*thresholds).beta)
            {
                *data.offset(-width as isize) =
                    ((2 * p1 as i32 + p0 as i32 + q1 as i32 + 2) >> 2) as u8;
                *data.offset(0) = ((2 * q1 as i32 + q0 as i32 + p1 as i32 + 2) >> 2) as u8;
            }
            i -= 1;
            data = data.add(1);
        }
    }
}

/* Helper used for 16x16 inter macroblocks (from the h264bsd repo). */
unsafe fn GetBoundaryStrengthsA(mb: *mut mbStorage_t, bS: *mut bS_t) {
    let mb = &*mb;
    let bS = &mut *(bS as *mut [bS_t; 16]);
    bS[4].top = if mb.totalCoeff[2] != 0 || mb.totalCoeff[0] != 0 { 2 } else { 0 };
    bS[5].top = if mb.totalCoeff[3] != 0 || mb.totalCoeff[1] != 0 { 2 } else { 0 };
    bS[6].top = if mb.totalCoeff[6] != 0 || mb.totalCoeff[4] != 0 { 2 } else { 0 };
    bS[7].top = if mb.totalCoeff[7] != 0 || mb.totalCoeff[5] != 0 { 2 } else { 0 };
    bS[8].top = if mb.totalCoeff[8] != 0 || mb.totalCoeff[2] != 0 { 2 } else { 0 };
    bS[9].top = if mb.totalCoeff[9] != 0 || mb.totalCoeff[3] != 0 { 2 } else { 0 };
    bS[10].top = if mb.totalCoeff[12] != 0 || mb.totalCoeff[6] != 0 { 2 } else { 0 };
    bS[11].top = if mb.totalCoeff[13] != 0 || mb.totalCoeff[7] != 0 { 2 } else { 0 };
    bS[12].top = if mb.totalCoeff[10] != 0 || mb.totalCoeff[8] != 0 { 2 } else { 0 };
    bS[13].top = if mb.totalCoeff[11] != 0 || mb.totalCoeff[9] != 0 { 2 } else { 0 };
    bS[14].top = if mb.totalCoeff[14] != 0 || mb.totalCoeff[12] != 0 { 2 } else { 0 };
    bS[15].top = if mb.totalCoeff[15] != 0 || mb.totalCoeff[13] != 0 { 2 } else { 0 };

    bS[1].left = if mb.totalCoeff[1] != 0 || mb.totalCoeff[0] != 0 { 2 } else { 0 };
    bS[2].left = if mb.totalCoeff[4] != 0 || mb.totalCoeff[1] != 0 { 2 } else { 0 };
    bS[3].left = if mb.totalCoeff[5] != 0 || mb.totalCoeff[4] != 0 { 2 } else { 0 };
    bS[5].left = if mb.totalCoeff[3] != 0 || mb.totalCoeff[2] != 0 { 2 } else { 0 };
    bS[6].left = if mb.totalCoeff[6] != 0 || mb.totalCoeff[3] != 0 { 2 } else { 0 };
    bS[7].left = if mb.totalCoeff[7] != 0 || mb.totalCoeff[6] != 0 { 2 } else { 0 };
    bS[9].left = if mb.totalCoeff[9] != 0 || mb.totalCoeff[8] != 0 { 2 } else { 0 };
    bS[10].left = if mb.totalCoeff[12] != 0 || mb.totalCoeff[9] != 0 { 2 } else { 0 };
    bS[11].left = if mb.totalCoeff[13] != 0 || mb.totalCoeff[12] != 0 { 2 } else { 0 };
    bS[13].left = if mb.totalCoeff[11] != 0 || mb.totalCoeff[10] != 0 { 2 } else { 0 };
    bS[14].left = if mb.totalCoeff[14] != 0 || mb.totalCoeff[11] != 0 { 2 } else { 0 };
    bS[15].left = if mb.totalCoeff[15] != 0 || mb.totalCoeff[14] != 0 { 2 } else { 0 };
}

/*------------------------------------------------------------------------------

    Function: GetBoundaryStrengths

        Functional description:
            Function to calculate boundary strengths for all edges of a
            macroblock. Function returns HANTRO_TRUE if any of the bS values for
            the macroblock had non-zero value, HANTRO_FALSE otherwise.

------------------------------------------------------------------------------*/
unsafe fn GetBoundaryStrengths(mb: *mut mbStorage_t, bS: *mut bS_t, flags: u32) -> u32 {
    /* this flag is set HANTRO_TRUE as soon as any boundary strength value is
     * non-zero */
    let mut nonZeroBs: u32 = HANTRO_FALSE;

    let pbS = bS;
    let bS = &mut *(pbS as *mut [bS_t; 16]);

    /* top edges */
    if flags & FILTER_TOP_EDGE != 0 {
        if IS_INTRA_MB(&*mb) || IS_INTRA_MB(&*(*mb).mbB) {
            bS[0].top = 4;
            bS[1].top = 4;
            bS[2].top = 4;
            bS[3].top = 4;
            nonZeroBs = HANTRO_TRUE;
        } else {
            bS[0].top = EdgeBoundaryStrength(mb, (*mb).mbB, 0, 10);
            bS[1].top = EdgeBoundaryStrength(mb, (*mb).mbB, 1, 11);
            bS[2].top = EdgeBoundaryStrength(mb, (*mb).mbB, 4, 14);
            bS[3].top = EdgeBoundaryStrength(mb, (*mb).mbB, 5, 15);
            if bS[0].top != 0 || bS[1].top != 0 || bS[2].top != 0 || bS[3].top != 0 {
                nonZeroBs = HANTRO_TRUE;
            }
        }
    } else {
        bS[0].top = 0;
        bS[1].top = 0;
        bS[2].top = 0;
        bS[3].top = 0;
    }

    /* left edges */
    if flags & FILTER_LEFT_EDGE != 0 {
        if IS_INTRA_MB(&*mb) || IS_INTRA_MB(&*(*mb).mbA) {
            bS[0].left = 4;
            bS[4].left = 4;
            bS[8].left = 4;
            bS[12].left = 4;
            nonZeroBs = HANTRO_TRUE;
        } else {
            bS[0].left = EdgeBoundaryStrength(mb, (*mb).mbA, 0, 5);
            bS[4].left = EdgeBoundaryStrength(mb, (*mb).mbA, 2, 7);
            bS[8].left = EdgeBoundaryStrength(mb, (*mb).mbA, 8, 13);
            bS[12].left = EdgeBoundaryStrength(mb, (*mb).mbA, 10, 15);
            if nonZeroBs == 0
                && (bS[0].left != 0 || bS[4].left != 0 || bS[8].left != 0 || bS[12].left != 0)
            {
                nonZeroBs = HANTRO_TRUE;
            }
        }
    } else {
        bS[0].left = 0;
        bS[4].left = 0;
        bS[8].left = 0;
        bS[12].left = 0;
    }

    /* inner edges */
    if IS_INTRA_MB(&*mb) {
        bS[4].top = 3;
        bS[5].top = 3;
        bS[6].top = 3;
        bS[7].top = 3;
        bS[8].top = 3;
        bS[9].top = 3;
        bS[10].top = 3;
        bS[11].top = 3;
        bS[12].top = 3;
        bS[13].top = 3;
        bS[14].top = 3;
        bS[15].top = 3;

        bS[1].left = 3;
        bS[2].left = 3;
        bS[3].left = 3;
        bS[5].left = 3;
        bS[6].left = 3;
        bS[7].left = 3;
        bS[9].left = 3;
        bS[10].left = 3;
        bS[11].left = 3;
        bS[13].left = 3;
        bS[14].left = 3;
        bS[15].left = 3;
        nonZeroBs = HANTRO_TRUE;
    } else {
        /* 16x16 inter mb -> ref addresses or motion vectors cannot differ,
         * only check if either of the blocks contain coefficients */
        if h264bsdNumMbPart((*mb).mbType) == 1 {
            GetBoundaryStrengthsA(mb, pbS);
        }
        /* 16x8 inter mb -> ref addresses and motion vectors can be different
         * only for the middle horizontal edge, for the other top edges it is
         * enough to check whether the blocks contain coefficients or not. The
         * same applies to all internal left edges. */
        else if (*mb).mbType == P_L0_L0_16x8 {
            let m = &*mb;
            bS[4].top = if m.totalCoeff[2] != 0 || m.totalCoeff[0] != 0 { 2 } else { 0 };
            bS[5].top = if m.totalCoeff[3] != 0 || m.totalCoeff[1] != 0 { 2 } else { 0 };
            bS[6].top = if m.totalCoeff[6] != 0 || m.totalCoeff[4] != 0 { 2 } else { 0 };
            bS[7].top = if m.totalCoeff[7] != 0 || m.totalCoeff[5] != 0 { 2 } else { 0 };
            bS[12].top = if m.totalCoeff[10] != 0 || m.totalCoeff[8] != 0 { 2 } else { 0 };
            bS[13].top = if m.totalCoeff[11] != 0 || m.totalCoeff[9] != 0 { 2 } else { 0 };
            bS[14].top = if m.totalCoeff[14] != 0 || m.totalCoeff[12] != 0 { 2 } else { 0 };
            bS[15].top = if m.totalCoeff[15] != 0 || m.totalCoeff[13] != 0 { 2 } else { 0 };
            bS[8].top = InnerBoundaryStrength(mb, 8, 2);
            bS[9].top = InnerBoundaryStrength(mb, 9, 3);
            bS[10].top = InnerBoundaryStrength(mb, 12, 6);
            bS[11].top = InnerBoundaryStrength(mb, 13, 7);

            bS[1].left = if m.totalCoeff[1] != 0 || m.totalCoeff[0] != 0 { 2 } else { 0 };
            bS[2].left = if m.totalCoeff[4] != 0 || m.totalCoeff[1] != 0 { 2 } else { 0 };
            bS[3].left = if m.totalCoeff[5] != 0 || m.totalCoeff[4] != 0 { 2 } else { 0 };
            bS[5].left = if m.totalCoeff[3] != 0 || m.totalCoeff[2] != 0 { 2 } else { 0 };
            bS[6].left = if m.totalCoeff[6] != 0 || m.totalCoeff[3] != 0 { 2 } else { 0 };
            bS[7].left = if m.totalCoeff[7] != 0 || m.totalCoeff[6] != 0 { 2 } else { 0 };
            bS[9].left = if m.totalCoeff[9] != 0 || m.totalCoeff[8] != 0 { 2 } else { 0 };
            bS[10].left = if m.totalCoeff[12] != 0 || m.totalCoeff[9] != 0 { 2 } else { 0 };
            bS[11].left = if m.totalCoeff[13] != 0 || m.totalCoeff[12] != 0 { 2 } else { 0 };
            bS[13].left = if m.totalCoeff[11] != 0 || m.totalCoeff[10] != 0 { 2 } else { 0 };
            bS[14].left = if m.totalCoeff[14] != 0 || m.totalCoeff[11] != 0 { 2 } else { 0 };
            bS[15].left = if m.totalCoeff[15] != 0 || m.totalCoeff[14] != 0 { 2 } else { 0 };
        }
        /* 8x16 inter mb -> ref addresses and motion vectors can be different
         * only for the middle vertical edge, for the other left edges it is
         * enough to check whether the blocks contain coefficients or not. The
         * same applies to all internal top edges. */
        else if (*mb).mbType == P_L0_L0_8x16 {
            let m = &*mb;
            bS[4].top = if m.totalCoeff[2] != 0 || m.totalCoeff[0] != 0 { 2 } else { 0 };
            bS[5].top = if m.totalCoeff[3] != 0 || m.totalCoeff[1] != 0 { 2 } else { 0 };
            bS[6].top = if m.totalCoeff[6] != 0 || m.totalCoeff[4] != 0 { 2 } else { 0 };
            bS[7].top = if m.totalCoeff[7] != 0 || m.totalCoeff[5] != 0 { 2 } else { 0 };
            bS[8].top = if m.totalCoeff[8] != 0 || m.totalCoeff[2] != 0 { 2 } else { 0 };
            bS[9].top = if m.totalCoeff[9] != 0 || m.totalCoeff[3] != 0 { 2 } else { 0 };
            bS[10].top = if m.totalCoeff[12] != 0 || m.totalCoeff[6] != 0 { 2 } else { 0 };
            bS[11].top = if m.totalCoeff[13] != 0 || m.totalCoeff[7] != 0 { 2 } else { 0 };
            bS[12].top = if m.totalCoeff[10] != 0 || m.totalCoeff[8] != 0 { 2 } else { 0 };
            bS[13].top = if m.totalCoeff[11] != 0 || m.totalCoeff[9] != 0 { 2 } else { 0 };
            bS[14].top = if m.totalCoeff[14] != 0 || m.totalCoeff[12] != 0 { 2 } else { 0 };
            bS[15].top = if m.totalCoeff[15] != 0 || m.totalCoeff[13] != 0 { 2 } else { 0 };

            bS[1].left = if m.totalCoeff[1] != 0 || m.totalCoeff[0] != 0 { 2 } else { 0 };
            bS[3].left = if m.totalCoeff[5] != 0 || m.totalCoeff[4] != 0 { 2 } else { 0 };
            bS[5].left = if m.totalCoeff[3] != 0 || m.totalCoeff[2] != 0 { 2 } else { 0 };
            bS[7].left = if m.totalCoeff[7] != 0 || m.totalCoeff[6] != 0 { 2 } else { 0 };
            bS[9].left = if m.totalCoeff[9] != 0 || m.totalCoeff[8] != 0 { 2 } else { 0 };
            bS[11].left = if m.totalCoeff[13] != 0 || m.totalCoeff[12] != 0 { 2 } else { 0 };
            bS[13].left = if m.totalCoeff[11] != 0 || m.totalCoeff[10] != 0 { 2 } else { 0 };
            bS[15].left = if m.totalCoeff[15] != 0 || m.totalCoeff[14] != 0 { 2 } else { 0 };
            bS[2].left = InnerBoundaryStrength(mb, 4, 1);
            bS[6].left = InnerBoundaryStrength(mb, 6, 3);
            bS[10].left = InnerBoundaryStrength(mb, 12, 9);
            bS[14].left = InnerBoundaryStrength(mb, 14, 11);
        } else {
            bS[4].top = InnerBoundaryStrength(mb, mb4x4Index[4], mb4x4Index[0]);
            bS[5].top = InnerBoundaryStrength(mb, mb4x4Index[5], mb4x4Index[1]);
            bS[6].top = InnerBoundaryStrength(mb, mb4x4Index[6], mb4x4Index[2]);
            bS[7].top = InnerBoundaryStrength(mb, mb4x4Index[7], mb4x4Index[3]);
            bS[8].top = InnerBoundaryStrength(mb, mb4x4Index[8], mb4x4Index[4]);
            bS[9].top = InnerBoundaryStrength(mb, mb4x4Index[9], mb4x4Index[5]);
            bS[10].top = InnerBoundaryStrength(mb, mb4x4Index[10], mb4x4Index[6]);
            bS[11].top = InnerBoundaryStrength(mb, mb4x4Index[11], mb4x4Index[7]);
            bS[12].top = InnerBoundaryStrength(mb, mb4x4Index[12], mb4x4Index[8]);
            bS[13].top = InnerBoundaryStrength(mb, mb4x4Index[13], mb4x4Index[9]);
            bS[14].top = InnerBoundaryStrength(mb, mb4x4Index[14], mb4x4Index[10]);
            bS[15].top = InnerBoundaryStrength(mb, mb4x4Index[15], mb4x4Index[11]);

            bS[1].left = InnerBoundaryStrength(mb, mb4x4Index[1], mb4x4Index[0]);
            bS[2].left = InnerBoundaryStrength(mb, mb4x4Index[2], mb4x4Index[1]);
            bS[3].left = InnerBoundaryStrength(mb, mb4x4Index[3], mb4x4Index[2]);
            bS[5].left = InnerBoundaryStrength(mb, mb4x4Index[5], mb4x4Index[4]);
            bS[6].left = InnerBoundaryStrength(mb, mb4x4Index[6], mb4x4Index[5]);
            bS[7].left = InnerBoundaryStrength(mb, mb4x4Index[7], mb4x4Index[6]);
            bS[9].left = InnerBoundaryStrength(mb, mb4x4Index[9], mb4x4Index[8]);
            bS[10].left = InnerBoundaryStrength(mb, mb4x4Index[10], mb4x4Index[9]);
            bS[11].left = InnerBoundaryStrength(mb, mb4x4Index[11], mb4x4Index[10]);
            bS[13].left = InnerBoundaryStrength(mb, mb4x4Index[13], mb4x4Index[12]);
            bS[14].left = InnerBoundaryStrength(mb, mb4x4Index[14], mb4x4Index[13]);
            bS[15].left = InnerBoundaryStrength(mb, mb4x4Index[15], mb4x4Index[14]);
        }
        if nonZeroBs == 0
            && (bS[4].top != 0
                || bS[5].top != 0
                || bS[6].top != 0
                || bS[7].top != 0
                || bS[8].top != 0
                || bS[9].top != 0
                || bS[10].top != 0
                || bS[11].top != 0
                || bS[12].top != 0
                || bS[13].top != 0
                || bS[14].top != 0
                || bS[15].top != 0
                || bS[1].left != 0
                || bS[2].left != 0
                || bS[3].left != 0
                || bS[5].left != 0
                || bS[6].left != 0
                || bS[7].left != 0
                || bS[9].left != 0
                || bS[10].left != 0
                || bS[11].left != 0
                || bS[13].left != 0
                || bS[14].left != 0
                || bS[15].left != 0)
        {
            nonZeroBs = HANTRO_TRUE;
        }
    }

    nonZeroBs
}

/*------------------------------------------------------------------------------

    Function: GetLumaEdgeThresholds

        Functional description:
            Compute alpha, beta and tc0 thresholds for inner, left and top
            luma edges of a macroblock.

------------------------------------------------------------------------------*/
unsafe fn GetLumaEdgeThresholds(
    thresholds: *mut edgeThreshold_t,
    mb: *mut mbStorage_t,
    filteringFlags: u32,
) {
    let mut indexA: u32;
    let mut indexB: u32;
    let mut qpAv: u32;
    let qp: u32;
    let mut qpTmp: u32;

    let thresholds = &mut *(thresholds as *mut [edgeThreshold_t; 3]);

    qp = (*mb).qpY;

    indexA = CLIP3!(0, 51, qp as i32 + (*mb).filterOffsetA) as u32;
    indexB = CLIP3!(0, 51, qp as i32 + (*mb).filterOffsetB) as u32;

    thresholds[INNER as usize].alpha = alphas[indexA as usize] as u32;
    thresholds[INNER as usize].beta = betas[indexB as usize] as u32;
    thresholds[INNER as usize].tc0 = tc0[indexA as usize].as_ptr();

    if filteringFlags & FILTER_TOP_EDGE != 0 {
        qpTmp = (*(*mb).mbB).qpY;
        if qpTmp != qp {
            qpAv = (qp + qpTmp + 1) >> 1;

            indexA = CLIP3!(0, 51, qpAv as i32 + (*mb).filterOffsetA) as u32;
            indexB = CLIP3!(0, 51, qpAv as i32 + (*mb).filterOffsetB) as u32;

            thresholds[TOP as usize].alpha = alphas[indexA as usize] as u32;
            thresholds[TOP as usize].beta = betas[indexB as usize] as u32;
            thresholds[TOP as usize].tc0 = tc0[indexA as usize].as_ptr();
        } else {
            thresholds[TOP as usize].alpha = thresholds[INNER as usize].alpha;
            thresholds[TOP as usize].beta = thresholds[INNER as usize].beta;
            thresholds[TOP as usize].tc0 = thresholds[INNER as usize].tc0;
        }
    }
    if filteringFlags & FILTER_LEFT_EDGE != 0 {
        qpTmp = (*(*mb).mbA).qpY;
        if qpTmp != qp {
            qpAv = (qp + qpTmp + 1) >> 1;

            indexA = CLIP3!(0, 51, qpAv as i32 + (*mb).filterOffsetA) as u32;
            indexB = CLIP3!(0, 51, qpAv as i32 + (*mb).filterOffsetB) as u32;

            thresholds[LEFT as usize].alpha = alphas[indexA as usize] as u32;
            thresholds[LEFT as usize].beta = betas[indexB as usize] as u32;
            thresholds[LEFT as usize].tc0 = tc0[indexA as usize].as_ptr();
        } else {
            thresholds[LEFT as usize].alpha = thresholds[INNER as usize].alpha;
            thresholds[LEFT as usize].beta = thresholds[INNER as usize].beta;
            thresholds[LEFT as usize].tc0 = thresholds[INNER as usize].tc0;
        }
    }
}

/*------------------------------------------------------------------------------

    Function: GetChromaEdgeThresholds

        Functional description:
            Compute alpha, beta and tc0 thresholds for inner, left and top
            chroma edges of a macroblock.

------------------------------------------------------------------------------*/
unsafe fn GetChromaEdgeThresholds(
    thresholds: *mut edgeThreshold_t,
    mb: *mut mbStorage_t,
    filteringFlags: u32,
    chromaQpIndexOffset: i32,
) {
    let mut indexA: u32;
    let mut indexB: u32;
    let mut qpAv: u32;
    let mut qp: u32;
    let mut qpTmp: u32;

    let thresholds = &mut *(thresholds as *mut [edgeThreshold_t; 3]);

    qp = (*mb).qpY;
    qp = h264bsdQpC[CLIP3!(0, 51, qp as i32 + chromaQpIndexOffset) as usize];

    indexA = CLIP3!(0, 51, qp as i32 + (*mb).filterOffsetA) as u32;
    indexB = CLIP3!(0, 51, qp as i32 + (*mb).filterOffsetB) as u32;

    thresholds[INNER as usize].alpha = alphas[indexA as usize] as u32;
    thresholds[INNER as usize].beta = betas[indexB as usize] as u32;
    thresholds[INNER as usize].tc0 = tc0[indexA as usize].as_ptr();

    if filteringFlags & FILTER_TOP_EDGE != 0 {
        qpTmp = (*(*mb).mbB).qpY;
        if qpTmp != (*mb).qpY {
            qpTmp = h264bsdQpC[CLIP3!(0, 51, qpTmp as i32 + chromaQpIndexOffset) as usize];
            qpAv = (qp + qpTmp + 1) >> 1;

            indexA = CLIP3!(0, 51, qpAv as i32 + (*mb).filterOffsetA) as u32;
            indexB = CLIP3!(0, 51, qpAv as i32 + (*mb).filterOffsetB) as u32;

            thresholds[TOP as usize].alpha = alphas[indexA as usize] as u32;
            thresholds[TOP as usize].beta = betas[indexB as usize] as u32;
            thresholds[TOP as usize].tc0 = tc0[indexA as usize].as_ptr();
        } else {
            thresholds[TOP as usize].alpha = thresholds[INNER as usize].alpha;
            thresholds[TOP as usize].beta = thresholds[INNER as usize].beta;
            thresholds[TOP as usize].tc0 = thresholds[INNER as usize].tc0;
        }
    }
    if filteringFlags & FILTER_LEFT_EDGE != 0 {
        qpTmp = (*(*mb).mbA).qpY;
        if qpTmp != (*mb).qpY {
            qpTmp = h264bsdQpC[CLIP3!(0, 51, qpTmp as i32 + chromaQpIndexOffset) as usize];
            qpAv = (qp + qpTmp + 1) >> 1;

            indexA = CLIP3!(0, 51, qpAv as i32 + (*mb).filterOffsetA) as u32;
            indexB = CLIP3!(0, 51, qpAv as i32 + (*mb).filterOffsetB) as u32;

            thresholds[LEFT as usize].alpha = alphas[indexA as usize] as u32;
            thresholds[LEFT as usize].beta = betas[indexB as usize] as u32;
            thresholds[LEFT as usize].tc0 = tc0[indexA as usize].as_ptr();
        } else {
            thresholds[LEFT as usize].alpha = thresholds[INNER as usize].alpha;
            thresholds[LEFT as usize].beta = thresholds[INNER as usize].beta;
            thresholds[LEFT as usize].tc0 = thresholds[INNER as usize].tc0;
        }
    }
}

/*------------------------------------------------------------------------------

    Function: FilterLuma

        Functional description:
            Function to filter all luma edges of a macroblock

------------------------------------------------------------------------------*/
unsafe fn FilterLuma(
    data: *mut u8,
    bS: *const bS_t,
    thresholds: *const edgeThreshold_t,
    width: u32,
) {
    let mut vblock: u32;
    let mut tmp: *const bS_t;
    let mut ptr: *mut u8;
    let mut offset: u32;

    ptr = data;
    tmp = bS;

    offset = TOP;

    /* loop block rows, perform filtering for all vertical edges of the block
     * row first, then filter each horizontal edge of the row */
    vblock = 4;
    while vblock != 0 {
        vblock -= 1;

        /* only perform filtering if bS is non-zero, first of the four
         * FilterVerLumaEdge handles the left edge of the macroblock, others
         * filter inner edges */
        if (*tmp.add(0)).left != 0 {
            FilterVerLumaEdge(ptr, (*tmp.add(0)).left, thresholds.add(LEFT as usize), width);
        }
        if (*tmp.add(1)).left != 0 {
            FilterVerLumaEdge(
                ptr.add(4),
                (*tmp.add(1)).left,
                thresholds.add(INNER as usize),
                width,
            );
        }
        if (*tmp.add(2)).left != 0 {
            FilterVerLumaEdge(
                ptr.add(8),
                (*tmp.add(2)).left,
                thresholds.add(INNER as usize),
                width,
            );
        }
        if (*tmp.add(3)).left != 0 {
            FilterVerLumaEdge(
                ptr.add(12),
                (*tmp.add(3)).left,
                thresholds.add(INNER as usize),
                width,
            );
        }

        /* if bS is equal for all horizontal edges of the row -> perform
         * filtering with FilterHorLuma, otherwise use FilterHorLumaEdge for
         * each edge separately. offset variable indicates top macroblock edge
         * on the first loop round, inner edge for the other rounds */
        if (*tmp.add(0)).top == (*tmp.add(1)).top
            && (*tmp.add(1)).top == (*tmp.add(2)).top
            && (*tmp.add(2)).top == (*tmp.add(3)).top
        {
            if (*tmp.add(0)).top != 0 {
                FilterHorLuma(
                    ptr,
                    (*tmp.add(0)).top,
                    thresholds.add(offset as usize),
                    width as i32,
                );
            }
        } else {
            if (*tmp.add(0)).top != 0 {
                FilterHorLumaEdge(
                    ptr,
                    (*tmp.add(0)).top,
                    thresholds.add(offset as usize),
                    width as i32,
                );
            }
            if (*tmp.add(1)).top != 0 {
                FilterHorLumaEdge(
                    ptr.add(4),
                    (*tmp.add(1)).top,
                    thresholds.add(offset as usize),
                    width as i32,
                );
            }
            if (*tmp.add(2)).top != 0 {
                FilterHorLumaEdge(
                    ptr.add(8),
                    (*tmp.add(2)).top,
                    thresholds.add(offset as usize),
                    width as i32,
                );
            }
            if (*tmp.add(3)).top != 0 {
                FilterHorLumaEdge(
                    ptr.add(12),
                    (*tmp.add(3)).top,
                    thresholds.add(offset as usize),
                    width as i32,
                );
            }
        }

        /* four pixel rows ahead, i.e. next row of 4x4-blocks */
        ptr = ptr.add((width * 4) as usize);
        tmp = tmp.add(4);
        offset = INNER;
    }
}

/*------------------------------------------------------------------------------

    Function: FilterChroma

        Functional description:
            Function to filter all chroma edges of a macroblock

------------------------------------------------------------------------------*/
unsafe fn FilterChroma(
    mut dataCb: *mut u8,
    mut dataCr: *mut u8,
    bS: *const bS_t,
    thresholds: *const edgeThreshold_t,
    width: u32,
) {
    let mut vblock: u32;
    let mut tmp: *const bS_t;
    let mut offset: u32;

    tmp = bS;
    offset = TOP;

    /* loop block rows, perform filtering for all vertical edges of the block
     * row first, then filter each horizontal edge of the row */
    vblock = 0;
    while vblock < 2 {
        /* only perform filtering if bS is non-zero, first two of the four
         * FilterVerChromaEdge calls handle the left edge of the macroblock,
         * others filter the inner edge. Note that as chroma uses bS values
         * determined for luma edges, each bS is used only for 2 pixels of
         * a 4-pixel edge */
        if (*tmp.add(0)).left != 0 {
            FilterVerChromaEdge(dataCb, (*tmp.add(0)).left, thresholds.add(LEFT as usize), width);
            FilterVerChromaEdge(dataCr, (*tmp.add(0)).left, thresholds.add(LEFT as usize), width);
        }
        if (*tmp.add(4)).left != 0 {
            FilterVerChromaEdge(
                dataCb.add((2 * width) as usize),
                (*tmp.add(4)).left,
                thresholds.add(LEFT as usize),
                width,
            );
            FilterVerChromaEdge(
                dataCr.add((2 * width) as usize),
                (*tmp.add(4)).left,
                thresholds.add(LEFT as usize),
                width,
            );
        }
        if (*tmp.add(2)).left != 0 {
            FilterVerChromaEdge(
                dataCb.add(4),
                (*tmp.add(2)).left,
                thresholds.add(INNER as usize),
                width,
            );
            FilterVerChromaEdge(
                dataCr.add(4),
                (*tmp.add(2)).left,
                thresholds.add(INNER as usize),
                width,
            );
        }
        if (*tmp.add(6)).left != 0 {
            FilterVerChromaEdge(
                dataCb.add((2 * width + 4) as usize),
                (*tmp.add(6)).left,
                thresholds.add(INNER as usize),
                width,
            );
            FilterVerChromaEdge(
                dataCr.add((2 * width + 4) as usize),
                (*tmp.add(6)).left,
                thresholds.add(INNER as usize),
                width,
            );
        }

        /* if bS is equal for all horizontal edges of the row -> perform
         * filtering with FilterHorChroma, otherwise use FilterHorChromaEdge
         * for each edge separately. offset variable indicates top macroblock
         * edge on the first loop round, inner edge for the second */
        if (*tmp.add(0)).top == (*tmp.add(1)).top
            && (*tmp.add(1)).top == (*tmp.add(2)).top
            && (*tmp.add(2)).top == (*tmp.add(3)).top
        {
            if (*tmp.add(0)).top != 0 {
                FilterHorChroma(
                    dataCb,
                    (*tmp.add(0)).top,
                    thresholds.add(offset as usize),
                    width as i32,
                );
                FilterHorChroma(
                    dataCr,
                    (*tmp.add(0)).top,
                    thresholds.add(offset as usize),
                    width as i32,
                );
            }
        } else {
            if (*tmp.add(0)).top != 0 {
                FilterHorChromaEdge(
                    dataCb,
                    (*tmp.add(0)).top,
                    thresholds.add(offset as usize),
                    width as i32,
                );
                FilterHorChromaEdge(
                    dataCr,
                    (*tmp.add(0)).top,
                    thresholds.add(offset as usize),
                    width as i32,
                );
            }
            if (*tmp.add(1)).top != 0 {
                FilterHorChromaEdge(
                    dataCb.add(2),
                    (*tmp.add(1)).top,
                    thresholds.add(offset as usize),
                    width as i32,
                );
                FilterHorChromaEdge(
                    dataCr.add(2),
                    (*tmp.add(1)).top,
                    thresholds.add(offset as usize),
                    width as i32,
                );
            }
            if (*tmp.add(2)).top != 0 {
                FilterHorChromaEdge(
                    dataCb.add(4),
                    (*tmp.add(2)).top,
                    thresholds.add(offset as usize),
                    width as i32,
                );
                FilterHorChromaEdge(
                    dataCr.add(4),
                    (*tmp.add(2)).top,
                    thresholds.add(offset as usize),
                    width as i32,
                );
            }
            if (*tmp.add(3)).top != 0 {
                FilterHorChromaEdge(
                    dataCb.add(6),
                    (*tmp.add(3)).top,
                    thresholds.add(offset as usize),
                    width as i32,
                );
                FilterHorChromaEdge(
                    dataCr.add(6),
                    (*tmp.add(3)).top,
                    thresholds.add(offset as usize),
                    width as i32,
                );
            }
        }

        tmp = tmp.add(8);
        dataCb = dataCb.add((width * 4) as usize);
        dataCr = dataCr.add((width * 4) as usize);
        offset = INNER;
        vblock += 1;
    }
}
