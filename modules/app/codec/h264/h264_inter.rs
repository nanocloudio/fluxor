// h264bsd inter prediction — mechanical Rust port of
// h264bsd_inter_prediction.c (plain build path, H264DEC_OMXDL undefined;
// the OMXDL variant of h264bsdInterPrediction is skipped).
// Ported per scratchpad PORT_RULES.md; C names kept verbatim.

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
use super::h264_macroblock::*;
use super::h264_neighbour::*;
use super::h264_reconstruct::*;
use super::h264_dpb::*;

/*------------------------------------------------------------------------------
    3. Module defines
------------------------------------------------------------------------------*/

#[repr(C)]
#[derive(Clone, Copy)]
struct interNeighbour_t {
    available: u32,
    refIndex: u32,
    mv: mv_t,
}

const fn nb(mb: neighbourMb_e, index: u8) -> neighbour_t {
    neighbour_t { mb, index }
}

static N_A_SUB_PART: [[[neighbour_t; 4]; 4]; 4] = [
    [
        [nb(MB_A, 5), nb(MB_NA, 0), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_A, 5), nb(MB_A, 7), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_A, 5), nb(MB_CURR, 0), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_A, 5), nb(MB_CURR, 0), nb(MB_A, 7), nb(MB_CURR, 2)],
    ],
    [
        [nb(MB_CURR, 1), nb(MB_NA, 0), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_CURR, 1), nb(MB_CURR, 3), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_CURR, 1), nb(MB_CURR, 4), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_CURR, 1), nb(MB_CURR, 4), nb(MB_CURR, 3), nb(MB_CURR, 6)],
    ],
    [
        [nb(MB_A, 13), nb(MB_NA, 0), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_A, 13), nb(MB_A, 15), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_A, 13), nb(MB_CURR, 8), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_A, 13), nb(MB_CURR, 8), nb(MB_A, 15), nb(MB_CURR, 10)],
    ],
    [
        [nb(MB_CURR, 9), nb(MB_NA, 0), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_CURR, 9), nb(MB_CURR, 11), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_CURR, 9), nb(MB_CURR, 12), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_CURR, 9), nb(MB_CURR, 12), nb(MB_CURR, 11), nb(MB_CURR, 14)],
    ],
];

static N_B_SUB_PART: [[[neighbour_t; 4]; 4]; 4] = [
    [
        [nb(MB_B, 10), nb(MB_NA, 0), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_B, 10), nb(MB_CURR, 0), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_B, 10), nb(MB_B, 11), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_B, 10), nb(MB_B, 11), nb(MB_CURR, 0), nb(MB_CURR, 1)],
    ],
    [
        [nb(MB_B, 14), nb(MB_NA, 0), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_B, 14), nb(MB_CURR, 4), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_B, 14), nb(MB_B, 15), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_B, 14), nb(MB_B, 15), nb(MB_CURR, 4), nb(MB_CURR, 5)],
    ],
    [
        [nb(MB_CURR, 2), nb(MB_NA, 0), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_CURR, 2), nb(MB_CURR, 8), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_CURR, 2), nb(MB_CURR, 3), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_CURR, 2), nb(MB_CURR, 3), nb(MB_CURR, 8), nb(MB_CURR, 9)],
    ],
    [
        [nb(MB_CURR, 6), nb(MB_NA, 0), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_CURR, 6), nb(MB_CURR, 12), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_CURR, 6), nb(MB_CURR, 7), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_CURR, 6), nb(MB_CURR, 7), nb(MB_CURR, 12), nb(MB_CURR, 13)],
    ],
];

static N_C_SUB_PART: [[[neighbour_t; 4]; 4]; 4] = [
    [
        [nb(MB_B, 14), nb(MB_NA, 0), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_B, 14), nb(MB_NA, 4), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_B, 11), nb(MB_B, 14), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_B, 11), nb(MB_B, 14), nb(MB_CURR, 1), nb(MB_NA, 4)],
    ],
    [
        [nb(MB_C, 10), nb(MB_NA, 0), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_C, 10), nb(MB_NA, 0), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_B, 15), nb(MB_C, 10), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_B, 15), nb(MB_C, 10), nb(MB_CURR, 5), nb(MB_NA, 0)],
    ],
    [
        [nb(MB_CURR, 6), nb(MB_NA, 0), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_CURR, 6), nb(MB_NA, 12), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_CURR, 3), nb(MB_CURR, 6), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_CURR, 3), nb(MB_CURR, 6), nb(MB_CURR, 9), nb(MB_NA, 12)],
    ],
    [
        [nb(MB_NA, 2), nb(MB_NA, 0), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_NA, 2), nb(MB_NA, 8), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_CURR, 7), nb(MB_NA, 2), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_CURR, 7), nb(MB_NA, 2), nb(MB_CURR, 13), nb(MB_NA, 8)],
    ],
];

static N_D_SUB_PART: [[[neighbour_t; 4]; 4]; 4] = [
    [
        [nb(MB_D, 15), nb(MB_NA, 0), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_D, 15), nb(MB_A, 5), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_D, 15), nb(MB_B, 10), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_D, 15), nb(MB_B, 10), nb(MB_A, 5), nb(MB_CURR, 0)],
    ],
    [
        [nb(MB_B, 11), nb(MB_NA, 0), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_B, 11), nb(MB_CURR, 1), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_B, 11), nb(MB_B, 14), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_B, 11), nb(MB_B, 14), nb(MB_CURR, 1), nb(MB_CURR, 4)],
    ],
    [
        [nb(MB_A, 7), nb(MB_NA, 0), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_A, 7), nb(MB_A, 13), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_A, 7), nb(MB_CURR, 2), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_A, 7), nb(MB_CURR, 2), nb(MB_A, 13), nb(MB_CURR, 8)],
    ],
    [
        [nb(MB_CURR, 3), nb(MB_NA, 0), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_CURR, 3), nb(MB_CURR, 9), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_CURR, 3), nb(MB_CURR, 6), nb(MB_NA, 0), nb(MB_NA, 0)],
        [nb(MB_CURR, 3), nb(MB_CURR, 6), nb(MB_CURR, 9), nb(MB_CURR, 12)],
    ],
];

/*------------------------------------------------------------------------------

    Function: h264bsdInterPrediction

        Functional description:
          Processes one inter macroblock. Performs motion vector prediction
          and reconstructs prediction macroblock. Writes the final macroblock
          (prediction + residual) into the output image (currImage)

        Returns:
          HANTRO_OK     success
          HANTRO_NOK    error in motion vector prediction

------------------------------------------------------------------------------*/
pub unsafe fn h264bsdInterPrediction(
    pMb: &mut mbStorage_t,
    pMbLayer: &mut macroblockLayer_t,
    dpb: &mut dpbStorage_t,
    mbNum: u32,
    image: &mut image_t,
    data: *mut u8,
) -> u32 {
    /* Variables */

    let mut i: u32;
    let mut x: u32;
    let mut y: u32;
    let mut row: u32;
    let mut col: u32;
    let mut subPartMode: subMbPartMode_e;

    /* C parameter name is currImage; manifest uses `image` */
    let currImage = image;

    /* Code */

    row = udiv(mbNum, currImage.width);
    col = mbNum - row * currImage.width;
    row *= 16;
    col *= 16;

    let mut refImage = image_t {
        data: core::ptr::null_mut(),
        width: currImage.width,
        height: currImage.height,
        luma: core::ptr::null_mut(),
        cb: core::ptr::null_mut(),
        cr: core::ptr::null_mut(),
    };

    match pMb.mbType {
        P_Skip | P_L0_16x16 => {
            if MvPrediction16x16(pMb, &mut pMbLayer.mbPred, dpb) != HANTRO_OK {
                return HANTRO_NOK;
            }
            refImage.data = pMb.refAddr[0];
            h264bsdPredictSamples(data, &pMb.mv[0], &refImage, col, row, 0, 0, 16, 16);
        }

        P_L0_L0_16x8 => {
            if MvPrediction16x8(pMb, &mut pMbLayer.mbPred, dpb) != HANTRO_OK {
                return HANTRO_NOK;
            }
            refImage.data = pMb.refAddr[0];
            h264bsdPredictSamples(data, &pMb.mv[0], &refImage, col, row, 0, 0, 16, 8);
            refImage.data = pMb.refAddr[2];
            h264bsdPredictSamples(data, &pMb.mv[8], &refImage, col, row, 0, 8, 16, 8);
        }

        P_L0_L0_8x16 => {
            if MvPrediction8x16(pMb, &mut pMbLayer.mbPred, dpb) != HANTRO_OK {
                return HANTRO_NOK;
            }
            refImage.data = pMb.refAddr[0];
            h264bsdPredictSamples(data, &pMb.mv[0], &refImage, col, row, 0, 0, 8, 16);
            refImage.data = pMb.refAddr[1];
            h264bsdPredictSamples(data, &pMb.mv[4], &refImage, col, row, 8, 0, 8, 16);
        }

        _ => {
            /* P_8x8 and P_8x8ref0 */
            if MvPrediction8x8(pMb, &mut pMbLayer.subMbPred, dpb) != HANTRO_OK {
                return HANTRO_NOK;
            }
            i = 0;
            while i < 4 {
                refImage.data = pMb.refAddr[i as usize];
                subPartMode =
                    h264bsdSubMbPartMode(pMbLayer.subMbPred.subMbType[i as usize]);
                x = if i & 0x1 != 0 { 8 } else { 0 };
                y = if i < 2 { 0 } else { 8 };
                match subPartMode {
                    MB_SP_8x8 => {
                        h264bsdPredictSamples(
                            data,
                            &pMb.mv[(4 * i) as usize],
                            &refImage,
                            col,
                            row,
                            x,
                            y,
                            8,
                            8,
                        );
                    }

                    MB_SP_8x4 => {
                        h264bsdPredictSamples(
                            data,
                            &pMb.mv[(4 * i) as usize],
                            &refImage,
                            col,
                            row,
                            x,
                            y,
                            8,
                            4,
                        );
                        h264bsdPredictSamples(
                            data,
                            &pMb.mv[(4 * i + 2) as usize],
                            &refImage,
                            col,
                            row,
                            x,
                            y + 4,
                            8,
                            4,
                        );
                    }

                    MB_SP_4x8 => {
                        h264bsdPredictSamples(
                            data,
                            &pMb.mv[(4 * i) as usize],
                            &refImage,
                            col,
                            row,
                            x,
                            y,
                            4,
                            8,
                        );
                        h264bsdPredictSamples(
                            data,
                            &pMb.mv[(4 * i + 1) as usize],
                            &refImage,
                            col,
                            row,
                            x + 4,
                            y,
                            4,
                            8,
                        );
                    }

                    _ => {
                        h264bsdPredictSamples(
                            data,
                            &pMb.mv[(4 * i) as usize],
                            &refImage,
                            col,
                            row,
                            x,
                            y,
                            4,
                            4,
                        );
                        h264bsdPredictSamples(
                            data,
                            &pMb.mv[(4 * i + 1) as usize],
                            &refImage,
                            col,
                            row,
                            x + 4,
                            y,
                            4,
                            4,
                        );
                        h264bsdPredictSamples(
                            data,
                            &pMb.mv[(4 * i + 2) as usize],
                            &refImage,
                            col,
                            row,
                            x,
                            y + 4,
                            4,
                            4,
                        );
                        h264bsdPredictSamples(
                            data,
                            &pMb.mv[(4 * i + 3) as usize],
                            &refImage,
                            col,
                            row,
                            x + 4,
                            y + 4,
                            4,
                            4,
                        );
                    }
                }
                i += 1;
            }
        }
    }

    /* if decoded flag > 1 -> mb has already been successfully decoded and
     * written to output -> do not write again */
    if pMb.decoded > 1 {
        return HANTRO_OK;
    }

    if pMb.mbType != P_Skip {
        h264bsdWriteOutputBlocks(
            currImage,
            mbNum,
            data,
            pMbLayer.residual.level.as_mut_ptr(),
        );
    } else {
        h264bsdWriteMacroblock(currImage, data);
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: MvPrediction16x16

        Functional description:
            Motion vector prediction for 16x16 partition mode

------------------------------------------------------------------------------*/

unsafe fn MvPrediction16x16(
    pMb: &mut mbStorage_t,
    mbPred: &mut mbPred_t,
    dpb: &mut dpbStorage_t,
) -> u32 {
    /* Variables */

    let mut mv: mv_t = mv_t { hor: 0, ver: 0 };
    let mut mvPred: mv_t = mv_t { hor: 0, ver: 0 };
    /* A, B, C */
    let mut a: [interNeighbour_t; 3] = [interNeighbour_t {
        available: 0,
        refIndex: 0,
        mv: mv_t { hor: 0, ver: 0 },
    }; 3];
    let refIndex: u32;
    let tmp: *mut u8;

    /* Code */

    refIndex = mbPred.refIdxL0[0];

    GetInterNeighbour(pMb.sliceId, pMb.mbA, &mut a[0], 5);
    GetInterNeighbour(pMb.sliceId, pMb.mbB, &mut a[1], 10);
    /* we test just that both MVs are zero,
     * i.e. a[0].mv.hor == 0 && a[0].mv.ver == 0 */
    let tmpMv1 = (&a[0].mv) as *const mv_t as *const u32;
    let tmpMv2 = (&a[1].mv) as *const mv_t as *const u32;
    if pMb.mbType == P_Skip
        && (a[0].available == 0
            || a[1].available == 0
            || (a[0].refIndex == 0 && *tmpMv1 == 0)
            || (a[1].refIndex == 0 && *tmpMv2 == 0))
    {
        mv.hor = 0;
        mv.ver = 0;
    } else {
        mv = mbPred.mvdL0[0];
        GetInterNeighbour(pMb.sliceId, pMb.mbC, &mut a[2], 10);
        if a[2].available == 0 {
            GetInterNeighbour(pMb.sliceId, pMb.mbD, &mut a[2], 15);
        }

        GetPredictionMv(&mut mvPred, &a, refIndex);

        mv.hor = mv.hor.wrapping_add(mvPred.hor);
        mv.ver = mv.ver.wrapping_add(mvPred.ver);

        /* horizontal motion vector range [-2048, 2047.75] */
        if (mv.hor as i32 + 8192) as u32 >= 16384 {
            return HANTRO_NOK;
        }

        /* vertical motion vector range [-512, 511.75]
         * (smaller for low levels) */
        if (mv.ver as i32 + 2048) as u32 >= 4096 {
            return HANTRO_NOK;
        }
    }

    tmp = h264bsdGetRefPicData(dpb, refIndex);
    if tmp.is_null() {
        return HANTRO_NOK;
    }

    pMb.mv[0] = mv;
    pMb.mv[1] = mv;
    pMb.mv[2] = mv;
    pMb.mv[3] = mv;
    pMb.mv[4] = mv;
    pMb.mv[5] = mv;
    pMb.mv[6] = mv;
    pMb.mv[7] = mv;
    pMb.mv[8] = mv;
    pMb.mv[9] = mv;
    pMb.mv[10] = mv;
    pMb.mv[11] = mv;
    pMb.mv[12] = mv;
    pMb.mv[13] = mv;
    pMb.mv[14] = mv;
    pMb.mv[15] = mv;

    pMb.refPic[0] = refIndex;
    pMb.refPic[1] = refIndex;
    pMb.refPic[2] = refIndex;
    pMb.refPic[3] = refIndex;
    pMb.refAddr[0] = tmp;
    pMb.refAddr[1] = tmp;
    pMb.refAddr[2] = tmp;
    pMb.refAddr[3] = tmp;

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: MvPrediction16x8

        Functional description:
            Motion vector prediction for 16x8 partition mode

------------------------------------------------------------------------------*/

unsafe fn MvPrediction16x8(
    pMb: &mut mbStorage_t,
    mbPred: &mut mbPred_t,
    dpb: &mut dpbStorage_t,
) -> u32 {
    /* Variables */

    let mut mv: mv_t;
    let mut mvPred: mv_t = mv_t { hor: 0, ver: 0 };
    /* A, B, C */
    let mut a: [interNeighbour_t; 3] = [interNeighbour_t {
        available: 0,
        refIndex: 0,
        mv: mv_t { hor: 0, ver: 0 },
    }; 3];
    let mut refIndex: u32;
    let mut tmp: *mut u8;

    /* Code */

    mv = mbPred.mvdL0[0];
    refIndex = mbPred.refIdxL0[0];

    GetInterNeighbour(pMb.sliceId, pMb.mbB, &mut a[1], 10);

    if a[1].refIndex == refIndex {
        mvPred = a[1].mv;
    } else {
        GetInterNeighbour(pMb.sliceId, pMb.mbA, &mut a[0], 5);
        GetInterNeighbour(pMb.sliceId, pMb.mbC, &mut a[2], 10);
        if a[2].available == 0 {
            GetInterNeighbour(pMb.sliceId, pMb.mbD, &mut a[2], 15);
        }

        GetPredictionMv(&mut mvPred, &a, refIndex);
    }
    mv.hor = mv.hor.wrapping_add(mvPred.hor);
    mv.ver = mv.ver.wrapping_add(mvPred.ver);

    /* horizontal motion vector range [-2048, 2047.75] */
    if (mv.hor as i32 + 8192) as u32 >= 16384 {
        return HANTRO_NOK;
    }

    /* vertical motion vector range [-512, 511.75] (smaller for low levels) */
    if (mv.ver as i32 + 2048) as u32 >= 4096 {
        return HANTRO_NOK;
    }

    tmp = h264bsdGetRefPicData(dpb, refIndex);
    if tmp.is_null() {
        return HANTRO_NOK;
    }

    pMb.mv[0] = mv;
    pMb.mv[1] = mv;
    pMb.mv[2] = mv;
    pMb.mv[3] = mv;
    pMb.mv[4] = mv;
    pMb.mv[5] = mv;
    pMb.mv[6] = mv;
    pMb.mv[7] = mv;
    pMb.refPic[0] = refIndex;
    pMb.refPic[1] = refIndex;
    pMb.refAddr[0] = tmp;
    pMb.refAddr[1] = tmp;

    mv = mbPred.mvdL0[1];
    refIndex = mbPred.refIdxL0[1];

    GetInterNeighbour(pMb.sliceId, pMb.mbA, &mut a[0], 13);
    if a[0].refIndex == refIndex {
        mvPred = a[0].mv;
    } else {
        a[1].available = HANTRO_TRUE;
        a[1].refIndex = pMb.refPic[0];
        a[1].mv = pMb.mv[0];

        /* c is not available */
        GetInterNeighbour(pMb.sliceId, pMb.mbA, &mut a[2], 7);

        GetPredictionMv(&mut mvPred, &a, refIndex);
    }
    mv.hor = mv.hor.wrapping_add(mvPred.hor);
    mv.ver = mv.ver.wrapping_add(mvPred.ver);

    /* horizontal motion vector range [-2048, 2047.75] */
    if (mv.hor as i32 + 8192) as u32 >= 16384 {
        return HANTRO_NOK;
    }

    /* vertical motion vector range [-512, 511.75] (smaller for low levels) */
    if (mv.ver as i32 + 2048) as u32 >= 4096 {
        return HANTRO_NOK;
    }

    tmp = h264bsdGetRefPicData(dpb, refIndex);
    if tmp.is_null() {
        return HANTRO_NOK;
    }

    pMb.mv[8] = mv;
    pMb.mv[9] = mv;
    pMb.mv[10] = mv;
    pMb.mv[11] = mv;
    pMb.mv[12] = mv;
    pMb.mv[13] = mv;
    pMb.mv[14] = mv;
    pMb.mv[15] = mv;
    pMb.refPic[2] = refIndex;
    pMb.refPic[3] = refIndex;
    pMb.refAddr[2] = tmp;
    pMb.refAddr[3] = tmp;

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: MvPrediction8x16

        Functional description:
            Motion vector prediction for 8x16 partition mode

------------------------------------------------------------------------------*/

unsafe fn MvPrediction8x16(
    pMb: &mut mbStorage_t,
    mbPred: &mut mbPred_t,
    dpb: &mut dpbStorage_t,
) -> u32 {
    /* Variables */

    let mut mv: mv_t;
    let mut mvPred: mv_t = mv_t { hor: 0, ver: 0 };
    /* A, B, C */
    let mut a: [interNeighbour_t; 3] = [interNeighbour_t {
        available: 0,
        refIndex: 0,
        mv: mv_t { hor: 0, ver: 0 },
    }; 3];
    let mut refIndex: u32;
    let mut tmp: *mut u8;

    /* Code */

    mv = mbPred.mvdL0[0];
    refIndex = mbPred.refIdxL0[0];

    GetInterNeighbour(pMb.sliceId, pMb.mbA, &mut a[0], 5);

    if a[0].refIndex == refIndex {
        mvPred = a[0].mv;
    } else {
        GetInterNeighbour(pMb.sliceId, pMb.mbB, &mut a[1], 10);
        GetInterNeighbour(pMb.sliceId, pMb.mbB, &mut a[2], 14);
        if a[2].available == 0 {
            GetInterNeighbour(pMb.sliceId, pMb.mbD, &mut a[2], 15);
        }

        GetPredictionMv(&mut mvPred, &a, refIndex);
    }
    mv.hor = mv.hor.wrapping_add(mvPred.hor);
    mv.ver = mv.ver.wrapping_add(mvPred.ver);

    /* horizontal motion vector range [-2048, 2047.75] */
    if (mv.hor as i32 + 8192) as u32 >= 16384 {
        return HANTRO_NOK;
    }

    /* vertical motion vector range [-512, 511.75] (smaller for low levels) */
    if (mv.ver as i32 + 2048) as u32 >= 4096 {
        return HANTRO_NOK;
    }

    tmp = h264bsdGetRefPicData(dpb, refIndex);
    if tmp.is_null() {
        return HANTRO_NOK;
    }

    pMb.mv[0] = mv;
    pMb.mv[1] = mv;
    pMb.mv[2] = mv;
    pMb.mv[3] = mv;
    pMb.mv[8] = mv;
    pMb.mv[9] = mv;
    pMb.mv[10] = mv;
    pMb.mv[11] = mv;
    pMb.refPic[0] = refIndex;
    pMb.refPic[2] = refIndex;
    pMb.refAddr[0] = tmp;
    pMb.refAddr[2] = tmp;

    mv = mbPred.mvdL0[1];
    refIndex = mbPred.refIdxL0[1];

    GetInterNeighbour(pMb.sliceId, pMb.mbC, &mut a[2], 10);
    if a[2].available == 0 {
        GetInterNeighbour(pMb.sliceId, pMb.mbB, &mut a[2], 11);
    }
    if a[2].refIndex == refIndex {
        mvPred = a[2].mv;
    } else {
        a[0].available = HANTRO_TRUE;
        a[0].refIndex = pMb.refPic[0];
        a[0].mv = pMb.mv[0];

        GetInterNeighbour(pMb.sliceId, pMb.mbB, &mut a[1], 14);

        GetPredictionMv(&mut mvPred, &a, refIndex);
    }
    mv.hor = mv.hor.wrapping_add(mvPred.hor);
    mv.ver = mv.ver.wrapping_add(mvPred.ver);

    /* horizontal motion vector range [-2048, 2047.75] */
    if (mv.hor as i32 + 8192) as u32 >= 16384 {
        return HANTRO_NOK;
    }

    /* vertical motion vector range [-512, 511.75] (smaller for low levels) */
    if (mv.ver as i32 + 2048) as u32 >= 4096 {
        return HANTRO_NOK;
    }

    tmp = h264bsdGetRefPicData(dpb, refIndex);
    if tmp.is_null() {
        return HANTRO_NOK;
    }

    pMb.mv[4] = mv;
    pMb.mv[5] = mv;
    pMb.mv[6] = mv;
    pMb.mv[7] = mv;
    pMb.mv[12] = mv;
    pMb.mv[13] = mv;
    pMb.mv[14] = mv;
    pMb.mv[15] = mv;
    pMb.refPic[1] = refIndex;
    pMb.refPic[3] = refIndex;
    pMb.refAddr[1] = tmp;
    pMb.refAddr[3] = tmp;

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: MvPrediction8x8

        Functional description:
            Motion vector prediction for 8x8 partition mode

------------------------------------------------------------------------------*/

unsafe fn MvPrediction8x8(
    pMb: &mut mbStorage_t,
    subMbPred: &mut subMbPred_t,
    dpb: &mut dpbStorage_t,
) -> u32 {
    /* Variables */

    let mut i: u32;
    let mut j: u32;
    let mut numSubMbPart: u32;

    /* Code */

    i = 0;
    while i < 4 {
        numSubMbPart = h264bsdNumSubMbPart(subMbPred.subMbType[i as usize]);
        pMb.refPic[i as usize] = subMbPred.refIdxL0[i as usize];
        pMb.refAddr[i as usize] =
            h264bsdGetRefPicData(dpb, subMbPred.refIdxL0[i as usize]);
        if pMb.refAddr[i as usize].is_null() {
            return HANTRO_NOK;
        }
        j = 0;
        while j < numSubMbPart {
            if MvPrediction(pMb, subMbPred, i, j) != HANTRO_OK {
                return HANTRO_NOK;
            }
            j += 1;
        }
        i += 1;
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: MvPrediction

        Functional description:
            Perform motion vector prediction for sub-partition

------------------------------------------------------------------------------*/

unsafe fn MvPrediction(
    pMb: &mut mbStorage_t,
    subMbPred: &mut subMbPred_t,
    mbPartIdx: u32,
    subMbPartIdx: u32,
) -> u32 {
    /* Variables */

    let mut mv: mv_t;
    let mut mvPred: mv_t = mv_t { hor: 0, ver: 0 };
    let refIndex: u32;
    let subMbPartMode: subMbPartMode_e;
    let mut n: &neighbour_t;
    let mut nMb: *mut mbStorage_t;
    /* A, B, C */
    let mut a: [interNeighbour_t; 3] = [interNeighbour_t {
        available: 0,
        refIndex: 0,
        mv: mv_t { hor: 0, ver: 0 },
    }; 3];

    /* Code */

    mv = subMbPred.mvdL0[mbPartIdx as usize][subMbPartIdx as usize];
    subMbPartMode = h264bsdSubMbPartMode(subMbPred.subMbType[mbPartIdx as usize]);
    refIndex = subMbPred.refIdxL0[mbPartIdx as usize];

    n = &N_A_SUB_PART[mbPartIdx as usize][subMbPartMode as usize][subMbPartIdx as usize];
    nMb = h264bsdGetNeighbourMb(pMb, n.mb);
    GetInterNeighbour(pMb.sliceId, nMb, &mut a[0], n.index as u32);

    n = &N_B_SUB_PART[mbPartIdx as usize][subMbPartMode as usize][subMbPartIdx as usize];
    nMb = h264bsdGetNeighbourMb(pMb, n.mb);
    GetInterNeighbour(pMb.sliceId, nMb, &mut a[1], n.index as u32);

    n = &N_C_SUB_PART[mbPartIdx as usize][subMbPartMode as usize][subMbPartIdx as usize];
    nMb = h264bsdGetNeighbourMb(pMb, n.mb);
    GetInterNeighbour(pMb.sliceId, nMb, &mut a[2], n.index as u32);

    if a[2].available == 0 {
        n = &N_D_SUB_PART[mbPartIdx as usize][subMbPartMode as usize]
            [subMbPartIdx as usize];
        nMb = h264bsdGetNeighbourMb(pMb, n.mb);
        GetInterNeighbour(pMb.sliceId, nMb, &mut a[2], n.index as u32);
    }

    GetPredictionMv(&mut mvPred, &a, refIndex);

    mv.hor = mv.hor.wrapping_add(mvPred.hor);
    mv.ver = mv.ver.wrapping_add(mvPred.ver);

    /* horizontal motion vector range [-2048, 2047.75] */
    if (mv.hor as i32 + 8192) as u32 >= 16384 {
        return HANTRO_NOK;
    }

    /* vertical motion vector range [-512, 511.75] (smaller for low levels) */
    if (mv.ver as i32 + 2048) as u32 >= 4096 {
        return HANTRO_NOK;
    }

    match subMbPartMode {
        MB_SP_8x8 => {
            pMb.mv[(4 * mbPartIdx) as usize] = mv;
            pMb.mv[(4 * mbPartIdx + 1) as usize] = mv;
            pMb.mv[(4 * mbPartIdx + 2) as usize] = mv;
            pMb.mv[(4 * mbPartIdx + 3) as usize] = mv;
        }

        MB_SP_8x4 => {
            pMb.mv[(4 * mbPartIdx + 2 * subMbPartIdx) as usize] = mv;
            pMb.mv[(4 * mbPartIdx + 2 * subMbPartIdx + 1) as usize] = mv;
        }

        MB_SP_4x8 => {
            pMb.mv[(4 * mbPartIdx + subMbPartIdx) as usize] = mv;
            pMb.mv[(4 * mbPartIdx + subMbPartIdx + 2) as usize] = mv;
        }

        MB_SP_4x4 => {
            pMb.mv[(4 * mbPartIdx + subMbPartIdx) as usize] = mv;
        }

        _ => {}
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: MedianFilter

        Functional description:
            Median filtering for motion vector prediction

------------------------------------------------------------------------------*/

fn MedianFilter(a: i32, b: i32, c: i32) -> i32 {
    /* Variables */

    let mut max: i32;
    let mut min: i32;
    let mut med: i32;

    /* Code */

    max = a;
    min = a;
    med = a;
    if b > max {
        max = b;
    } else if b < min {
        min = b;
    }
    if c > max {
        med = max;
    } else if c < min {
        med = min;
    } else {
        med = c;
    }

    med
}

/*------------------------------------------------------------------------------

    Function: GetInterNeighbour

        Functional description:
            Get availability, reference index and motion vector of a neighbour

------------------------------------------------------------------------------*/

unsafe fn GetInterNeighbour(
    sliceId: u32,
    nMb: *mut mbStorage_t,
    n: &mut interNeighbour_t,
    index: u32,
) {
    n.available = HANTRO_FALSE;
    n.refIndex = 0xFFFFFFFF;
    n.mv.hor = 0;
    n.mv.ver = 0;

    if !nMb.is_null() && sliceId == (*nMb).sliceId {
        let mut tmp: u32;
        let tmpMv: mv_t;

        tmp = (*nMb).mbType;
        n.available = HANTRO_TRUE;
        /* MbPartPredMode "inlined" */
        if tmp <= P_8x8ref0 {
            tmpMv = (*nMb).mv[index as usize];
            tmp = (*nMb).refPic[(index >> 2) as usize];
            n.refIndex = tmp;
            n.mv = tmpMv;
        }
    }
}

/*------------------------------------------------------------------------------

    Function: GetPredictionMv

        Functional description:
            Compute motion vector predictor based on neighbours A, B and C

------------------------------------------------------------------------------*/

fn GetPredictionMv(mv: &mut mv_t, a: &[interNeighbour_t; 3], refIndex: u32) {
    if a[1].available != 0 || a[2].available != 0 || a[0].available == 0 {
        let isA: u32;
        let isB: u32;
        let isC: u32;
        isA = if a[0].refIndex == refIndex { HANTRO_TRUE } else { HANTRO_FALSE };
        isB = if a[1].refIndex == refIndex { HANTRO_TRUE } else { HANTRO_FALSE };
        isC = if a[2].refIndex == refIndex { HANTRO_TRUE } else { HANTRO_FALSE };

        if isA + isB + isC != 1 {
            mv.hor =
                MedianFilter(a[0].mv.hor as i32, a[1].mv.hor as i32, a[2].mv.hor as i32) as i16;
            mv.ver =
                MedianFilter(a[0].mv.ver as i32, a[1].mv.ver as i32, a[2].mv.ver as i32) as i16;
        } else if isA != 0 {
            *mv = a[0].mv;
        } else if isB != 0 {
            *mv = a[1].mv;
        } else {
            *mv = a[2].mv;
        }
    } else {
        *mv = a[0].mv;
    }
}
