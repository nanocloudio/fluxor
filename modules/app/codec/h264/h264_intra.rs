// Mechanical Rust port of h264bsd_intra_prediction.c (plain build path,
// H264DEC_OMXDL undefined) per the h264bsd → Rust port rules.
//
// Ported: h264bsdIntraPrediction, h264bsdGetNeighbourPels,
// h264bsdIntra16x16Prediction, h264bsdIntra4x4Prediction,
// h264bsdIntraChromaPrediction, h264bsdAddResidual,
// Intra16x16{Vertical,Horizontal,Dc,Plane}Prediction,
// IntraChroma{Dc,Horizontal,Vertical,Plane}Prediction,
// Get4x4NeighbourPels, Write4x4To16x16, all nine Intra4x4*Prediction
// modes, DetermineIntra4x4PredMode, plus the h264bsdBlockX/h264bsdBlockY
// and h264bsdClip tables (pub: shared with sibling translation units).
//
// Skipped: the H264DEC_OMXDL variants of h264bsdIntra16x16Prediction /
// h264bsdIntra4x4Prediction / h264bsdIntraChromaPrediction (OMXDL build
// only) and get_h264bsdClip() (JS-wrapper helper, dead in this build).

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

/* x- and y-coordinates for each block */
pub static h264bsdBlockX: [u32; 16] = [0, 4, 0, 4, 8, 12, 8, 12, 0, 4, 0, 4, 8, 12, 8, 12];
pub static h264bsdBlockY: [u32; 16] = [0, 0, 4, 4, 0, 0, 4, 4, 8, 8, 12, 12, 8, 8, 12, 12];

pub static h264bsdClip: [u8; 1280] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
    80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
    96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
    112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127,
    128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
    144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
    160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175,
    176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191,
    192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207,
    208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223,
    224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
    240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
];

/*------------------------------------------------------------------------------

    Function: h264bsdIntraPrediction

        Functional description:
          Processes one intra macroblock. Performs intra prediction using
          specified prediction mode. Writes the final macroblock
          (prediction + residual) into the output image (image)

        Inputs:
          pMb           pointer to macroblock specific information
          mbLayer       pointer to current macroblock data from stream
          image         pointer to output image
          mbNum         current macroblock number
          constrainedIntraPred  flag specifying if neighbouring inter
                                macroblocks are used in intra prediction
          data          pointer where output macroblock will be stored

        Outputs:
          pMb           structure is updated with current macroblock
          image         current macroblock is written into image
          data          current macroblock is stored here

        Returns:
          HANTRO_OK     success
          HANTRO_NOK    error in intra prediction

------------------------------------------------------------------------------*/
pub unsafe fn h264bsdIntraPrediction(
    pMb: &mut mbStorage_t,
    mbLayer: &mut macroblockLayer_t,
    image: &mut image_t,
    mbNum: u32,
    constrainedIntraPred: u32,
    data: *mut u8,
) -> u32 {
    /* pelAbove and pelLeft contain samples above and left to the current
     * macroblock. Above array contains also sample above-left to the current
     * mb as well as 4 samples above-right to the current mb (latter only for
     * luma) */
    /* lumD + lumB + lumC + cbD + cbB + crD + crB */
    let mut pelAbove = [0u8; 1 + 16 + 4 + 1 + 8 + 1 + 8];
    /* lumA + cbA + crA */
    let mut pelLeft = [0u8; 16 + 8 + 8];
    let mut tmp: u32;

    h264bsdGetNeighbourPels(image, pelAbove.as_mut_ptr(), pelLeft.as_mut_ptr(), mbNum);

    if h264bsdMbPartPredMode(pMb.mbType) == PRED_MODE_INTRA16x16 {
        tmp = h264bsdIntra16x16Prediction(
            pMb,
            data,
            mbLayer.residual.level.as_mut_ptr(),
            pelAbove.as_mut_ptr(),
            pelLeft.as_mut_ptr(),
            constrainedIntraPred,
        );
        if tmp != HANTRO_OK {
            return tmp;
        }
    } else {
        tmp = h264bsdIntra4x4Prediction(
            pMb,
            data,
            mbLayer,
            pelAbove.as_mut_ptr(),
            pelLeft.as_mut_ptr(),
            constrainedIntraPred,
        );
        if tmp != HANTRO_OK {
            return tmp;
        }
    }

    tmp = h264bsdIntraChromaPrediction(
        pMb,
        data.add(256),
        mbLayer.residual.level.as_mut_ptr().add(16),
        pelAbove.as_mut_ptr().add(21),
        pelLeft.as_mut_ptr().add(16),
        mbLayer.mbPred.intraChromaPredMode,
        constrainedIntraPred,
    );
    if tmp != HANTRO_OK {
        return tmp;
    }

    /* if decoded flag > 1 -> mb has already been successfully decoded and
     * written to output -> do not write again */
    if pMb.decoded > 1 {
        return HANTRO_OK;
    }

    h264bsdWriteMacroblock(image, data);

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: h264bsdGetNeighbourPels

        Functional description:
          Get pixel values from neighbouring macroblocks into 'above'
          and 'left' arrays.

------------------------------------------------------------------------------*/
pub unsafe fn h264bsdGetNeighbourPels(image: &image_t, above: *mut u8, left: *mut u8, mbNum: u32) {
    let mut above = above;
    let mut left = left;

    if mbNum == 0 {
        return;
    }

    let mut width = image.width;
    let picSize = width * image.height;
    let row = udiv(mbNum, width);
    let col = mbNum - row * width;

    width *= 16;
    let mut ptr = image.data.add((row * 16 * width + col * 16) as usize);

    /* note that luma samples above-right to current macroblock do not make
     * sense when current mb is the right-most mb in a row. Same applies to
     * sample above-left if col is zero. However, usage of pels in prediction
     * is controlled by neighbour availability information in actual prediction
     * process */
    if row != 0 {
        let mut tmp = ptr.sub((width + 1) as usize);
        for _i in 0..21 {
            *above = *tmp;
            above = above.add(1);
            tmp = tmp.add(1);
        }
    }

    if col != 0 {
        ptr = ptr.sub(1);
        for _i in 0..16 {
            *left = *ptr;
            left = left.add(1);
            ptr = ptr.add(width as usize);
        }
    }

    width >>= 1;
    ptr = image
        .data
        .add((picSize * 256 + row * 8 * width + col * 8) as usize);

    if row != 0 {
        let mut tmp = ptr.sub((width + 1) as usize);
        for _i in 0..9 {
            *above = *tmp;
            above = above.add(1);
            tmp = tmp.add(1);
        }
        tmp = tmp.add((picSize * 64 - 9) as usize);
        for _i in 0..9 {
            *above = *tmp;
            above = above.add(1);
            tmp = tmp.add(1);
        }
    }

    if col != 0 {
        ptr = ptr.sub(1);
        for _i in 0..8 {
            *left = *ptr;
            left = left.add(1);
            ptr = ptr.add(width as usize);
        }
        ptr = ptr.add((picSize * 64 - 8 * width) as usize);
        for _i in 0..8 {
            *left = *ptr;
            left = left.add(1);
            ptr = ptr.add(width as usize);
        }
    }
}

/*------------------------------------------------------------------------------

    Function: Intra16x16Prediction

        Functional description:
          Perform intra 16x16 prediction mode for luma pixels and add
          residual into prediction. The resulting luma pixels are
          stored in macroblock array 'data'.

------------------------------------------------------------------------------*/
pub unsafe fn h264bsdIntra16x16Prediction(
    pMb: &mut mbStorage_t,
    data: *mut u8,
    residual: *mut [i32; 16],
    above: *mut u8,
    left: *mut u8,
    constrainedIntraPred: u32,
) -> u32 {
    let mut availableA = h264bsdIsNeighbourAvailable(pMb, pMb.mbA);
    if availableA != 0
        && constrainedIntraPred != 0
        && h264bsdMbPartPredMode((*pMb.mbA).mbType) == PRED_MODE_INTER
    {
        availableA = HANTRO_FALSE;
    }
    let mut availableB = h264bsdIsNeighbourAvailable(pMb, pMb.mbB);
    if availableB != 0
        && constrainedIntraPred != 0
        && h264bsdMbPartPredMode((*pMb.mbB).mbType) == PRED_MODE_INTER
    {
        availableB = HANTRO_FALSE;
    }
    let mut availableD = h264bsdIsNeighbourAvailable(pMb, pMb.mbD);
    if availableD != 0
        && constrainedIntraPred != 0
        && h264bsdMbPartPredMode((*pMb.mbD).mbType) == PRED_MODE_INTER
    {
        availableD = HANTRO_FALSE;
    }

    match h264bsdPredModeIntra16x16(pMb.mbType) {
        0 => {
            /* Intra_16x16_Vertical */
            if availableB == 0 {
                return HANTRO_NOK;
            }
            Intra16x16VerticalPrediction(data, above.add(1));
        }
        1 => {
            /* Intra_16x16_Horizontal */
            if availableA == 0 {
                return HANTRO_NOK;
            }
            Intra16x16HorizontalPrediction(data, left);
        }
        2 => {
            /* Intra_16x16_DC */
            Intra16x16DcPrediction(data, above.add(1), left, availableA, availableB);
        }
        _ => {
            /* case 3: Intra_16x16_Plane */
            if availableA == 0 || availableB == 0 || availableD == 0 {
                return HANTRO_NOK;
            }
            Intra16x16PlanePrediction(data, above.add(1), left);
        }
    }
    /* add residual */
    for i in 0..16u32 {
        h264bsdAddResidual(data, (*residual.add(i as usize)).as_ptr(), i);
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: Intra4x4Prediction

        Functional description:
          Perform intra 4x4 prediction for luma pixels and add residual
          into prediction. The resulting luma pixels are stored in
          macroblock array 'data'. The intra 4x4 prediction mode for each
          block is stored in 'pMb' structure.

------------------------------------------------------------------------------*/
pub unsafe fn h264bsdIntra4x4Prediction(
    pMb: &mut mbStorage_t,
    data: *mut u8,
    mbLayer: &mut macroblockLayer_t,
    above: *mut u8,
    left: *mut u8,
    constrainedIntraPred: u32,
) -> u32 {
    let mut a = [0u8; 1 + 4 + 4];
    let mut l = [0u8; 1 + 4];
    let mut data4x4 = [0u32; 4];

    for block in 0..16u32 {
        let mut neighbour = *h264bsdNeighbour4x4BlockA(block);
        let mut nMb = h264bsdGetNeighbourMb(pMb, neighbour.mb);
        let mut availableA = h264bsdIsNeighbourAvailable(pMb, nMb);
        if availableA != 0
            && constrainedIntraPred != 0
            && h264bsdMbPartPredMode((*nMb).mbType) == PRED_MODE_INTER
        {
            availableA = HANTRO_FALSE;
        }

        let mut neighbourB = *h264bsdNeighbour4x4BlockB(block);
        let nMb2 = h264bsdGetNeighbourMb(pMb, neighbourB.mb);
        let mut availableB = h264bsdIsNeighbourAvailable(pMb, nMb2);
        if availableB != 0
            && constrainedIntraPred != 0
            && h264bsdMbPartPredMode((*nMb2).mbType) == PRED_MODE_INTER
        {
            availableB = HANTRO_FALSE;
        }

        let mode = DetermineIntra4x4PredMode(
            mbLayer,
            if availableA != 0 && availableB != 0 { 1 } else { 0 },
            &mut neighbour,
            &mut neighbourB,
            block,
            nMb,
            nMb2,
        );
        pMb.intra4x4PredMode[block as usize] = mode as u8;

        neighbour = *h264bsdNeighbour4x4BlockC(block);
        nMb = h264bsdGetNeighbourMb(pMb, neighbour.mb);
        let mut availableC = h264bsdIsNeighbourAvailable(pMb, nMb);
        if availableC != 0
            && constrainedIntraPred != 0
            && h264bsdMbPartPredMode((*nMb).mbType) == PRED_MODE_INTER
        {
            availableC = HANTRO_FALSE;
        }

        neighbour = *h264bsdNeighbour4x4BlockD(block);
        nMb = h264bsdGetNeighbourMb(pMb, neighbour.mb);
        let mut availableD = h264bsdIsNeighbourAvailable(pMb, nMb);
        if availableD != 0
            && constrainedIntraPred != 0
            && h264bsdMbPartPredMode((*nMb).mbType) == PRED_MODE_INTER
        {
            availableD = HANTRO_FALSE;
        }

        Get4x4NeighbourPels(a.as_mut_ptr(), l.as_mut_ptr(), data, above, left, block);

        match mode {
            0 => {
                /* Intra_4x4_Vertical */
                if availableB == 0 {
                    return HANTRO_NOK;
                }
                Intra4x4VerticalPrediction(data4x4.as_mut_ptr() as *mut u8, a.as_mut_ptr().add(1));
            }
            1 => {
                /* Intra_4x4_Horizontal */
                if availableA == 0 {
                    return HANTRO_NOK;
                }
                Intra4x4HorizontalPrediction(data4x4.as_mut_ptr() as *mut u8, l.as_mut_ptr().add(1));
            }
            2 => {
                /* Intra_4x4_DC */
                Intra4x4DcPrediction(
                    data4x4.as_mut_ptr() as *mut u8,
                    a.as_mut_ptr().add(1),
                    l.as_mut_ptr().add(1),
                    availableA,
                    availableB,
                );
            }
            3 => {
                /* Intra_4x4_Diagonal_Down_Left */
                if availableB == 0 {
                    return HANTRO_NOK;
                }
                if availableC == 0 {
                    a[5] = a[4];
                    a[6] = a[4];
                    a[7] = a[4];
                    a[8] = a[4];
                }
                Intra4x4DiagonalDownLeftPrediction(
                    data4x4.as_mut_ptr() as *mut u8,
                    a.as_mut_ptr().add(1),
                );
            }
            4 => {
                /* Intra_4x4_Diagonal_Down_Right */
                if availableA == 0 || availableB == 0 || availableD == 0 {
                    return HANTRO_NOK;
                }
                Intra4x4DiagonalDownRightPrediction(
                    data4x4.as_mut_ptr() as *mut u8,
                    a.as_mut_ptr().add(1),
                    l.as_mut_ptr().add(1),
                );
            }
            5 => {
                /* Intra_4x4_Vertical_Right */
                if availableA == 0 || availableB == 0 || availableD == 0 {
                    return HANTRO_NOK;
                }
                Intra4x4VerticalRightPrediction(
                    data4x4.as_mut_ptr() as *mut u8,
                    a.as_mut_ptr().add(1),
                    l.as_mut_ptr().add(1),
                );
            }
            6 => {
                /* Intra_4x4_Horizontal_Down */
                if availableA == 0 || availableB == 0 || availableD == 0 {
                    return HANTRO_NOK;
                }
                Intra4x4HorizontalDownPrediction(
                    data4x4.as_mut_ptr() as *mut u8,
                    a.as_mut_ptr().add(1),
                    l.as_mut_ptr().add(1),
                );
            }
            7 => {
                /* Intra_4x4_Vertical_Left */
                if availableB == 0 {
                    return HANTRO_NOK;
                }
                if availableC == 0 {
                    a[5] = a[4];
                    a[6] = a[4];
                    a[7] = a[4];
                    a[8] = a[4];
                }
                Intra4x4VerticalLeftPrediction(
                    data4x4.as_mut_ptr() as *mut u8,
                    a.as_mut_ptr().add(1),
                );
            }
            _ => {
                /* case 8 Intra_4x4_Horizontal_Up */
                if availableA == 0 {
                    return HANTRO_NOK;
                }
                Intra4x4HorizontalUpPrediction(
                    data4x4.as_mut_ptr() as *mut u8,
                    l.as_mut_ptr().add(1),
                );
            }
        }

        Write4x4To16x16(data, data4x4.as_mut_ptr() as *mut u8, block);
        h264bsdAddResidual(data, mbLayer.residual.level[block as usize].as_ptr(), block);
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: IntraChromaPrediction

        Functional description:
          Perform intra prediction for chroma pixels and add residual
          into prediction. The resulting chroma pixels are stored in 'data'.

------------------------------------------------------------------------------*/
pub unsafe fn h264bsdIntraChromaPrediction(
    pMb: &mut mbStorage_t,
    data: *mut u8,
    residual: *mut [i32; 16],
    above: *mut u8,
    left: *mut u8,
    predMode: u32,
    constrainedIntraPred: u32,
) -> u32 {
    let mut data = data;
    let mut residual = residual;
    let mut above = above;
    let mut left = left;

    let mut availableA = h264bsdIsNeighbourAvailable(pMb, pMb.mbA);
    if availableA != 0
        && constrainedIntraPred != 0
        && h264bsdMbPartPredMode((*pMb.mbA).mbType) == PRED_MODE_INTER
    {
        availableA = HANTRO_FALSE;
    }
    let mut availableB = h264bsdIsNeighbourAvailable(pMb, pMb.mbB);
    if availableB != 0
        && constrainedIntraPred != 0
        && h264bsdMbPartPredMode((*pMb.mbB).mbType) == PRED_MODE_INTER
    {
        availableB = HANTRO_FALSE;
    }
    let mut availableD = h264bsdIsNeighbourAvailable(pMb, pMb.mbD);
    if availableD != 0
        && constrainedIntraPred != 0
        && h264bsdMbPartPredMode((*pMb.mbD).mbType) == PRED_MODE_INTER
    {
        availableD = HANTRO_FALSE;
    }

    let mut block = 16u32;
    for _comp in 0..2u32 {
        match predMode {
            0 => {
                /* Intra_Chroma_DC */
                IntraChromaDcPrediction(data, above.add(1), left, availableA, availableB);
            }
            1 => {
                /* Intra_Chroma_Horizontal */
                if availableA == 0 {
                    return HANTRO_NOK;
                }
                IntraChromaHorizontalPrediction(data, left);
            }
            2 => {
                /* Intra_Chroma_Vertical */
                if availableB == 0 {
                    return HANTRO_NOK;
                }
                IntraChromaVerticalPrediction(data, above.add(1));
            }
            _ => {
                /* case 3: Intra_Chroma_Plane */
                if availableA == 0 || availableB == 0 || availableD == 0 {
                    return HANTRO_NOK;
                }
                IntraChromaPlanePrediction(data, above.add(1), left);
            }
        }
        for i in 0..4u32 {
            h264bsdAddResidual(data, (*residual.add(i as usize)).as_ptr(), block);
            block += 1;
        }

        /* advance pointers */
        data = data.add(64);
        above = above.add(9);
        left = left.add(8);
        residual = residual.add(4);
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: h264bsdAddResidual

        Functional description:
          Add residual of a block into prediction in macroblock array 'data'.
          The result (residual + prediction) is stored in 'data'.

------------------------------------------------------------------------------*/
pub unsafe fn h264bsdAddResidual(data: *mut u8, residual: *const i32, blockNum: u32) {
    let mut residual = residual;
    let clp = h264bsdClip.as_ptr().add(512);

    if IS_RESIDUAL_EMPTY(core::slice::from_raw_parts(residual, 16)) {
        return;
    }

    let width: u32;
    let x: u32;
    let y: u32;
    if blockNum < 16 {
        width = 16;
        x = h264bsdBlockX[blockNum as usize];
        y = h264bsdBlockY[blockNum as usize];
    } else {
        width = 8;
        x = h264bsdBlockX[(blockNum & 0x3) as usize];
        y = h264bsdBlockY[(blockNum & 0x3) as usize];
    }

    let mut tmp = data.add((y * width + x) as usize);
    for _i in 0..4 {
        let mut tmp1 = *residual;
        residual = residual.add(1);
        let mut tmp2 = *tmp.add(0) as i32;
        let mut tmp3 = *residual;
        residual = residual.add(1);
        let mut tmp4 = *tmp.add(1) as i32;

        *tmp.add(0) = *clp.offset((tmp1 + tmp2) as isize);

        tmp1 = *residual;
        residual = residual.add(1);
        tmp2 = *tmp.add(2) as i32;

        *tmp.add(1) = *clp.offset((tmp3 + tmp4) as isize);

        tmp3 = *residual;
        residual = residual.add(1);
        tmp4 = *tmp.add(3) as i32;

        tmp1 = *clp.offset((tmp1 + tmp2) as isize) as i32;
        tmp3 = *clp.offset((tmp3 + tmp4) as isize) as i32;
        *tmp.add(2) = tmp1 as u8;
        *tmp.add(3) = tmp3 as u8;

        tmp = tmp.add(width as usize);
    }
}

/*------------------------------------------------------------------------------

    Function: Intra16x16VerticalPrediction

        Functional description:
          Perform intra 16x16 vertical prediction mode.

------------------------------------------------------------------------------*/
unsafe fn Intra16x16VerticalPrediction(data: *mut u8, above: *mut u8) {
    let mut data = data;
    for _i in 0..16 {
        for j in 0..16usize {
            *data = *above.add(j);
            data = data.add(1);
        }
    }
}

/*------------------------------------------------------------------------------

    Function: Intra16x16HorizontalPrediction

        Functional description:
          Perform intra 16x16 horizontal prediction mode.

------------------------------------------------------------------------------*/
unsafe fn Intra16x16HorizontalPrediction(data: *mut u8, left: *mut u8) {
    let mut data = data;
    for i in 0..16usize {
        for _j in 0..16 {
            *data = *left.add(i);
            data = data.add(1);
        }
    }
}

/*------------------------------------------------------------------------------

    Function: Intra16x16DcPrediction

        Functional description:
          Perform intra 16x16 DC prediction mode.

------------------------------------------------------------------------------*/
unsafe fn Intra16x16DcPrediction(
    data: *mut u8,
    above: *mut u8,
    left: *mut u8,
    availableA: u32,
    availableB: u32,
) {
    let mut tmp: u32;

    if availableA != 0 && availableB != 0 {
        tmp = 0;
        for i in 0..16usize {
            tmp += *above.add(i) as u32 + *left.add(i) as u32;
        }
        tmp = (tmp + 16) >> 5;
    } else if availableA != 0 {
        tmp = 0;
        for i in 0..16usize {
            tmp += *left.add(i) as u32;
        }
        tmp = (tmp + 8) >> 4;
    } else if availableB != 0 {
        tmp = 0;
        for i in 0..16usize {
            tmp += *above.add(i) as u32;
        }
        tmp = (tmp + 8) >> 4;
    }
    /* neither A nor B available */
    else {
        tmp = 128;
    }
    for i in 0..256usize {
        *data.add(i) = tmp as u8;
    }
}

/*------------------------------------------------------------------------------

    Function: Intra16x16PlanePrediction

        Functional description:
          Perform intra 16x16 plane prediction mode.

------------------------------------------------------------------------------*/
unsafe fn Intra16x16PlanePrediction(data: *mut u8, above: *mut u8, left: *mut u8) {
    let a: i32 = 16 * (*above.add(15) as i32 + *left.add(15) as i32);

    let mut b: i32 = 0;
    for i in 0..8i32 {
        b += (i + 1)
            * (*above.offset((8 + i) as isize) as i32 - *above.offset((6 - i) as isize) as i32);
    }
    b = (5 * b + 32) >> 6;

    let mut c: i32 = 0;
    let mut i: i32 = 0;
    while i < 7 {
        c += (i + 1)
            * (*left.offset((8 + i) as isize) as i32 - *left.offset((6 - i) as isize) as i32);
        i += 1;
    }
    /* p[-1,-1] has to be accessed through above pointer */
    c += (i + 1) * (*left.offset((8 + i) as isize) as i32 - *above.offset(-1) as i32);
    c = (5 * c + 32) >> 6;

    for i in 0..16i32 {
        for j in 0..16i32 {
            let tmp = (a + b * (j - 7) + c * (i - 7) + 16) >> 5;
            *data.add((i * 16 + j) as usize) = CLIP1!(tmp) as u8;
        }
    }
}

/*------------------------------------------------------------------------------

    Function: IntraChromaDcPrediction

        Functional description:
          Perform intra chroma DC prediction mode.

------------------------------------------------------------------------------*/
unsafe fn IntraChromaDcPrediction(
    data: *mut u8,
    above: *mut u8,
    left: *mut u8,
    availableA: u32,
    availableB: u32,
) {
    let mut data = data;
    let mut tmp1: u32;
    let mut tmp2: u32;

    /* y = 0..3 */
    if availableA != 0 && availableB != 0 {
        tmp1 = *above.add(0) as u32
            + *above.add(1) as u32
            + *above.add(2) as u32
            + *above.add(3) as u32
            + *left.add(0) as u32
            + *left.add(1) as u32
            + *left.add(2) as u32
            + *left.add(3) as u32;
        tmp1 = (tmp1 + 4) >> 3;
        tmp2 = (*above.add(4) as u32
            + *above.add(5) as u32
            + *above.add(6) as u32
            + *above.add(7) as u32
            + 2)
            >> 2;
    } else if availableB != 0 {
        tmp1 = (*above.add(0) as u32
            + *above.add(1) as u32
            + *above.add(2) as u32
            + *above.add(3) as u32
            + 2)
            >> 2;
        tmp2 = (*above.add(4) as u32
            + *above.add(5) as u32
            + *above.add(6) as u32
            + *above.add(7) as u32
            + 2)
            >> 2;
    } else if availableA != 0 {
        tmp1 = (*left.add(0) as u32
            + *left.add(1) as u32
            + *left.add(2) as u32
            + *left.add(3) as u32
            + 2)
            >> 2;
        tmp2 = tmp1;
    }
    /* neither A nor B available */
    else {
        tmp1 = 128;
        tmp2 = 128;
    }

    for _i in 0..4 {
        *data = tmp1 as u8;
        data = data.add(1);
        *data = tmp1 as u8;
        data = data.add(1);
        *data = tmp1 as u8;
        data = data.add(1);
        *data = tmp1 as u8;
        data = data.add(1);
        *data = tmp2 as u8;
        data = data.add(1);
        *data = tmp2 as u8;
        data = data.add(1);
        *data = tmp2 as u8;
        data = data.add(1);
        *data = tmp2 as u8;
        data = data.add(1);
    }

    /* y = 4...7 */
    if availableA != 0 {
        tmp1 = (*left.add(4) as u32
            + *left.add(5) as u32
            + *left.add(6) as u32
            + *left.add(7) as u32
            + 2)
            >> 2;
        if availableB != 0 {
            tmp2 = *above.add(4) as u32
                + *above.add(5) as u32
                + *above.add(6) as u32
                + *above.add(7) as u32
                + *left.add(4) as u32
                + *left.add(5) as u32
                + *left.add(6) as u32
                + *left.add(7) as u32;
            tmp2 = (tmp2 + 4) >> 3;
        } else {
            tmp2 = tmp1;
        }
    } else if availableB != 0 {
        tmp1 = (*above.add(0) as u32
            + *above.add(1) as u32
            + *above.add(2) as u32
            + *above.add(3) as u32
            + 2)
            >> 2;
        tmp2 = (*above.add(4) as u32
            + *above.add(5) as u32
            + *above.add(6) as u32
            + *above.add(7) as u32
            + 2)
            >> 2;
    } else {
        tmp1 = 128;
        tmp2 = 128;
    }

    for _i in 0..4 {
        *data = tmp1 as u8;
        data = data.add(1);
        *data = tmp1 as u8;
        data = data.add(1);
        *data = tmp1 as u8;
        data = data.add(1);
        *data = tmp1 as u8;
        data = data.add(1);
        *data = tmp2 as u8;
        data = data.add(1);
        *data = tmp2 as u8;
        data = data.add(1);
        *data = tmp2 as u8;
        data = data.add(1);
        *data = tmp2 as u8;
        data = data.add(1);
    }
}

/*------------------------------------------------------------------------------

    Function: IntraChromaHorizontalPrediction

        Functional description:
          Perform intra chroma horizontal prediction mode.

------------------------------------------------------------------------------*/
unsafe fn IntraChromaHorizontalPrediction(data: *mut u8, left: *mut u8) {
    let mut data = data;
    let mut left = left;

    for _i in 0..8 {
        *data = *left;
        data = data.add(1);
        *data = *left;
        data = data.add(1);
        *data = *left;
        data = data.add(1);
        *data = *left;
        data = data.add(1);
        *data = *left;
        data = data.add(1);
        *data = *left;
        data = data.add(1);
        *data = *left;
        data = data.add(1);
        *data = *left;
        data = data.add(1);
        left = left.add(1);
    }
}

/*------------------------------------------------------------------------------

    Function: IntraChromaVerticalPrediction

        Functional description:
          Perform intra chroma vertical prediction mode.

------------------------------------------------------------------------------*/
unsafe fn IntraChromaVerticalPrediction(data: *mut u8, above: *mut u8) {
    let mut data = data;
    let mut above = above;

    for _i in 0..8 {
        *data.add(0) = *above;
        *data.add(8) = *above;
        *data.add(16) = *above;
        *data.add(24) = *above;
        *data.add(32) = *above;
        *data.add(40) = *above;
        *data.add(48) = *above;
        *data.add(56) = *above;
        above = above.add(1);
        data = data.add(1);
    }
}

/*------------------------------------------------------------------------------

    Function: IntraChromaPlanePrediction

        Functional description:
          Perform intra chroma plane prediction mode.

------------------------------------------------------------------------------*/
unsafe fn IntraChromaPlanePrediction(data: *mut u8, above: *mut u8, left: *mut u8) {
    let mut data = data;
    let clp = h264bsdClip.as_ptr().add(512);

    let mut a: i32 = 16 * (*above.add(7) as i32 + *left.add(7) as i32);

    let mut b: i32 = (*above.add(4) as i32 - *above.add(2) as i32)
        + 2 * (*above.add(5) as i32 - *above.add(1) as i32)
        + 3 * (*above.add(6) as i32 - *above.add(0) as i32)
        + 4 * (*above.add(7) as i32 - *above.offset(-1) as i32);
    b = (17 * b + 16) >> 5;

    /* p[-1,-1] has to be accessed through above pointer */
    let mut c: i32 = (*left.add(4) as i32 - *left.add(2) as i32)
        + 2 * (*left.add(5) as i32 - *left.add(1) as i32)
        + 3 * (*left.add(6) as i32 - *left.add(0) as i32)
        + 4 * (*left.add(7) as i32 - *above.offset(-1) as i32);
    c = (17 * c + 16) >> 5;

    /*a += 16;*/
    a = a - 3 * c + 16;
    for _i in 0..8 {
        let mut tmp = a - 3 * b;
        *data = *clp.offset((tmp >> 5) as isize);
        data = data.add(1);
        tmp += b;
        *data = *clp.offset((tmp >> 5) as isize);
        data = data.add(1);
        tmp += b;
        *data = *clp.offset((tmp >> 5) as isize);
        data = data.add(1);
        tmp += b;
        *data = *clp.offset((tmp >> 5) as isize);
        data = data.add(1);
        tmp += b;
        *data = *clp.offset((tmp >> 5) as isize);
        data = data.add(1);
        tmp += b;
        *data = *clp.offset((tmp >> 5) as isize);
        data = data.add(1);
        tmp += b;
        *data = *clp.offset((tmp >> 5) as isize);
        data = data.add(1);
        tmp += b;
        *data = *clp.offset((tmp >> 5) as isize);
        data = data.add(1);
        a += c;
    }
}

/*------------------------------------------------------------------------------

    Function: Get4x4NeighbourPels

        Functional description:
          Get neighbouring pixels of a 4x4 block into 'a' and 'l'.

------------------------------------------------------------------------------*/
unsafe fn Get4x4NeighbourPels(
    a: *mut u8,
    l: *mut u8,
    data: *mut u8,
    above: *mut u8,
    left: *mut u8,
    blockNum: u32,
) {
    let x = h264bsdBlockX[blockNum as usize] as usize;
    let y = h264bsdBlockY[blockNum as usize] as usize;

    let mut t1: u8;
    let mut t2: u8;

    /* A and D */
    if x == 0 {
        t1 = *left.add(y);
        t2 = *left.add(y + 1);
        *l.add(1) = t1;
        *l.add(2) = t2;
        t1 = *left.add(y + 2);
        t2 = *left.add(y + 3);
        *l.add(3) = t1;
        *l.add(4) = t2;
    } else {
        t1 = *data.add(y * 16 + x - 1);
        t2 = *data.add(y * 16 + x - 1 + 16);
        *l.add(1) = t1;
        *l.add(2) = t2;
        t1 = *data.add(y * 16 + x - 1 + 32);
        t2 = *data.add(y * 16 + x - 1 + 48);
        *l.add(3) = t1;
        *l.add(4) = t2;
    }

    /* B, C and D */
    if y == 0 {
        t1 = *above.add(x);
        t2 = *above.add(x);
        *l.add(0) = t1;
        *a.add(0) = t2;
        t1 = *above.add(x + 1);
        t2 = *above.add(x + 2);
        *a.add(1) = t1;
        *a.add(2) = t2;
        t1 = *above.add(x + 3);
        t2 = *above.add(x + 4);
        *a.add(3) = t1;
        *a.add(4) = t2;
        t1 = *above.add(x + 5);
        t2 = *above.add(x + 6);
        *a.add(5) = t1;
        *a.add(6) = t2;
        t1 = *above.add(x + 7);
        t2 = *above.add(x + 8);
        *a.add(7) = t1;
        *a.add(8) = t2;
    } else {
        t1 = *data.add((y - 1) * 16 + x);
        t2 = *data.add((y - 1) * 16 + x + 1);
        *a.add(1) = t1;
        *a.add(2) = t2;
        t1 = *data.add((y - 1) * 16 + x + 2);
        t2 = *data.add((y - 1) * 16 + x + 3);
        *a.add(3) = t1;
        *a.add(4) = t2;
        t1 = *data.add((y - 1) * 16 + x + 4);
        t2 = *data.add((y - 1) * 16 + x + 5);
        *a.add(5) = t1;
        *a.add(6) = t2;
        t1 = *data.add((y - 1) * 16 + x + 6);
        t2 = *data.add((y - 1) * 16 + x + 7);
        *a.add(7) = t1;
        *a.add(8) = t2;

        if x == 0 {
            t1 = *left.add(y - 1);
            *l.add(0) = t1;
            *a.add(0) = t1;
        } else {
            t1 = *data.add((y - 1) * 16 + x - 1);
            *l.add(0) = t1;
            *a.add(0) = t1;
        }
    }
}

/*------------------------------------------------------------------------------

    Function: Intra4x4VerticalPrediction

        Functional description:
          Perform intra 4x4 vertical prediction mode.

------------------------------------------------------------------------------*/
unsafe fn Intra4x4VerticalPrediction(data: *mut u8, above: *mut u8) {
    let mut t1 = *above.add(0);
    let mut t2 = *above.add(1);
    *data.add(0) = t1;
    *data.add(4) = t1;
    *data.add(8) = t1;
    *data.add(12) = t1;
    *data.add(1) = t2;
    *data.add(5) = t2;
    *data.add(9) = t2;
    *data.add(13) = t2;
    t1 = *above.add(2);
    t2 = *above.add(3);
    *data.add(2) = t1;
    *data.add(6) = t1;
    *data.add(10) = t1;
    *data.add(14) = t1;
    *data.add(3) = t2;
    *data.add(7) = t2;
    *data.add(11) = t2;
    *data.add(15) = t2;
}

/*------------------------------------------------------------------------------

    Function: Intra4x4HorizontalPrediction

        Functional description:
          Perform intra 4x4 horizontal prediction mode.

------------------------------------------------------------------------------*/
unsafe fn Intra4x4HorizontalPrediction(data: *mut u8, left: *mut u8) {
    let mut t1 = *left.add(0);
    let mut t2 = *left.add(1);
    *data.add(0) = t1;
    *data.add(1) = t1;
    *data.add(2) = t1;
    *data.add(3) = t1;
    *data.add(4) = t2;
    *data.add(5) = t2;
    *data.add(6) = t2;
    *data.add(7) = t2;
    t1 = *left.add(2);
    t2 = *left.add(3);
    *data.add(8) = t1;
    *data.add(9) = t1;
    *data.add(10) = t1;
    *data.add(11) = t1;
    *data.add(12) = t2;
    *data.add(13) = t2;
    *data.add(14) = t2;
    *data.add(15) = t2;
}

/*------------------------------------------------------------------------------

    Function: Intra4x4DcPrediction

        Functional description:
          Perform intra 4x4 DC prediction mode.

------------------------------------------------------------------------------*/
unsafe fn Intra4x4DcPrediction(
    data: *mut u8,
    above: *mut u8,
    left: *mut u8,
    availableA: u32,
    availableB: u32,
) {
    let tmp: u32;

    if availableA != 0 && availableB != 0 {
        let mut t = *above.add(0) as u32
            + *above.add(1) as u32
            + *above.add(2) as u32
            + *above.add(3) as u32;
        t += *left.add(0) as u32
            + *left.add(1) as u32
            + *left.add(2) as u32
            + *left.add(3) as u32;
        tmp = (t + 4) >> 3;
    } else if availableA != 0 {
        tmp = (*left.add(0) as u32
            + *left.add(1) as u32
            + *left.add(2) as u32
            + *left.add(3) as u32
            + 2)
            >> 2;
    } else if availableB != 0 {
        tmp = (*above.add(0) as u32
            + *above.add(1) as u32
            + *above.add(2) as u32
            + *above.add(3) as u32
            + 2)
            >> 2;
    } else {
        tmp = 128;
    }

    let v = tmp as u8;
    *data.add(0) = v;
    *data.add(1) = v;
    *data.add(2) = v;
    *data.add(3) = v;
    *data.add(4) = v;
    *data.add(5) = v;
    *data.add(6) = v;
    *data.add(7) = v;
    *data.add(8) = v;
    *data.add(9) = v;
    *data.add(10) = v;
    *data.add(11) = v;
    *data.add(12) = v;
    *data.add(13) = v;
    *data.add(14) = v;
    *data.add(15) = v;
}

/*------------------------------------------------------------------------------

    Function: Intra4x4DiagonalDownLeftPrediction

        Functional description:
          Perform intra 4x4 diagonal down-left prediction mode.

------------------------------------------------------------------------------*/
unsafe fn Intra4x4DiagonalDownLeftPrediction(data: *mut u8, above: *mut u8) {
    let a = |i: isize| unsafe { *above.offset(i) as u32 };

    *data.add(0) = ((a(0) + 2 * a(1) + a(2) + 2) >> 2) as u8;
    *data.add(1) = ((a(1) + 2 * a(2) + a(3) + 2) >> 2) as u8;
    *data.add(4) = ((a(1) + 2 * a(2) + a(3) + 2) >> 2) as u8;
    *data.add(2) = ((a(2) + 2 * a(3) + a(4) + 2) >> 2) as u8;
    *data.add(5) = ((a(2) + 2 * a(3) + a(4) + 2) >> 2) as u8;
    *data.add(8) = ((a(2) + 2 * a(3) + a(4) + 2) >> 2) as u8;
    *data.add(3) = ((a(3) + 2 * a(4) + a(5) + 2) >> 2) as u8;
    *data.add(6) = ((a(3) + 2 * a(4) + a(5) + 2) >> 2) as u8;
    *data.add(9) = ((a(3) + 2 * a(4) + a(5) + 2) >> 2) as u8;
    *data.add(12) = ((a(3) + 2 * a(4) + a(5) + 2) >> 2) as u8;
    *data.add(7) = ((a(4) + 2 * a(5) + a(6) + 2) >> 2) as u8;
    *data.add(10) = ((a(4) + 2 * a(5) + a(6) + 2) >> 2) as u8;
    *data.add(13) = ((a(4) + 2 * a(5) + a(6) + 2) >> 2) as u8;
    *data.add(11) = ((a(5) + 2 * a(6) + a(7) + 2) >> 2) as u8;
    *data.add(14) = ((a(5) + 2 * a(6) + a(7) + 2) >> 2) as u8;
    *data.add(15) = ((a(6) + 3 * a(7) + 2) >> 2) as u8;
}

/*------------------------------------------------------------------------------

    Function: Intra4x4DiagonalDownRightPrediction

        Functional description:
          Perform intra 4x4 diagonal down-right prediction mode.

------------------------------------------------------------------------------*/
unsafe fn Intra4x4DiagonalDownRightPrediction(data: *mut u8, above: *mut u8, left: *mut u8) {
    let a = |i: isize| unsafe { *above.offset(i) as u32 };
    let l = |i: isize| unsafe { *left.offset(i) as u32 };

    *data.add(0) = ((a(0) + 2 * a(-1) + l(0) + 2) >> 2) as u8;
    *data.add(5) = ((a(0) + 2 * a(-1) + l(0) + 2) >> 2) as u8;
    *data.add(10) = ((a(0) + 2 * a(-1) + l(0) + 2) >> 2) as u8;
    *data.add(15) = ((a(0) + 2 * a(-1) + l(0) + 2) >> 2) as u8;
    *data.add(1) = ((a(-1) + 2 * a(0) + a(1) + 2) >> 2) as u8;
    *data.add(6) = ((a(-1) + 2 * a(0) + a(1) + 2) >> 2) as u8;
    *data.add(11) = ((a(-1) + 2 * a(0) + a(1) + 2) >> 2) as u8;
    *data.add(2) = ((a(0) + 2 * a(1) + a(2) + 2) >> 2) as u8;
    *data.add(7) = ((a(0) + 2 * a(1) + a(2) + 2) >> 2) as u8;
    *data.add(3) = ((a(1) + 2 * a(2) + a(3) + 2) >> 2) as u8;
    *data.add(4) = ((l(-1) + 2 * l(0) + l(1) + 2) >> 2) as u8;
    *data.add(9) = ((l(-1) + 2 * l(0) + l(1) + 2) >> 2) as u8;
    *data.add(14) = ((l(-1) + 2 * l(0) + l(1) + 2) >> 2) as u8;
    *data.add(8) = ((l(0) + 2 * l(1) + l(2) + 2) >> 2) as u8;
    *data.add(13) = ((l(0) + 2 * l(1) + l(2) + 2) >> 2) as u8;
    *data.add(12) = ((l(1) + 2 * l(2) + l(3) + 2) >> 2) as u8;
}

/*------------------------------------------------------------------------------

    Function: Intra4x4VerticalRightPrediction

        Functional description:
          Perform intra 4x4 vertical right prediction mode.

------------------------------------------------------------------------------*/
unsafe fn Intra4x4VerticalRightPrediction(data: *mut u8, above: *mut u8, left: *mut u8) {
    let a = |i: isize| unsafe { *above.offset(i) as u32 };
    let l = |i: isize| unsafe { *left.offset(i) as u32 };

    *data.add(0) = ((a(-1) + a(0) + 1) >> 1) as u8;
    *data.add(9) = ((a(-1) + a(0) + 1) >> 1) as u8;
    *data.add(5) = ((a(-1) + 2 * a(0) + a(1) + 2) >> 2) as u8;
    *data.add(14) = ((a(-1) + 2 * a(0) + a(1) + 2) >> 2) as u8;
    *data.add(4) = ((a(0) + 2 * a(-1) + l(0) + 2) >> 2) as u8;
    *data.add(13) = ((a(0) + 2 * a(-1) + l(0) + 2) >> 2) as u8;
    *data.add(1) = ((a(0) + a(1) + 1) >> 1) as u8;
    *data.add(10) = ((a(0) + a(1) + 1) >> 1) as u8;
    *data.add(6) = ((a(0) + 2 * a(1) + a(2) + 2) >> 2) as u8;
    *data.add(15) = ((a(0) + 2 * a(1) + a(2) + 2) >> 2) as u8;
    *data.add(2) = ((a(1) + a(2) + 1) >> 1) as u8;
    *data.add(11) = ((a(1) + a(2) + 1) >> 1) as u8;
    *data.add(7) = ((a(1) + 2 * a(2) + a(3) + 2) >> 2) as u8;
    *data.add(3) = ((a(2) + a(3) + 1) >> 1) as u8;
    *data.add(8) = ((l(1) + 2 * l(0) + l(-1) + 2) >> 2) as u8;
    *data.add(12) = ((l(2) + 2 * l(1) + l(0) + 2) >> 2) as u8;
}

/*------------------------------------------------------------------------------

    Function: Intra4x4HorizontalDownPrediction

        Functional description:
          Perform intra 4x4 horizontal down prediction mode.

------------------------------------------------------------------------------*/
unsafe fn Intra4x4HorizontalDownPrediction(data: *mut u8, above: *mut u8, left: *mut u8) {
    let a = |i: isize| unsafe { *above.offset(i) as u32 };
    let l = |i: isize| unsafe { *left.offset(i) as u32 };

    *data.add(0) = ((l(-1) + l(0) + 1) >> 1) as u8;
    *data.add(6) = ((l(-1) + l(0) + 1) >> 1) as u8;
    *data.add(5) = ((l(-1) + 2 * l(0) + l(1) + 2) >> 2) as u8;
    *data.add(11) = ((l(-1) + 2 * l(0) + l(1) + 2) >> 2) as u8;
    *data.add(4) = ((l(0) + l(1) + 1) >> 1) as u8;
    *data.add(10) = ((l(0) + l(1) + 1) >> 1) as u8;
    *data.add(9) = ((l(0) + 2 * l(1) + l(2) + 2) >> 2) as u8;
    *data.add(15) = ((l(0) + 2 * l(1) + l(2) + 2) >> 2) as u8;
    *data.add(8) = ((l(1) + l(2) + 1) >> 1) as u8;
    *data.add(14) = ((l(1) + l(2) + 1) >> 1) as u8;
    *data.add(13) = ((l(1) + 2 * l(2) + l(3) + 2) >> 2) as u8;
    *data.add(12) = ((l(2) + l(3) + 1) >> 1) as u8;
    *data.add(1) = ((a(0) + 2 * a(-1) + l(0) + 2) >> 2) as u8;
    *data.add(7) = ((a(0) + 2 * a(-1) + l(0) + 2) >> 2) as u8;
    *data.add(2) = ((a(1) + 2 * a(0) + a(-1) + 2) >> 2) as u8;
    *data.add(3) = ((a(2) + 2 * a(1) + a(0) + 2) >> 2) as u8;
}

/*------------------------------------------------------------------------------

    Function: Intra4x4VerticalLeftPrediction

        Functional description:
          Perform intra 4x4 vertical left prediction mode.

------------------------------------------------------------------------------*/
unsafe fn Intra4x4VerticalLeftPrediction(data: *mut u8, above: *mut u8) {
    let a = |i: isize| unsafe { *above.offset(i) as u32 };

    *data.add(0) = ((a(0) + a(1) + 1) >> 1) as u8;
    *data.add(1) = ((a(1) + a(2) + 1) >> 1) as u8;
    *data.add(2) = ((a(2) + a(3) + 1) >> 1) as u8;
    *data.add(3) = ((a(3) + a(4) + 1) >> 1) as u8;
    *data.add(4) = ((a(0) + 2 * a(1) + a(2) + 2) >> 2) as u8;
    *data.add(5) = ((a(1) + 2 * a(2) + a(3) + 2) >> 2) as u8;
    *data.add(6) = ((a(2) + 2 * a(3) + a(4) + 2) >> 2) as u8;
    *data.add(7) = ((a(3) + 2 * a(4) + a(5) + 2) >> 2) as u8;
    *data.add(8) = ((a(1) + a(2) + 1) >> 1) as u8;
    *data.add(9) = ((a(2) + a(3) + 1) >> 1) as u8;
    *data.add(10) = ((a(3) + a(4) + 1) >> 1) as u8;
    *data.add(11) = ((a(4) + a(5) + 1) >> 1) as u8;
    *data.add(12) = ((a(1) + 2 * a(2) + a(3) + 2) >> 2) as u8;
    *data.add(13) = ((a(2) + 2 * a(3) + a(4) + 2) >> 2) as u8;
    *data.add(14) = ((a(3) + 2 * a(4) + a(5) + 2) >> 2) as u8;
    *data.add(15) = ((a(4) + 2 * a(5) + a(6) + 2) >> 2) as u8;
}

/*------------------------------------------------------------------------------

    Function: Intra4x4HorizontalUpPrediction

        Functional description:
          Perform intra 4x4 horizontal up prediction mode.

------------------------------------------------------------------------------*/
unsafe fn Intra4x4HorizontalUpPrediction(data: *mut u8, left: *mut u8) {
    let l = |i: isize| unsafe { *left.offset(i) as u32 };

    *data.add(0) = ((l(0) + l(1) + 1) >> 1) as u8;
    *data.add(1) = ((l(0) + 2 * l(1) + l(2) + 2) >> 2) as u8;
    *data.add(2) = ((l(1) + l(2) + 1) >> 1) as u8;
    *data.add(3) = ((l(1) + 2 * l(2) + l(3) + 2) >> 2) as u8;
    *data.add(4) = ((l(1) + l(2) + 1) >> 1) as u8;
    *data.add(5) = ((l(1) + 2 * l(2) + l(3) + 2) >> 2) as u8;
    *data.add(6) = ((l(2) + l(3) + 1) >> 1) as u8;
    *data.add(7) = ((l(2) + 3 * l(3) + 2) >> 2) as u8;
    *data.add(8) = ((l(2) + l(3) + 1) >> 1) as u8;
    *data.add(9) = ((l(2) + 3 * l(3) + 2) >> 2) as u8;
    *data.add(10) = l(3) as u8;
    *data.add(11) = l(3) as u8;
    *data.add(12) = l(3) as u8;
    *data.add(13) = l(3) as u8;
    *data.add(14) = l(3) as u8;
    *data.add(15) = l(3) as u8;
}

/*------------------------------------------------------------------------------

    Function: Write4x4To16x16

        Functional description:
          Write a 4x4 block (data4x4) into correct position
          in 16x16 macroblock (data).

------------------------------------------------------------------------------*/
unsafe fn Write4x4To16x16(data: *mut u8, data4x4: *mut u8, blockNum: u32) {
    let x = h264bsdBlockX[blockNum as usize];
    let y = h264bsdBlockY[blockNum as usize];

    let data = data.add((y * 16 + x) as usize);

    /* the C asserts ((u32)data & 0x3) == 0: the macroblock array is
     * 4-byte aligned and x is a multiple of 4, so plain u32 derefs
     * match the C (see port rule 5) */
    let out32 = data as *mut u32;
    let mut in32 = data4x4 as *const u32;

    *out32.add(0) = *in32;
    in32 = in32.add(1);
    *out32.add(4) = *in32;
    in32 = in32.add(1);
    *out32.add(8) = *in32;
    in32 = in32.add(1);
    *out32.add(12) = *in32;
}

/*------------------------------------------------------------------------------

    Function: DetermineIntra4x4PredMode

        Functional description:
          Returns the intra 4x4 prediction mode of a block based on the
          neighbouring macroblocks and information parsed from stream.

------------------------------------------------------------------------------*/
unsafe fn DetermineIntra4x4PredMode(
    pMbLayer: &mut macroblockLayer_t,
    available: u32,
    nA: &mut neighbour_t,
    nB: &mut neighbour_t,
    index: u32,
    nMbA: *mut mbStorage_t,
    nMbB: *mut mbStorage_t,
) -> u32 {
    let mut mode1: u32;
    let mode2: u32;

    /* dc only prediction? */
    if available == 0 {
        mode1 = 2;
    } else {
        let mut pMb = nMbA;
        if h264bsdMbPartPredMode((*pMb).mbType) == PRED_MODE_INTRA4x4 {
            mode1 = (*pMb).intra4x4PredMode[nA.index as usize] as u32;
        } else {
            mode1 = 2;
        }

        pMb = nMbB;
        if h264bsdMbPartPredMode((*pMb).mbType) == PRED_MODE_INTRA4x4 {
            mode2 = (*pMb).intra4x4PredMode[nB.index as usize] as u32;
        } else {
            mode2 = 2;
        }

        mode1 = MIN!(mode1, mode2);
    }

    if pMbLayer.mbPred.prevIntra4x4PredModeFlag[index as usize] == 0 {
        if pMbLayer.mbPred.remIntra4x4PredMode[index as usize] < mode1 {
            mode1 = pMbLayer.mbPred.remIntra4x4PredMode[index as usize];
        } else {
            mode1 = pMbLayer.mbPred.remIntra4x4PredMode[index as usize] + 1;
        }
    }

    mode1
}
