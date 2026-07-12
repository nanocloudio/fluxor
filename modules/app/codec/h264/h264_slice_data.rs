// Mechanical Rust port of h264bsd_slice_data.c (h264bsd baseline
// decoder), following the port rules in PORT_RULES.md: C names kept
// verbatim, control flow translated faithfully, bit-exact output.
//
// Ported: h264bsdDecodeSliceData, SetMbParams (file-local).
// Skipped: h264bsdMarkSliceCorrupted — also defined in this C file,
// but the cross-file signature manifest assigns it to the
// `h264_storage` module; it is ported there, not here.
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

/*------------------------------------------------------------------------------

   5.1  Function name: h264bsdDecodeSliceData

        Functional description:
            Decode one slice. Function decodes stream data, i.e. macroblocks
            and possible skip_run fields. h264bsdDecodeMacroblock function is
            called to handle all other macroblock related processing.
            Macroblock to slice group mapping is considered when next
            macroblock to process is determined (h264bsdNextMbAddress function)

        Inputs:
            pStrmData       pointer to stream data structure
            pStorage        pointer to storage structure
            currImage       pointer to current processed picture, needed for
                            intra prediction of the macroblocks
            pSliceHeader    pointer to slice header of the current slice

        Outputs:
            currImage       processed macroblocks are written to current image
            pStorage        mbStorage structure of each processed macroblock
                            is updated here

        Returns:
            HANTRO_OK       success
            HANTRO_NOK      invalid stream data

------------------------------------------------------------------------------*/

pub unsafe fn h264bsdDecodeSliceData(
    pStrmData: &mut strmData_t,
    pStorage: &mut storage_t,
    currImage: &mut image_t,
    pSliceHeader: &mut sliceHeader_t,
) -> u32 {
    /* Variables */

    let mut mbData: [u8; 384 + 15 + 32] = [0; 384 + 15 + 32];
    let data: *mut u8;
    let mut tmp: u32;
    let mut skipRun: u32;
    let mut prevSkipped: u32;
    let mut currMbAddr: u32;
    let mut moreMbs: u32;
    let mut mbCount: u32;
    let mut qpY: i32;
    let mbLayer: *mut macroblockLayer_t;

    /* Code */

    /* ensure 16-byte alignment */
    let base = mbData.as_mut_ptr();
    data = base.add(base.align_offset(16));

    mbLayer = pStorage.mbLayer;

    currMbAddr = pSliceHeader.firstMbInSlice;
    skipRun = 0;
    prevSkipped = HANTRO_FALSE;

    /* increment slice index, will be one for decoding of the first slice of
     * the picture */
    pStorage.slice[0].sliceId += 1;

    /* lastMbAddr stores address of the macroblock that was last successfully
     * decoded, needed for error handling */
    pStorage.slice[0].lastMbAddr = 0;

    mbCount = 0;
    /* initial quantization parameter for the slice is obtained as the sum of
     * initial QP for the picture and sliceQpDelta for the current slice */
    qpY = (*pStorage.activePps).picInitQp as i32 + pSliceHeader.sliceQpDelta;
    loop {
        /* primary picture and already decoded macroblock -> error */
        if pSliceHeader.redundantPicCnt == 0
            && (*pStorage.mb.add(currMbAddr as usize)).decoded != 0
        {
            return HANTRO_NOK;
        }

        SetMbParams(
            &mut *pStorage.mb.add(currMbAddr as usize),
            pSliceHeader,
            pStorage.slice[0].sliceId,
            (*pStorage.activePps).chromaQpIndexOffset,
        );

        if !IS_I_SLICE(pSliceHeader.sliceType) {
            if prevSkipped == 0 {
                tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut skipRun);
                if tmp != HANTRO_OK {
                    return tmp;
                }
                /* skip_run shall be less than or equal to number of
                 * macroblocks left */
                if skipRun > (pStorage.picSizeInMbs - currMbAddr) {
                    return HANTRO_NOK;
                }
                if skipRun != 0 {
                    prevSkipped = HANTRO_TRUE;
                    core::ptr::write_bytes(
                        &mut (*mbLayer).mbPred as *mut mbPred_t,
                        0,
                        1,
                    );
                    /* mark current macroblock skipped */
                    (*mbLayer).mbType = P_Skip;
                }
            }
        }

        if skipRun != 0 {
            skipRun -= 1;
        } else {
            prevSkipped = HANTRO_FALSE;
            tmp = h264bsdDecodeMacroblockLayer(
                pStrmData,
                &mut *mbLayer,
                &*pStorage.mb.add(currMbAddr as usize),
                pSliceHeader.sliceType,
                pSliceHeader.numRefIdxL0Active,
            );
            if tmp != HANTRO_OK {
                return tmp;
            }
        }

        tmp = h264bsdDecodeMacroblock(
            &mut *pStorage.mb.add(currMbAddr as usize),
            &mut *mbLayer,
            currImage,
            &mut pStorage.dpb[0],
            &mut qpY,
            currMbAddr,
            (*pStorage.activePps).constrainedIntraPredFlag,
            data,
        );
        if tmp != HANTRO_OK {
            return tmp;
        }

        /* increment macroblock count only for macroblocks that were decoded
         * for the first time (redundant slices) */
        if (*pStorage.mb.add(currMbAddr as usize)).decoded == 1 {
            mbCount += 1;
        }

        /* keep on processing as long as there is stream data left or
         * processing of macroblocks to be skipped based on the last skipRun is
         * not finished */
        moreMbs = if h264bsdMoreRbspData(pStrmData) != 0 || skipRun != 0 {
            HANTRO_TRUE
        } else {
            HANTRO_FALSE
        };

        /* lastMbAddr is only updated for intra slices (all macroblocks of
         * inter slices will be lost in case of an error) */
        if IS_I_SLICE(pSliceHeader.sliceType) {
            pStorage.slice[0].lastMbAddr = currMbAddr;
        }

        currMbAddr = h264bsdNextMbAddress(
            pStorage.sliceGroupMap,
            pStorage.picSizeInMbs,
            currMbAddr,
        );
        /* data left in the buffer but no more macroblocks for current slice
         * group -> error */
        if moreMbs != 0 && currMbAddr == 0 {
            return HANTRO_NOK;
        }

        if moreMbs == 0 {
            break;
        }
    }

    if (pStorage.slice[0].numDecodedMbs + mbCount) > pStorage.picSizeInMbs {
        return HANTRO_NOK;
    }

    pStorage.slice[0].numDecodedMbs += mbCount;

    HANTRO_OK
}

/*------------------------------------------------------------------------------

   5.2  Function: SetMbParams

        Functional description:
            Set macroblock parameters that remain constant for this slice

        Inputs:
            pSlice      pointer to current slice header
            sliceId     id of the current slice
            chromaQpIndexOffset

        Outputs:
            pMb         pointer to macroblock structure which is updated

        Returns:
            none

------------------------------------------------------------------------------*/

fn SetMbParams(
    pMb: &mut mbStorage_t,
    pSlice: &mut sliceHeader_t,
    sliceId: u32,
    chromaQpIndexOffset: i32,
) {
    /* Variables */
    let tmp1: u32;
    let tmp2: i32;
    let tmp3: i32;

    /* Code */

    tmp1 = pSlice.disableDeblockingFilterIdc;
    tmp2 = pSlice.sliceAlphaC0Offset;
    tmp3 = pSlice.sliceBetaOffset;
    pMb.sliceId = sliceId;
    pMb.disableDeblockingFilterIdc = tmp1;
    pMb.filterOffsetA = tmp2;
    pMb.filterOffsetB = tmp3;
    pMb.chromaQpIndexOffset = chromaQpIndexOffset;
}
