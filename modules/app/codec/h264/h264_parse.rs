// Mechanical Rust port of h264bsd translation units:
//   h264bsd_nal_unit.c
//   h264bsd_seq_param_set.c
//   h264bsd_pic_param_set.c
//   h264bsd_vui.c
//   h264bsd_byte_stream.c
// per the port rules in scratchpad/PORT_RULES.md (bit-exact, C names
// verbatim, plain-C build paths, ASSERT/DEBUG/EPRINT omitted).
// ALLOCATE() calls are routed through the `alloc: &Allocator` parameter.

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
// h264bsd_nal_unit.c
// ============================================================================

/*------------------------------------------------------------------------------

    Function name: h264bsdDecodeNalUnit

        Functional description:
            Decode NAL unit header information

        Inputs:
            pStrmData       pointer to stream data structure

        Outputs:
            pNalUnit        NAL unit header information is stored here

        Returns:
            HANTRO_OK       success
            HANTRO_NOK      invalid NAL unit header information

------------------------------------------------------------------------------*/

pub fn h264bsdDecodeNalUnit(pStrmData: &mut strmData_t, pNalUnit: &mut nalUnit_t) -> u32 {
    /* Variables */

    let mut tmp: u32;

    /* Code */

    /* forbidden_zero_bit (not checked to be zero, errors ignored) */
    tmp = h264bsdGetBits(pStrmData, 1);
    /* Assuming that NAL unit starts from byte boundary -> don't have to check
     * following 7 bits for END_OF_STREAM */
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }

    tmp = h264bsdGetBits(pStrmData, 2);
    pNalUnit.nalRefIdc = tmp;

    tmp = h264bsdGetBits(pStrmData, 5);
    pNalUnit.nalUnitType = tmp as nalUnitType_e;

    /* data partitioning NAL units not supported */
    if (tmp == 2) || (tmp == 3) || (tmp == 4) {
        return HANTRO_NOK;
    }

    /* nal_ref_idc shall not be zero for these nal_unit_types */
    if ((tmp == NAL_SEQ_PARAM_SET) || (tmp == NAL_PIC_PARAM_SET) || (tmp == NAL_CODED_SLICE_IDR))
        && (pNalUnit.nalRefIdc == 0)
    {
        return HANTRO_NOK;
    }
    /* nal_ref_idc shall be zero for these nal_unit_types */
    else if ((tmp == NAL_SEI)
        || (tmp == NAL_ACCESS_UNIT_DELIMITER)
        || (tmp == NAL_END_OF_SEQUENCE)
        || (tmp == NAL_END_OF_STREAM)
        || (tmp == NAL_FILLER_DATA))
        && (pNalUnit.nalRefIdc != 0)
    {
        return HANTRO_NOK;
    }

    HANTRO_OK
}

// ============================================================================
// h264bsd_seq_param_set.c
// ============================================================================

/* enumeration to indicate invalid return value from the GetDpbSize function */
const INVALID_DPB_SIZE: u32 = 0x7FFFFFFF;

/*------------------------------------------------------------------------------

    Function name: h264bsdDecodeSeqParamSet

        Functional description:
            Decode sequence parameter set information from the stream.

            Function allocates memory for offsetForRefFrame array if
            picture order count type is 1 and numRefFramesInPicOrderCntCycle
            is greater than zero.

        Inputs:
            pStrmData       pointer to stream data structure

        Outputs:
            pSeqParamSet    decoded information is stored here

        Returns:
            HANTRO_OK       success
            HANTRO_NOK      failure, invalid information or end of stream
            MEMORY_ALLOCATION_ERROR for memory allocation failure

------------------------------------------------------------------------------*/

pub unsafe fn h264bsdDecodeSeqParamSet(
    pStrmData: &mut strmData_t,
    pSeqParamSet: &mut seqParamSet_t,
    alloc: &Allocator,
) -> u32 {
    /* Variables */

    let mut tmp: u32;
    let mut i: u32;
    let mut value: u32 = 0;

    /* Code */

    core::ptr::write_bytes(pSeqParamSet as *mut seqParamSet_t, 0, 1);

    /* profile_idc */
    tmp = h264bsdGetBits(pStrmData, 8);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    pSeqParamSet.profileIdc = tmp;

    /* constrained_set0_flag */
    tmp = h264bsdGetBits(pStrmData, 1);
    /* constrained_set1_flag */
    tmp = h264bsdGetBits(pStrmData, 1);
    /* constrained_set2_flag */
    tmp = h264bsdGetBits(pStrmData, 1);

    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }

    /* reserved_zero_5bits, values of these bits shall be ignored */
    tmp = h264bsdGetBits(pStrmData, 5);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }

    tmp = h264bsdGetBits(pStrmData, 8);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    pSeqParamSet.levelIdc = tmp;

    tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut pSeqParamSet.seqParameterSetId);
    if tmp != HANTRO_OK {
        return tmp;
    }
    if pSeqParamSet.seqParameterSetId >= MAX_NUM_SEQ_PARAM_SETS as u32 {
        return HANTRO_NOK;
    }

    /* log2_max_frame_num_minus4 */
    tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }
    if value > 12 {
        return HANTRO_NOK;
    }
    /* maxFrameNum = 2^(log2_max_frame_num_minus4 + 4) */
    pSeqParamSet.maxFrameNum = 1u32 << (value + 4);

    /* valid POC types are 0, 1 and 2 */
    tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }
    if value > 2 {
        return HANTRO_NOK;
    }
    pSeqParamSet.picOrderCntType = value;

    if pSeqParamSet.picOrderCntType == 0 {
        /* log2_max_pic_order_cnt_lsb_minus4 */
        tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
        if tmp != HANTRO_OK {
            return tmp;
        }
        if value > 12 {
            return HANTRO_NOK;
        }
        /* maxPicOrderCntLsb = 2^(log2_max_pic_order_cnt_lsb_minus4 + 4) */
        pSeqParamSet.maxPicOrderCntLsb = 1u32 << (value + 4);
    } else if pSeqParamSet.picOrderCntType == 1 {
        tmp = h264bsdGetBits(pStrmData, 1);
        if tmp == END_OF_STREAM {
            return HANTRO_NOK;
        }
        pSeqParamSet.deltaPicOrderAlwaysZeroFlag =
            if tmp == 1 { HANTRO_TRUE } else { HANTRO_FALSE };

        tmp = h264bsdDecodeExpGolombSigned(pStrmData, &mut pSeqParamSet.offsetForNonRefPic);
        if tmp != HANTRO_OK {
            return tmp;
        }

        tmp = h264bsdDecodeExpGolombSigned(pStrmData, &mut pSeqParamSet.offsetForTopToBottomField);
        if tmp != HANTRO_OK {
            return tmp;
        }

        tmp = h264bsdDecodeExpGolombUnsigned(
            pStrmData,
            &mut pSeqParamSet.numRefFramesInPicOrderCntCycle,
        );
        if tmp != HANTRO_OK {
            return tmp;
        }
        if pSeqParamSet.numRefFramesInPicOrderCntCycle > 255 {
            return HANTRO_NOK;
        }

        if pSeqParamSet.numRefFramesInPicOrderCntCycle != 0 {
            /* NOTE: This has to be freed somewhere! */
            pSeqParamSet.offsetForRefFrame =
                alloc.alloc_n::<i32>(pSeqParamSet.numRefFramesInPicOrderCntCycle as usize);
            if pSeqParamSet.offsetForRefFrame.is_null() {
                return MEMORY_ALLOCATION_ERROR;
            }

            i = 0;
            while i < pSeqParamSet.numRefFramesInPicOrderCntCycle {
                tmp = h264bsdDecodeExpGolombSigned(
                    pStrmData,
                    &mut *pSeqParamSet.offsetForRefFrame.add(i as usize),
                );
                if tmp != HANTRO_OK {
                    return tmp;
                }
                i += 1;
            }
        } else {
            pSeqParamSet.offsetForRefFrame = core::ptr::null_mut();
        }
    }

    tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut pSeqParamSet.numRefFrames);
    if tmp != HANTRO_OK {
        return tmp;
    }
    if pSeqParamSet.numRefFrames > MAX_NUM_REF_PICS as u32 {
        return HANTRO_NOK;
    }

    tmp = h264bsdGetBits(pStrmData, 1);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    pSeqParamSet.gapsInFrameNumValueAllowedFlag =
        if tmp == 1 { HANTRO_TRUE } else { HANTRO_FALSE };

    tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }
    pSeqParamSet.picWidthInMbs = value + 1;

    tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }
    pSeqParamSet.picHeightInMbs = value + 1;

    /* frame_mbs_only_flag, shall be 1 for baseline profile */
    tmp = h264bsdGetBits(pStrmData, 1);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    if tmp == 0 {
        return HANTRO_NOK;
    }

    /* direct_8x8_inference_flag */
    tmp = h264bsdGetBits(pStrmData, 1);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }

    tmp = h264bsdGetBits(pStrmData, 1);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    pSeqParamSet.frameCroppingFlag = if tmp == 1 { HANTRO_TRUE } else { HANTRO_FALSE };

    if pSeqParamSet.frameCroppingFlag != 0 {
        tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut pSeqParamSet.frameCropLeftOffset);
        if tmp != HANTRO_OK {
            return tmp;
        }
        tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut pSeqParamSet.frameCropRightOffset);
        if tmp != HANTRO_OK {
            return tmp;
        }
        tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut pSeqParamSet.frameCropTopOffset);
        if tmp != HANTRO_OK {
            return tmp;
        }
        tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut pSeqParamSet.frameCropBottomOffset);
        if tmp != HANTRO_OK {
            return tmp;
        }

        /* check that frame cropping params are valid, parameters shall
         * specify non-negative area within the original picture */
        if ((pSeqParamSet.frameCropLeftOffset as i32)
            > (8 * pSeqParamSet.picWidthInMbs as i32
                - (pSeqParamSet.frameCropRightOffset as i32 + 1)))
            || ((pSeqParamSet.frameCropTopOffset as i32)
                > (8 * pSeqParamSet.picHeightInMbs as i32
                    - (pSeqParamSet.frameCropBottomOffset as i32 + 1)))
        {
            return HANTRO_NOK;
        }
    }

    /* check that image dimensions and levelIdc match */
    tmp = pSeqParamSet.picWidthInMbs * pSeqParamSet.picHeightInMbs;
    value = GetDpbSize(tmp, pSeqParamSet.levelIdc);
    if value == INVALID_DPB_SIZE || pSeqParamSet.numRefFrames > value {
        value = pSeqParamSet.numRefFrames;
    }
    pSeqParamSet.maxDpbSize = value;

    tmp = h264bsdGetBits(pStrmData, 1);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    pSeqParamSet.vuiParametersPresentFlag = if tmp == 1 { HANTRO_TRUE } else { HANTRO_FALSE };

    /* VUI */
    if pSeqParamSet.vuiParametersPresentFlag != 0 {
        pSeqParamSet.vuiParameters = alloc.alloc_n::<vuiParameters_t>(1);
        if pSeqParamSet.vuiParameters.is_null() {
            return MEMORY_ALLOCATION_ERROR;
        }
        tmp = h264bsdDecodeVuiParameters(pStrmData, &mut *pSeqParamSet.vuiParameters);
        if tmp != HANTRO_OK {
            return tmp;
        }
        /* check numReorderFrames and maxDecFrameBuffering */
        if (*pSeqParamSet.vuiParameters).bitstreamRestrictionFlag != 0 {
            if (*pSeqParamSet.vuiParameters).numReorderFrames
                > (*pSeqParamSet.vuiParameters).maxDecFrameBuffering
                || (*pSeqParamSet.vuiParameters).maxDecFrameBuffering < pSeqParamSet.numRefFrames
                || (*pSeqParamSet.vuiParameters).maxDecFrameBuffering > pSeqParamSet.maxDpbSize
            {
                return HANTRO_NOK;
            }

            /* standard says that "the sequence shall not require a DPB with
             * size of more than max(1, maxDecFrameBuffering) */
            pSeqParamSet.maxDpbSize =
                MAX!(1, (*pSeqParamSet.vuiParameters).maxDecFrameBuffering);
        }
    }

    tmp = h264bsdRbspTrailingBits(pStrmData);

    /* ignore possible errors in trailing bits of parameters sets */
    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: GetDpbSize

        Functional description:
            Get size of the DPB in frames. Size is determined based on the
            picture size and MaxDPB for the specified level. These determine
            how many pictures may fit into to the buffer. However, the size
            is also limited to a maximum of 16 frames and therefore function
            returns the minimum of the determined size and 16.

        Inputs:
            picSizeInMbs    number of macroblocks in the picture
            levelIdc        indicates the level

        Outputs:
            none

        Returns:
            size of the DPB in frames
            INVALID_DPB_SIZE when invalid levelIdc specified or picSizeInMbs
            is higher than supported by the level in question

------------------------------------------------------------------------------*/

fn GetDpbSize(picSizeInMbs: u32, levelIdc: u32) -> u32 {
    /* Variables */

    let mut tmp: u32;
    let maxPicSizeInMbs: u32;

    /* Code */

    /* use tmp as the size of the DPB in bytes, computes as 1024 * MaxDPB
     * (from table A-1 in Annex A) */
    match levelIdc {
        10 => {
            tmp = 152064;
            maxPicSizeInMbs = 99;
        }
        11 => {
            tmp = 345600;
            maxPicSizeInMbs = 396;
        }
        12 => {
            tmp = 912384;
            maxPicSizeInMbs = 396;
        }
        13 => {
            tmp = 912384;
            maxPicSizeInMbs = 396;
        }
        20 => {
            tmp = 912384;
            maxPicSizeInMbs = 396;
        }
        21 => {
            tmp = 1824768;
            maxPicSizeInMbs = 792;
        }
        22 => {
            tmp = 3110400;
            maxPicSizeInMbs = 1620;
        }
        30 => {
            tmp = 3110400;
            maxPicSizeInMbs = 1620;
        }
        31 => {
            tmp = 6912000;
            maxPicSizeInMbs = 3600;
        }
        32 => {
            tmp = 7864320;
            maxPicSizeInMbs = 5120;
        }
        40 => {
            tmp = 12582912;
            maxPicSizeInMbs = 8192;
        }
        41 => {
            tmp = 12582912;
            maxPicSizeInMbs = 8192;
        }
        42 => {
            tmp = 34816 * 384;
            maxPicSizeInMbs = 8704;
        }
        50 => {
            /* standard says 42301440 here, but corrigendum "corrects" this to
             * 42393600 */
            tmp = 42393600;
            maxPicSizeInMbs = 22080;
        }
        51 => {
            tmp = 70778880;
            maxPicSizeInMbs = 36864;
        }
        _ => {
            return INVALID_DPB_SIZE;
        }
    }

    /* this is not "correct" return value! However, it results in error in
     * decoding and this was easiest place to check picture size */
    if picSizeInMbs > maxPicSizeInMbs {
        return INVALID_DPB_SIZE;
    }

    tmp = udiv(tmp, picSizeInMbs * 384);

    MIN!(tmp, 16)
}

/*------------------------------------------------------------------------------

    Function name: h264bsdCompareSeqParamSets

        Functional description:
            Compare two sequence parameter sets.

        Inputs:
            pSps1   pointer to a sequence parameter set
            pSps2   pointer to another sequence parameter set

        Outputs:
            0       sequence parameter sets are equal
            1       otherwise

------------------------------------------------------------------------------*/

pub unsafe fn h264bsdCompareSeqParamSets(pSps1: &seqParamSet_t, pSps2: &seqParamSet_t) -> u32 {
    /* Variables */

    let mut i: u32;

    /* Code */

    /* first compare parameters whose existence does not depend on other
     * parameters and only compare the rest of the params if these are equal */
    if pSps1.profileIdc == pSps2.profileIdc
        && pSps1.levelIdc == pSps2.levelIdc
        && pSps1.maxFrameNum == pSps2.maxFrameNum
        && pSps1.picOrderCntType == pSps2.picOrderCntType
        && pSps1.numRefFrames == pSps2.numRefFrames
        && pSps1.gapsInFrameNumValueAllowedFlag == pSps2.gapsInFrameNumValueAllowedFlag
        && pSps1.picWidthInMbs == pSps2.picWidthInMbs
        && pSps1.picHeightInMbs == pSps2.picHeightInMbs
        && pSps1.frameCroppingFlag == pSps2.frameCroppingFlag
        && pSps1.vuiParametersPresentFlag == pSps2.vuiParametersPresentFlag
    {
        if pSps1.picOrderCntType == 0 {
            if pSps1.maxPicOrderCntLsb != pSps2.maxPicOrderCntLsb {
                return 1;
            }
        } else if pSps1.picOrderCntType == 1 {
            if pSps1.deltaPicOrderAlwaysZeroFlag != pSps2.deltaPicOrderAlwaysZeroFlag
                || pSps1.offsetForNonRefPic != pSps2.offsetForNonRefPic
                || pSps1.offsetForTopToBottomField != pSps2.offsetForTopToBottomField
                || pSps1.numRefFramesInPicOrderCntCycle != pSps2.numRefFramesInPicOrderCntCycle
            {
                return 1;
            } else {
                i = 0;
                while i < pSps1.numRefFramesInPicOrderCntCycle {
                    if *pSps1.offsetForRefFrame.add(i as usize)
                        != *pSps2.offsetForRefFrame.add(i as usize)
                    {
                        return 1;
                    }
                    i += 1;
                }
            }
        }
        if pSps1.frameCroppingFlag != 0 {
            if pSps1.frameCropLeftOffset != pSps2.frameCropLeftOffset
                || pSps1.frameCropRightOffset != pSps2.frameCropRightOffset
                || pSps1.frameCropTopOffset != pSps2.frameCropTopOffset
                || pSps1.frameCropBottomOffset != pSps2.frameCropBottomOffset
            {
                return 1;
            }
        }

        return 0;
    }

    1
}

// ============================================================================
// h264bsd_pic_param_set.c
// ============================================================================

/* lookup table for ceil(log2(numSliceGroups)), i.e. number of bits needed to
 * represent range [0, numSliceGroups)
 *
 * NOTE: if MAX_NUM_SLICE_GROUPS is higher than 8 this table has to be resized
 * accordingly */
static CeilLog2NumSliceGroups: [u32; 8] = [1, 1, 2, 2, 3, 3, 3, 3];

/*------------------------------------------------------------------------------

    Function name: h264bsdDecodePicParamSet

        Functional description:
            Decode picture parameter set information from the stream.

            Function allocates memory for
                - run lengths if slice group map type is 0
                - top-left and bottom-right arrays if map type is 2
                - for slice group ids if map type is 6

            Validity of some of the slice group mapping information depends
            on the image dimensions which are not known here. Therefore the
            validity has to be checked afterwards, currently in the parameter
            set activation phase.

        Inputs:
            pStrmData       pointer to stream data structure

        Outputs:
            pPicParamSet    decoded information is stored here

        Returns:
            HANTRO_OK       success
            HANTRO_NOK      failure, invalid information or end of stream
            MEMORY_ALLOCATION_ERROR for memory allocation failure

------------------------------------------------------------------------------*/

pub unsafe fn h264bsdDecodePicParamSet(
    pStrmData: &mut strmData_t,
    pPicParamSet: &mut picParamSet_t,
    alloc: &Allocator,
) -> u32 {
    /* Variables */

    let mut tmp: u32;
    let mut i: u32;
    let mut value: u32 = 0;
    let mut itmp: i32 = 0;

    /* Code */

    core::ptr::write_bytes(pPicParamSet as *mut picParamSet_t, 0, 1);

    tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut pPicParamSet.picParameterSetId);
    if tmp != HANTRO_OK {
        return tmp;
    }
    if pPicParamSet.picParameterSetId >= MAX_NUM_PIC_PARAM_SETS as u32 {
        return HANTRO_NOK;
    }

    tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut pPicParamSet.seqParameterSetId);
    if tmp != HANTRO_OK {
        return tmp;
    }
    if pPicParamSet.seqParameterSetId >= MAX_NUM_SEQ_PARAM_SETS as u32 {
        return HANTRO_NOK;
    }

    /* entropy_coding_mode_flag, shall be 0 for baseline profile */
    tmp = h264bsdGetBits(pStrmData, 1);
    if tmp != 0 {
        return HANTRO_NOK;
    }

    tmp = h264bsdGetBits(pStrmData, 1);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    pPicParamSet.picOrderPresentFlag = if tmp == 1 { HANTRO_TRUE } else { HANTRO_FALSE };

    /* num_slice_groups_minus1 */
    tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }
    pPicParamSet.numSliceGroups = value + 1;
    if pPicParamSet.numSliceGroups > MAX_NUM_SLICE_GROUPS as u32 {
        return HANTRO_NOK;
    }

    /* decode slice group mapping information if more than one slice groups */
    if pPicParamSet.numSliceGroups > 1 {
        tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut pPicParamSet.sliceGroupMapType);
        if tmp != HANTRO_OK {
            return tmp;
        }
        if pPicParamSet.sliceGroupMapType > 6 {
            return HANTRO_NOK;
        }

        if pPicParamSet.sliceGroupMapType == 0 {
            pPicParamSet.runLength = alloc.alloc_n::<u32>(pPicParamSet.numSliceGroups as usize);
            if pPicParamSet.runLength.is_null() {
                return MEMORY_ALLOCATION_ERROR;
            }
            i = 0;
            while i < pPicParamSet.numSliceGroups {
                tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
                if tmp != HANTRO_OK {
                    return tmp;
                }
                *pPicParamSet.runLength.add(i as usize) = value + 1;
                /* param values checked in CheckPps() */
                i += 1;
            }
        } else if pPicParamSet.sliceGroupMapType == 2 {
            pPicParamSet.topLeft =
                alloc.alloc_n::<u32>((pPicParamSet.numSliceGroups - 1) as usize);
            pPicParamSet.bottomRight =
                alloc.alloc_n::<u32>((pPicParamSet.numSliceGroups - 1) as usize);
            if pPicParamSet.topLeft.is_null() || pPicParamSet.bottomRight.is_null() {
                return MEMORY_ALLOCATION_ERROR;
            }
            i = 0;
            while i < pPicParamSet.numSliceGroups - 1 {
                tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
                if tmp != HANTRO_OK {
                    return tmp;
                }
                *pPicParamSet.topLeft.add(i as usize) = value;
                tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
                if tmp != HANTRO_OK {
                    return tmp;
                }
                *pPicParamSet.bottomRight.add(i as usize) = value;
                /* param values checked in CheckPps() */
                i += 1;
            }
        } else if (pPicParamSet.sliceGroupMapType == 3)
            || (pPicParamSet.sliceGroupMapType == 4)
            || (pPicParamSet.sliceGroupMapType == 5)
        {
            tmp = h264bsdGetBits(pStrmData, 1);
            if tmp == END_OF_STREAM {
                return HANTRO_NOK;
            }
            pPicParamSet.sliceGroupChangeDirectionFlag =
                if tmp == 1 { HANTRO_TRUE } else { HANTRO_FALSE };
            tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
            if tmp != HANTRO_OK {
                return tmp;
            }
            pPicParamSet.sliceGroupChangeRate = value + 1;
            /* param value checked in CheckPps() */
        } else if pPicParamSet.sliceGroupMapType == 6 {
            tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
            if tmp != HANTRO_OK {
                return tmp;
            }
            pPicParamSet.picSizeInMapUnits = value + 1;

            pPicParamSet.sliceGroupId =
                alloc.alloc_n::<u32>(pPicParamSet.picSizeInMapUnits as usize);
            if pPicParamSet.sliceGroupId.is_null() {
                return MEMORY_ALLOCATION_ERROR;
            }

            /* determine number of bits needed to represent range
             * [0, numSliceGroups) */
            tmp = CeilLog2NumSliceGroups[(pPicParamSet.numSliceGroups - 1) as usize];

            i = 0;
            while i < pPicParamSet.picSizeInMapUnits {
                *pPicParamSet.sliceGroupId.add(i as usize) = h264bsdGetBits(pStrmData, tmp);
                if *pPicParamSet.sliceGroupId.add(i as usize) >= pPicParamSet.numSliceGroups {
                    return HANTRO_NOK;
                }
                i += 1;
            }
        }
    }

    /* num_ref_idx_l0_active_minus1 */
    tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }
    if value > 31 {
        return HANTRO_NOK;
    }
    pPicParamSet.numRefIdxL0Active = value + 1;

    /* num_ref_idx_l1_active_minus1 */
    tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }
    if value > 31 {
        return HANTRO_NOK;
    }

    /* weighted_pred_flag, this shall be 0 for baseline profile */
    tmp = h264bsdGetBits(pStrmData, 1);
    if tmp != 0 {
        return HANTRO_NOK;
    }

    /* weighted_bipred_idc */
    tmp = h264bsdGetBits(pStrmData, 2);
    if tmp > 2 {
        return HANTRO_NOK;
    }

    /* pic_init_qp_minus26 */
    tmp = h264bsdDecodeExpGolombSigned(pStrmData, &mut itmp);
    if tmp != HANTRO_OK {
        return tmp;
    }
    if (itmp < -26) || (itmp > 25) {
        return HANTRO_NOK;
    }
    pPicParamSet.picInitQp = (itmp + 26) as u32;

    /* pic_init_qs_minus26 */
    tmp = h264bsdDecodeExpGolombSigned(pStrmData, &mut itmp);
    if tmp != HANTRO_OK {
        return tmp;
    }
    if (itmp < -26) || (itmp > 25) {
        return HANTRO_NOK;
    }

    tmp = h264bsdDecodeExpGolombSigned(pStrmData, &mut itmp);
    if tmp != HANTRO_OK {
        return tmp;
    }
    if (itmp < -12) || (itmp > 12) {
        return HANTRO_NOK;
    }
    pPicParamSet.chromaQpIndexOffset = itmp;

    tmp = h264bsdGetBits(pStrmData, 1);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    pPicParamSet.deblockingFilterControlPresentFlag =
        if tmp == 1 { HANTRO_TRUE } else { HANTRO_FALSE };

    tmp = h264bsdGetBits(pStrmData, 1);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    pPicParamSet.constrainedIntraPredFlag = if tmp == 1 { HANTRO_TRUE } else { HANTRO_FALSE };

    tmp = h264bsdGetBits(pStrmData, 1);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    pPicParamSet.redundantPicCntPresentFlag = if tmp == 1 { HANTRO_TRUE } else { HANTRO_FALSE };

    tmp = h264bsdRbspTrailingBits(pStrmData);

    /* ignore possible errors in trailing bits of parameters sets */
    HANTRO_OK
}

// ============================================================================
// h264bsd_vui.c
// ============================================================================

const MAX_DPB_SIZE: u32 = 16;
const MAX_BR: u32 = 240000; /* for level 5.1 */
const MAX_CPB: u32 = 240000; /* for level 5.1 */

/*------------------------------------------------------------------------------

    Function: h264bsdDecodeVuiParameters

        Functional description:
            Decode VUI parameters from the stream. See standard for details.

        Inputs:
            pStrmData       pointer to stream data structure

        Outputs:
            pVuiParameters  decoded information is stored here

        Returns:
            HANTRO_OK       success
            HANTRO_NOK      invalid stream data or end of stream

------------------------------------------------------------------------------*/

pub fn h264bsdDecodeVuiParameters(
    pStrmData: &mut strmData_t,
    pVuiParameters: &mut vuiParameters_t,
) -> u32 {
    /* Variables */

    let mut tmp: u32;

    /* Code */

    unsafe {
        core::ptr::write_bytes(pVuiParameters as *mut vuiParameters_t, 0, 1);
    }

    tmp = h264bsdGetBits(pStrmData, 1);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    pVuiParameters.aspectRatioPresentFlag = if tmp == 1 { HANTRO_TRUE } else { HANTRO_FALSE };

    if pVuiParameters.aspectRatioPresentFlag != 0 {
        tmp = h264bsdGetBits(pStrmData, 8);
        if tmp == END_OF_STREAM {
            return HANTRO_NOK;
        }
        pVuiParameters.aspectRatioIdc = tmp;

        if pVuiParameters.aspectRatioIdc == ASPECT_RATIO_EXTENDED_SAR {
            tmp = h264bsdGetBits(pStrmData, 16);
            if tmp == END_OF_STREAM {
                return HANTRO_NOK;
            }
            pVuiParameters.sarWidth = tmp;

            tmp = h264bsdGetBits(pStrmData, 16);
            if tmp == END_OF_STREAM {
                return HANTRO_NOK;
            }
            pVuiParameters.sarHeight = tmp;
        }
    }

    tmp = h264bsdGetBits(pStrmData, 1);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    pVuiParameters.overscanInfoPresentFlag = if tmp == 1 { HANTRO_TRUE } else { HANTRO_FALSE };

    if pVuiParameters.overscanInfoPresentFlag != 0 {
        tmp = h264bsdGetBits(pStrmData, 1);
        if tmp == END_OF_STREAM {
            return HANTRO_NOK;
        }
        pVuiParameters.overscanAppropriateFlag = if tmp == 1 { HANTRO_TRUE } else { HANTRO_FALSE };
    }

    tmp = h264bsdGetBits(pStrmData, 1);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    pVuiParameters.videoSignalTypePresentFlag = if tmp == 1 { HANTRO_TRUE } else { HANTRO_FALSE };

    if pVuiParameters.videoSignalTypePresentFlag != 0 {
        tmp = h264bsdGetBits(pStrmData, 3);
        if tmp == END_OF_STREAM {
            return HANTRO_NOK;
        }
        pVuiParameters.videoFormat = tmp;

        tmp = h264bsdGetBits(pStrmData, 1);
        if tmp == END_OF_STREAM {
            return HANTRO_NOK;
        }
        pVuiParameters.videoFullRangeFlag = if tmp == 1 { HANTRO_TRUE } else { HANTRO_FALSE };

        tmp = h264bsdGetBits(pStrmData, 1);
        if tmp == END_OF_STREAM {
            return HANTRO_NOK;
        }
        pVuiParameters.colourDescriptionPresentFlag =
            if tmp == 1 { HANTRO_TRUE } else { HANTRO_FALSE };

        if pVuiParameters.colourDescriptionPresentFlag != 0 {
            tmp = h264bsdGetBits(pStrmData, 8);
            if tmp == END_OF_STREAM {
                return HANTRO_NOK;
            }
            pVuiParameters.colourPrimaries = tmp;

            tmp = h264bsdGetBits(pStrmData, 8);
            if tmp == END_OF_STREAM {
                return HANTRO_NOK;
            }
            pVuiParameters.transferCharacteristics = tmp;

            tmp = h264bsdGetBits(pStrmData, 8);
            if tmp == END_OF_STREAM {
                return HANTRO_NOK;
            }
            pVuiParameters.matrixCoefficients = tmp;
        } else {
            pVuiParameters.colourPrimaries = 2;
            pVuiParameters.transferCharacteristics = 2;
            pVuiParameters.matrixCoefficients = 2;
        }
    } else {
        pVuiParameters.videoFormat = 5;
        pVuiParameters.colourPrimaries = 2;
        pVuiParameters.transferCharacteristics = 2;
        pVuiParameters.matrixCoefficients = 2;
    }

    tmp = h264bsdGetBits(pStrmData, 1);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    pVuiParameters.chromaLocInfoPresentFlag = if tmp == 1 { HANTRO_TRUE } else { HANTRO_FALSE };

    if pVuiParameters.chromaLocInfoPresentFlag != 0 {
        tmp = h264bsdDecodeExpGolombUnsigned(
            pStrmData,
            &mut pVuiParameters.chromaSampleLocTypeTopField,
        );
        if tmp != HANTRO_OK {
            return tmp;
        }
        if pVuiParameters.chromaSampleLocTypeTopField > 5 {
            return HANTRO_NOK;
        }

        tmp = h264bsdDecodeExpGolombUnsigned(
            pStrmData,
            &mut pVuiParameters.chromaSampleLocTypeBottomField,
        );
        if tmp != HANTRO_OK {
            return tmp;
        }
        if pVuiParameters.chromaSampleLocTypeBottomField > 5 {
            return HANTRO_NOK;
        }
    }

    tmp = h264bsdGetBits(pStrmData, 1);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    pVuiParameters.timingInfoPresentFlag = if tmp == 1 { HANTRO_TRUE } else { HANTRO_FALSE };

    if pVuiParameters.timingInfoPresentFlag != 0 {
        tmp = h264bsdShowBits32(pStrmData);
        if h264bsdFlushBits(pStrmData, 32) == END_OF_STREAM {
            return HANTRO_NOK;
        }
        if tmp == 0 {
            return HANTRO_NOK;
        }
        pVuiParameters.numUnitsInTick = tmp;

        tmp = h264bsdShowBits32(pStrmData);
        if h264bsdFlushBits(pStrmData, 32) == END_OF_STREAM {
            return HANTRO_NOK;
        }
        if tmp == 0 {
            return HANTRO_NOK;
        }
        pVuiParameters.timeScale = tmp;

        tmp = h264bsdGetBits(pStrmData, 1);
        if tmp == END_OF_STREAM {
            return HANTRO_NOK;
        }
        pVuiParameters.fixedFrameRateFlag = if tmp == 1 { HANTRO_TRUE } else { HANTRO_FALSE };
    }

    tmp = h264bsdGetBits(pStrmData, 1);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    pVuiParameters.nalHrdParametersPresentFlag = if tmp == 1 { HANTRO_TRUE } else { HANTRO_FALSE };

    if pVuiParameters.nalHrdParametersPresentFlag != 0 {
        tmp = DecodeHrdParameters(pStrmData, &mut pVuiParameters.nalHrdParameters);
        if tmp != HANTRO_OK {
            return tmp;
        }
    } else {
        pVuiParameters.nalHrdParameters.cpbCnt = 1;
        /* MaxBR and MaxCPB should be the values correspondig to the levelIdc
         * in the SPS containing these VUI parameters. However, these values
         * are not used anywhere and maximum for any level will be used here */
        pVuiParameters.nalHrdParameters.bitRateValue[0] = 1200 * MAX_BR + 1;
        pVuiParameters.nalHrdParameters.cpbSizeValue[0] = 1200 * MAX_CPB + 1;
        pVuiParameters.nalHrdParameters.initialCpbRemovalDelayLength = 24;
        pVuiParameters.nalHrdParameters.cpbRemovalDelayLength = 24;
        pVuiParameters.nalHrdParameters.dpbOutputDelayLength = 24;
        pVuiParameters.nalHrdParameters.timeOffsetLength = 24;
    }

    tmp = h264bsdGetBits(pStrmData, 1);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    pVuiParameters.vclHrdParametersPresentFlag = if tmp == 1 { HANTRO_TRUE } else { HANTRO_FALSE };

    if pVuiParameters.vclHrdParametersPresentFlag != 0 {
        tmp = DecodeHrdParameters(pStrmData, &mut pVuiParameters.vclHrdParameters);
        if tmp != HANTRO_OK {
            return tmp;
        }
    } else {
        pVuiParameters.vclHrdParameters.cpbCnt = 1;
        /* MaxBR and MaxCPB should be the values correspondig to the levelIdc
         * in the SPS containing these VUI parameters. However, these values
         * are not used anywhere and maximum for any level will be used here */
        pVuiParameters.vclHrdParameters.bitRateValue[0] = 1000 * MAX_BR + 1;
        pVuiParameters.vclHrdParameters.cpbSizeValue[0] = 1000 * MAX_CPB + 1;
        pVuiParameters.vclHrdParameters.initialCpbRemovalDelayLength = 24;
        pVuiParameters.vclHrdParameters.cpbRemovalDelayLength = 24;
        pVuiParameters.vclHrdParameters.dpbOutputDelayLength = 24;
        pVuiParameters.vclHrdParameters.timeOffsetLength = 24;
    }

    if pVuiParameters.nalHrdParametersPresentFlag != 0
        || pVuiParameters.vclHrdParametersPresentFlag != 0
    {
        tmp = h264bsdGetBits(pStrmData, 1);
        if tmp == END_OF_STREAM {
            return HANTRO_NOK;
        }
        pVuiParameters.lowDelayHrdFlag = if tmp == 1 { HANTRO_TRUE } else { HANTRO_FALSE };
    }

    tmp = h264bsdGetBits(pStrmData, 1);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    pVuiParameters.picStructPresentFlag = if tmp == 1 { HANTRO_TRUE } else { HANTRO_FALSE };

    tmp = h264bsdGetBits(pStrmData, 1);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    pVuiParameters.bitstreamRestrictionFlag = if tmp == 1 { HANTRO_TRUE } else { HANTRO_FALSE };

    if pVuiParameters.bitstreamRestrictionFlag != 0 {
        tmp = h264bsdGetBits(pStrmData, 1);
        if tmp == END_OF_STREAM {
            return HANTRO_NOK;
        }
        pVuiParameters.motionVectorsOverPicBoundariesFlag =
            if tmp == 1 { HANTRO_TRUE } else { HANTRO_FALSE };

        tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut pVuiParameters.maxBytesPerPicDenom);
        if tmp != HANTRO_OK {
            return tmp;
        }
        if pVuiParameters.maxBytesPerPicDenom > 16 {
            return HANTRO_NOK;
        }

        tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut pVuiParameters.maxBitsPerMbDenom);
        if tmp != HANTRO_OK {
            return tmp;
        }
        if pVuiParameters.maxBitsPerMbDenom > 16 {
            return HANTRO_NOK;
        }

        tmp = h264bsdDecodeExpGolombUnsigned(
            pStrmData,
            &mut pVuiParameters.log2MaxMvLengthHorizontal,
        );
        if tmp != HANTRO_OK {
            return tmp;
        }
        if pVuiParameters.log2MaxMvLengthHorizontal > 16 {
            return HANTRO_NOK;
        }

        tmp = h264bsdDecodeExpGolombUnsigned(
            pStrmData,
            &mut pVuiParameters.log2MaxMvLengthVertical,
        );
        if tmp != HANTRO_OK {
            return tmp;
        }
        if pVuiParameters.log2MaxMvLengthVertical > 16 {
            return HANTRO_NOK;
        }

        tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut pVuiParameters.numReorderFrames);
        if tmp != HANTRO_OK {
            return tmp;
        }

        tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut pVuiParameters.maxDecFrameBuffering);
        if tmp != HANTRO_OK {
            return tmp;
        }
    } else {
        pVuiParameters.motionVectorsOverPicBoundariesFlag = HANTRO_TRUE;
        pVuiParameters.maxBytesPerPicDenom = 2;
        pVuiParameters.maxBitsPerMbDenom = 1;
        pVuiParameters.log2MaxMvLengthHorizontal = 16;
        pVuiParameters.log2MaxMvLengthVertical = 16;
        pVuiParameters.numReorderFrames = MAX_DPB_SIZE;
        pVuiParameters.maxDecFrameBuffering = MAX_DPB_SIZE;
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: DecodeHrdParameters

        Functional description:
            Decode HRD parameters from the stream. See standard for details.

        Inputs:
            pStrmData       pointer to stream data structure

        Outputs:
            pHrdParameters  decoded information is stored here

        Returns:
            HANTRO_OK       success
            HANTRO_NOK      invalid stream data

------------------------------------------------------------------------------*/

fn DecodeHrdParameters(pStrmData: &mut strmData_t, pHrdParameters: &mut hrdParameters_t) -> u32 {
    /* Variables */

    let mut tmp: u32;
    let mut i: u32;

    /* Code */

    tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut pHrdParameters.cpbCnt);
    if tmp != HANTRO_OK {
        return tmp;
    }
    /* cpbCount = cpb_cnt_minus1 + 1 */
    pHrdParameters.cpbCnt += 1;
    if pHrdParameters.cpbCnt > MAX_CPB_CNT as u32 {
        return HANTRO_NOK;
    }

    tmp = h264bsdGetBits(pStrmData, 4);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    pHrdParameters.bitRateScale = tmp;

    tmp = h264bsdGetBits(pStrmData, 4);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    pHrdParameters.cpbSizeScale = tmp;

    i = 0;
    while i < pHrdParameters.cpbCnt {
        /* bit_rate_value_minus1 in the range [0, 2^32 - 2] */
        tmp = h264bsdDecodeExpGolombUnsigned(
            pStrmData,
            &mut pHrdParameters.bitRateValue[i as usize],
        );
        if tmp != HANTRO_OK {
            return tmp;
        }
        if pHrdParameters.bitRateValue[i as usize] > 4294967294u32 {
            return HANTRO_NOK;
        }
        pHrdParameters.bitRateValue[i as usize] += 1;
        /* this may result in overflow, but this value is not used for
         * anything */
        pHrdParameters.bitRateValue[i as usize] = pHrdParameters.bitRateValue[i as usize]
            .wrapping_mul(1u32 << (6 + pHrdParameters.bitRateScale));

        /* cpb_size_value_minus1 in the range [0, 2^32 - 2] */
        tmp = h264bsdDecodeExpGolombUnsigned(
            pStrmData,
            &mut pHrdParameters.cpbSizeValue[i as usize],
        );
        if tmp != HANTRO_OK {
            return tmp;
        }
        if pHrdParameters.cpbSizeValue[i as usize] > 4294967294u32 {
            return HANTRO_NOK;
        }
        pHrdParameters.cpbSizeValue[i as usize] += 1;
        /* this may result in overflow, but this value is not used for
         * anything */
        pHrdParameters.cpbSizeValue[i as usize] = pHrdParameters.cpbSizeValue[i as usize]
            .wrapping_mul(1u32 << (4 + pHrdParameters.cpbSizeScale));

        tmp = h264bsdGetBits(pStrmData, 1);
        if tmp == END_OF_STREAM {
            return HANTRO_NOK;
        }
        pHrdParameters.cbrFlag[i as usize] = if tmp == 1 { HANTRO_TRUE } else { HANTRO_FALSE };

        i += 1;
    }

    tmp = h264bsdGetBits(pStrmData, 5);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    pHrdParameters.initialCpbRemovalDelayLength = tmp + 1;

    tmp = h264bsdGetBits(pStrmData, 5);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    pHrdParameters.cpbRemovalDelayLength = tmp + 1;

    tmp = h264bsdGetBits(pStrmData, 5);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    pHrdParameters.dpbOutputDelayLength = tmp + 1;

    tmp = h264bsdGetBits(pStrmData, 5);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    pHrdParameters.timeOffsetLength = tmp;

    HANTRO_OK
}

// ============================================================================
// h264bsd_byte_stream.c
// ============================================================================

const BYTE_STREAM_ERROR: u32 = 0xFFFFFFFF;

/*------------------------------------------------------------------------------

    Function name: ExtractNalUnit

        Functional description:
            Extracts one NAL unit from the byte stream buffer. Removes
            emulation prevention bytes if present. The original stream buffer
            is used directly and is therefore modified if emulation prevention
            bytes are present in the stream.

            Stream buffer is assumed to contain either exactly one NAL unit
            and nothing else, or one or more NAL units embedded in byte
            stream format described in the Annex B of the standard. Function
            detects which one is used based on the first bytes in the buffer.

        Inputs:
            pByteStream     pointer to byte stream buffer
            len             length of the stream buffer (in bytes)

        Outputs:
            pStrmData       stream information is stored here
            readBytes       number of bytes "consumed" from the stream buffer

        Returns:
            HANTRO_OK       success
            HANTRO_NOK      error in byte stream

------------------------------------------------------------------------------*/

pub unsafe fn h264bsdExtractNalUnit(
    pByteStream: *mut u8,
    len: u32,
    pStrmData: &mut strmData_t,
    readBytes: &mut u32,
) -> u32 {
    /* Variables */

    let mut i: u32;
    let tmp: u32;
    let mut byteCount: u32;
    let initByteCount: u32;
    let mut zeroCount: u32;
    let mut byte: u8;
    let mut hasEmulation: u32 = HANTRO_FALSE;
    let mut invalidStream: u32 = HANTRO_FALSE;
    let mut readPtr: *mut u8;
    let mut writePtr: *mut u8;

    /* Code */

    /* byte stream format if starts with 0x000001 or 0x000000 */
    if len > 3
        && *pByteStream.add(0) == 0x00
        && *pByteStream.add(1) == 0x00
        && (*pByteStream.add(2) & 0xFE) == 0x00
    {
        /* search for NAL unit start point, i.e. point after first start code
         * prefix in the stream */
        zeroCount = 2;
        byteCount = 2;
        readPtr = pByteStream.add(2);
        loop {
            byte = *readPtr;
            readPtr = readPtr.add(1);
            byteCount += 1;

            if byteCount == len {
                /* no start code prefix found -> error */
                *readBytes = len;
                return HANTRO_NOK;
            }

            if byte == 0 {
                zeroCount += 1;
            } else if (byte == 0x01) && (zeroCount >= 2) {
                break;
            } else {
                zeroCount = 0;
            }
        }

        initByteCount = byteCount;

        /* determine size of the NAL unit. Search for next start code prefix
         * or end of stream and ignore possible trailing zero bytes */
        zeroCount = 0;
        loop {
            byte = *readPtr;
            readPtr = readPtr.add(1);
            byteCount += 1;
            if byte == 0 {
                zeroCount += 1;
            }

            if (byte == 0x03) && (zeroCount == 2) {
                hasEmulation = HANTRO_TRUE;
            }

            if (byte == 0x01) && (zeroCount >= 2) {
                pStrmData.strmBuffSize = byteCount - initByteCount - zeroCount - 1;
                zeroCount -= MIN!(zeroCount, 3);
                break;
            } else if byte != 0 {
                if zeroCount >= 3 {
                    invalidStream = HANTRO_TRUE;
                }
                zeroCount = 0;
            }

            if byteCount == len {
                pStrmData.strmBuffSize = byteCount - initByteCount - zeroCount;
                break;
            }
        }
    }
    /* separate NAL units as input -> just set stream params */
    else {
        initByteCount = 0;
        zeroCount = 0;
        pStrmData.strmBuffSize = len;
        hasEmulation = HANTRO_TRUE;
    }

    pStrmData.pStrmBuffStart = pByteStream.add(initByteCount as usize);
    pStrmData.pStrmCurrPos = pStrmData.pStrmBuffStart;
    pStrmData.bitPosInWord = 0;
    pStrmData.strmBuffReadBits = 0;

    /* return number of bytes "consumed" */
    *readBytes = pStrmData.strmBuffSize + initByteCount + zeroCount;

    if invalidStream != 0 {
        return HANTRO_NOK;
    }

    /* remove emulation prevention bytes before rbsp processing */
    if hasEmulation != 0 {
        tmp = pStrmData.strmBuffSize;
        readPtr = pStrmData.pStrmBuffStart as *mut u8;
        writePtr = readPtr;
        zeroCount = 0;
        i = tmp;
        while i != 0 {
            i -= 1;
            if (zeroCount == 2) && (*readPtr == 0x03) {
                /* emulation prevention byte shall be followed by one of the
                 * following bytes: 0x00, 0x01, 0x02, 0x03. This implies that
                 * emulation prevention 0x03 byte shall not be the last byte
                 * of the stream. */
                if (i == 0) || (*readPtr.add(1) > 0x03) {
                    return HANTRO_NOK;
                }

                /* do not write emulation prevention byte */
                readPtr = readPtr.add(1);
                zeroCount = 0;
            } else {
                /* NAL unit shall not contain byte sequences 0x000000,
                 * 0x000001 or 0x000002 */
                if (zeroCount == 2) && (*readPtr <= 0x02) {
                    return HANTRO_NOK;
                }

                if *readPtr == 0 {
                    zeroCount += 1;
                } else {
                    zeroCount = 0;
                }

                *writePtr = *readPtr;
                writePtr = writePtr.add(1);
                readPtr = readPtr.add(1);
            }
        }

        /* (readPtr - writePtr) indicates number of "removed" emulation
         * prevention bytes -> subtract from stream buffer size */
        pStrmData.strmBuffSize -= readPtr.offset_from(writePtr) as u32;
    }

    HANTRO_OK
}
