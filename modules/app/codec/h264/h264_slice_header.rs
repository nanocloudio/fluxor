// Mechanical Rust port of h264bsd translation units:
//   - h264bsd_slice_header.c
//   - h264bsd_pic_order_cnt.c
// per the port rules in PORT_RULES.md (bit-exact vs the C reference;
// C names kept verbatim; plain-C build paths; ASSERT/EPRINT omitted).
//
// Port helper: `strmDataCopy` replaces the C idiom
// `strmData_t tmpStrmData[1]; *tmpStrmData = *pStrmData;` (strmData_t
// is not Copy in the shared foundation).
//
// No functions skipped: everything in these two files is reachable in
// our build.

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

/// Port helper: field-wise copy of strmData_t (C struct assignment).
#[inline(always)]
fn strmDataCopy(s: &strmData_t) -> strmData_t {
    strmData_t {
        pStrmBuffStart: s.pStrmBuffStart,
        pStrmCurrPos: s.pStrmCurrPos,
        bitPosInWord: s.bitPosInWord,
        strmBuffSize: s.strmBuffSize,
        strmBuffReadBits: s.strmBuffReadBits,
    }
}

/*------------------------------------------------------------------------------

    Function name: h264bsdDecodeSliceHeader

        Functional description:
            Decode slice header data from the stream.

        Inputs:
            pStrmData       pointer to stream data structure
            pSeqParamSet    pointer to active sequence parameter set
            pPicParamSet    pointer to active picture parameter set
            pNalUnit        pointer to current NAL unit structure

        Outputs:
            pSliceHeader    decoded data is stored here

        Returns:
            HANTRO_OK       success
            HANTRO_NOK      invalid stream data or end of stream

------------------------------------------------------------------------------*/

pub unsafe fn h264bsdDecodeSliceHeader(
    pStrmData: &mut strmData_t,
    pSliceHeader: &mut sliceHeader_t,
    pSeqParamSet: &seqParamSet_t,
    pPicParamSet: &picParamSet_t,
    pNalUnit: &nalUnit_t,
) -> u32 {
    /* Variables */

    let mut tmp: u32;
    let mut i: u32;
    let mut value: u32 = 0;
    let mut itmp: i32 = 0;
    let picSizeInMbs: u32;

    /* Code */

    core::ptr::write_bytes(pSliceHeader as *mut sliceHeader_t, 0, 1);

    picSizeInMbs = pSeqParamSet.picWidthInMbs * pSeqParamSet.picHeightInMbs;
    tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }
    pSliceHeader.firstMbInSlice = value;
    if value >= picSizeInMbs {
        return HANTRO_NOK;
    }

    tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }
    pSliceHeader.sliceType = value;
    /* slice type has to be either I or P slice. P slice is not allowed when
     * current NAL unit is an IDR NAL unit or num_ref_frames is 0 */
    if !IS_I_SLICE(pSliceHeader.sliceType)
        && (!IS_P_SLICE(pSliceHeader.sliceType)
            || IS_IDR_NAL_UNIT(pNalUnit)
            || pSeqParamSet.numRefFrames == 0)
    {
        return HANTRO_NOK;
    }

    tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }
    pSliceHeader.picParameterSetId = value;
    if pSliceHeader.picParameterSetId != pPicParamSet.picParameterSetId {
        return HANTRO_NOK;
    }

    /* log2(maxFrameNum) -> num bits to represent frame_num */
    i = 0;
    while (pSeqParamSet.maxFrameNum >> i) != 0 {
        i += 1;
    }
    i -= 1;

    tmp = h264bsdGetBits(pStrmData, i);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    if IS_IDR_NAL_UNIT(pNalUnit) && tmp != 0 {
        return HANTRO_NOK;
    }
    pSliceHeader.frameNum = tmp;

    if IS_IDR_NAL_UNIT(pNalUnit) {
        tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
        if tmp != HANTRO_OK {
            return tmp;
        }
        pSliceHeader.idrPicId = value;
        if value > 65535 {
            return HANTRO_NOK;
        }
    }

    if pSeqParamSet.picOrderCntType == 0 {
        /* log2(maxPicOrderCntLsb) -> num bits to represent pic_order_cnt_lsb */
        i = 0;
        while (pSeqParamSet.maxPicOrderCntLsb >> i) != 0 {
            i += 1;
        }
        i -= 1;

        tmp = h264bsdGetBits(pStrmData, i);
        if tmp == END_OF_STREAM {
            return HANTRO_NOK;
        }
        pSliceHeader.picOrderCntLsb = tmp;

        if pPicParamSet.picOrderPresentFlag != 0 {
            tmp = h264bsdDecodeExpGolombSigned(pStrmData, &mut itmp);
            if tmp != HANTRO_OK {
                return tmp;
            }
            pSliceHeader.deltaPicOrderCntBottom = itmp;
        }

        /* check that picOrderCnt for IDR picture will be zero. See
         * DecodePicOrderCnt function to understand the logic here */
        if IS_IDR_NAL_UNIT(pNalUnit)
            && ((pSliceHeader.picOrderCntLsb > pSeqParamSet.maxPicOrderCntLsb / 2)
                || MIN!(
                    pSliceHeader.picOrderCntLsb as i32,
                    (pSliceHeader.picOrderCntLsb as i32)
                        .wrapping_add(pSliceHeader.deltaPicOrderCntBottom)
                ) != 0)
        {
            return HANTRO_NOK;
        }
    }

    if (pSeqParamSet.picOrderCntType == 1) && pSeqParamSet.deltaPicOrderAlwaysZeroFlag == 0 {
        tmp = h264bsdDecodeExpGolombSigned(pStrmData, &mut itmp);
        if tmp != HANTRO_OK {
            return tmp;
        }
        pSliceHeader.deltaPicOrderCnt[0] = itmp;

        if pPicParamSet.picOrderPresentFlag != 0 {
            tmp = h264bsdDecodeExpGolombSigned(pStrmData, &mut itmp);
            if tmp != HANTRO_OK {
                return tmp;
            }
            pSliceHeader.deltaPicOrderCnt[1] = itmp;
        }

        /* check that picOrderCnt for IDR picture will be zero. See
         * DecodePicOrderCnt function to understand the logic here */
        if IS_IDR_NAL_UNIT(pNalUnit)
            && MIN!(
                pSliceHeader.deltaPicOrderCnt[0],
                pSliceHeader.deltaPicOrderCnt[0]
                    .wrapping_add(pSeqParamSet.offsetForTopToBottomField)
                    .wrapping_add(pSliceHeader.deltaPicOrderCnt[1])
            ) != 0
        {
            return HANTRO_NOK;
        }
    }

    if pPicParamSet.redundantPicCntPresentFlag != 0 {
        tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
        if tmp != HANTRO_OK {
            return tmp;
        }
        pSliceHeader.redundantPicCnt = value;
        if value > 127 {
            return HANTRO_NOK;
        }
    }

    if IS_P_SLICE(pSliceHeader.sliceType) {
        tmp = h264bsdGetBits(pStrmData, 1);
        if tmp == END_OF_STREAM {
            return HANTRO_NOK;
        }
        pSliceHeader.numRefIdxActiveOverrideFlag = tmp;

        if pSliceHeader.numRefIdxActiveOverrideFlag != 0 {
            tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
            if tmp != HANTRO_OK {
                return tmp;
            }
            if value > 15 {
                return HANTRO_NOK;
            }
            pSliceHeader.numRefIdxL0Active = value + 1;
        }
        /* set numRefIdxL0Active from pic param set */
        else {
            /* if value (minus1) in picture parameter set exceeds 15 it should
             * have been overridden here */
            if pPicParamSet.numRefIdxL0Active > 16 {
                return HANTRO_NOK;
            }
            pSliceHeader.numRefIdxL0Active = pPicParamSet.numRefIdxL0Active;
        }
    }

    if IS_P_SLICE(pSliceHeader.sliceType) {
        tmp = RefPicListReordering(
            pStrmData,
            &mut pSliceHeader.refPicListReordering,
            pSliceHeader.numRefIdxL0Active,
            pSeqParamSet.maxFrameNum,
        );
        if tmp != HANTRO_OK {
            return tmp;
        }
    }

    if pNalUnit.nalRefIdc != 0 {
        tmp = DecRefPicMarking(
            pStrmData,
            &mut pSliceHeader.decRefPicMarking,
            pNalUnit.nalUnitType,
            pSeqParamSet.numRefFrames,
        );
        if tmp != HANTRO_OK {
            return tmp;
        }
    }

    /* decode sliceQpDelta and check that initial QP for the slice will be on
     * the range [0, 51] */
    tmp = h264bsdDecodeExpGolombSigned(pStrmData, &mut itmp);
    if tmp != HANTRO_OK {
        return tmp;
    }
    pSliceHeader.sliceQpDelta = itmp;
    itmp += pPicParamSet.picInitQp as i32;
    if (itmp < 0) || (itmp > 51) {
        return HANTRO_NOK;
    }

    if pPicParamSet.deblockingFilterControlPresentFlag != 0 {
        tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
        if tmp != HANTRO_OK {
            return tmp;
        }
        pSliceHeader.disableDeblockingFilterIdc = value;
        if pSliceHeader.disableDeblockingFilterIdc > 2 {
            return HANTRO_NOK;
        }

        if pSliceHeader.disableDeblockingFilterIdc != 1 {
            tmp = h264bsdDecodeExpGolombSigned(pStrmData, &mut itmp);
            if tmp != HANTRO_OK {
                return tmp;
            }
            if (itmp < -6) || (itmp > 6) {
                return HANTRO_NOK;
            }
            pSliceHeader.sliceAlphaC0Offset = itmp * 2;

            tmp = h264bsdDecodeExpGolombSigned(pStrmData, &mut itmp);
            if tmp != HANTRO_OK {
                return tmp;
            }
            if (itmp < -6) || (itmp > 6) {
                return HANTRO_NOK;
            }
            pSliceHeader.sliceBetaOffset = itmp * 2;
        }
    }

    if (pPicParamSet.numSliceGroups > 1)
        && (pPicParamSet.sliceGroupMapType >= 3)
        && (pPicParamSet.sliceGroupMapType <= 5)
    {
        /* set tmp to number of bits used to represent slice_group_change_cycle
         * in the stream */
        tmp = NumSliceGroupChangeCycleBits(picSizeInMbs, pPicParamSet.sliceGroupChangeRate);
        value = h264bsdGetBits(pStrmData, tmp);
        if value == END_OF_STREAM {
            return HANTRO_NOK;
        }
        pSliceHeader.sliceGroupChangeCycle = value;

        /* corresponds to tmp = Ceil(picSizeInMbs / sliceGroupChangeRate) */
        tmp = udiv(
            picSizeInMbs + pPicParamSet.sliceGroupChangeRate - 1,
            pPicParamSet.sliceGroupChangeRate,
        );
        if pSliceHeader.sliceGroupChangeCycle > tmp {
            return HANTRO_NOK;
        }
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: NumSliceGroupChangeCycleBits

        Functional description:
            Determine number of bits needed to represent
            slice_group_change_cycle in the stream. The standard states that
            slice_group_change_cycle is represented by
                Ceil( Log2( (picSizeInMbs / sliceGroupChangeRate) + 1) )

            bits. Division "/" in the equation is non-truncating division.

        Inputs:
            picSizeInMbs            picture size in macroblocks
            sliceGroupChangeRate

        Outputs:
            none

        Returns:
            number of bits needed

------------------------------------------------------------------------------*/

fn NumSliceGroupChangeCycleBits(picSizeInMbs: u32, sliceGroupChangeRate: u32) -> u32 {
    /* Variables */

    let tmp: u32;
    let mut numBits: u32;
    let mask: u32;

    /* Code */

    /* compute (picSizeInMbs / sliceGroupChangeRate + 1), rounded up */
    if urem(picSizeInMbs, sliceGroupChangeRate) != 0 {
        tmp = 2 + udiv(picSizeInMbs, sliceGroupChangeRate);
    } else {
        tmp = 1 + udiv(picSizeInMbs, sliceGroupChangeRate);
    }

    numBits = 0;
    mask = !0u32;

    /* set numBits to position of right-most non-zero bit */
    loop {
        numBits += 1;
        if tmp & (mask << numBits) == 0 {
            break;
        }
    }
    numBits -= 1;

    /* add one more bit if value greater than 2^numBits */
    if tmp & ((1u32 << numBits) - 1) != 0 {
        numBits += 1;
    }

    numBits
}

/*------------------------------------------------------------------------------

    Function: RefPicListReordering

        Functional description:
            Decode reference picture list reordering syntax elements from
            the stream. Max number of reordering commands is numRefIdxActive.

        Inputs:
            pStrmData       pointer to stream data structure
            numRefIdxActive number of active reference indices to be used for
                            current slice
            maxPicNum       maxFrameNum from the active SPS

        Outputs:
            pRefPicListReordering   decoded data is stored here

        Returns:
            HANTRO_OK       success
            HANTRO_NOK      invalid stream data

------------------------------------------------------------------------------*/

fn RefPicListReordering(
    pStrmData: &mut strmData_t,
    pRefPicListReordering: &mut refPicListReordering_t,
    numRefIdxActive: u32,
    maxPicNum: u32,
) -> u32 {
    /* Variables */

    let mut tmp: u32;
    let mut value: u32 = 0;
    let mut i: u32;
    let mut command: u32 = 0;

    /* Code */

    tmp = h264bsdGetBits(pStrmData, 1);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }

    pRefPicListReordering.refPicListReorderingFlagL0 = tmp;

    if pRefPicListReordering.refPicListReorderingFlagL0 != 0 {
        i = 0;

        loop {
            if i > numRefIdxActive {
                return HANTRO_NOK;
            }

            tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut command);
            if tmp != HANTRO_OK {
                return tmp;
            }
            if command > 3 {
                return HANTRO_NOK;
            }

            pRefPicListReordering.command[i as usize].reorderingOfPicNumsIdc = command;

            if (command == 0) || (command == 1) {
                tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
                if tmp != HANTRO_OK {
                    return tmp;
                }
                if value >= maxPicNum {
                    return HANTRO_NOK;
                }
                pRefPicListReordering.command[i as usize].absDiffPicNum = value + 1;
            } else if command == 2 {
                tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
                if tmp != HANTRO_OK {
                    return tmp;
                }
                pRefPicListReordering.command[i as usize].longTermPicNum = value;
            }
            i += 1;
            if command == 3 {
                break;
            }
        }

        /* there shall be at least one reordering command if
         * refPicListReorderingFlagL0 was set */
        if i == 1 {
            return HANTRO_NOK;
        }
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: DecRefPicMarking

        Functional description:
            Decode decoded reference picture marking syntax elements from
            the stream.

        Inputs:
            pStrmData       pointer to stream data structure
            nalUnitType     type of the current NAL unit
            numRefFrames    max number of reference frames from the active SPS

        Outputs:
            pDecRefPicMarking   decoded data is stored here

        Returns:
            HANTRO_OK       success
            HANTRO_NOK      invalid stream data

------------------------------------------------------------------------------*/

fn DecRefPicMarking(
    pStrmData: &mut strmData_t,
    pDecRefPicMarking: &mut decRefPicMarking_t,
    nalUnitType: nalUnitType_e,
    numRefFrames: u32,
) -> u32 {
    /* Variables */

    let mut tmp: u32;
    let mut value: u32 = 0;
    let mut i: u32;
    let mut operation: u32 = 0;
    /* variables for error checking purposes, store number of memory
     * management operations of certain type */
    let mut num4: u32 = 0;
    let mut num5: u32 = 0;
    let mut num6: u32 = 0;
    let mut num1to3: u32 = 0;

    /* Code */

    if nalUnitType == NAL_CODED_SLICE_IDR {
        tmp = h264bsdGetBits(pStrmData, 1);
        if tmp == END_OF_STREAM {
            return HANTRO_NOK;
        }
        pDecRefPicMarking.noOutputOfPriorPicsFlag = tmp;

        tmp = h264bsdGetBits(pStrmData, 1);
        if tmp == END_OF_STREAM {
            return HANTRO_NOK;
        }
        pDecRefPicMarking.longTermReferenceFlag = tmp;
        if numRefFrames == 0 && pDecRefPicMarking.longTermReferenceFlag != 0 {
            return HANTRO_NOK;
        }
    } else {
        tmp = h264bsdGetBits(pStrmData, 1);
        if tmp == END_OF_STREAM {
            return HANTRO_NOK;
        }
        pDecRefPicMarking.adaptiveRefPicMarkingModeFlag = tmp;
        if pDecRefPicMarking.adaptiveRefPicMarkingModeFlag != 0 {
            i = 0;
            loop {
                /* see explanation of the MAX_NUM_MMC_OPERATIONS in
                 * slice_header.h */
                if i > (2 * numRefFrames + 2) {
                    return HANTRO_NOK;
                }

                tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut operation);
                if tmp != HANTRO_OK {
                    return tmp;
                }
                if operation > 6 {
                    return HANTRO_NOK;
                }

                pDecRefPicMarking.operation[i as usize].memoryManagementControlOperation =
                    operation;
                if (operation == 1) || (operation == 3) {
                    tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
                    if tmp != HANTRO_OK {
                        return tmp;
                    }
                    pDecRefPicMarking.operation[i as usize].differenceOfPicNums = value + 1;
                }
                if operation == 2 {
                    tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
                    if tmp != HANTRO_OK {
                        return tmp;
                    }
                    pDecRefPicMarking.operation[i as usize].longTermPicNum = value;
                }
                if (operation == 3) || (operation == 6) {
                    tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
                    if tmp != HANTRO_OK {
                        return tmp;
                    }
                    pDecRefPicMarking.operation[i as usize].longTermFrameIdx = value;
                }
                if operation == 4 {
                    tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
                    if tmp != HANTRO_OK {
                        return tmp;
                    }
                    /* value shall be in range [0, numRefFrames] */
                    if value > numRefFrames {
                        return HANTRO_NOK;
                    }
                    if value == 0 {
                        pDecRefPicMarking.operation[i as usize].maxLongTermFrameIdx =
                            NO_LONG_TERM_FRAME_INDICES;
                    } else {
                        pDecRefPicMarking.operation[i as usize].maxLongTermFrameIdx = value - 1;
                    }
                    num4 += 1;
                }
                if operation == 5 {
                    num5 += 1;
                }
                if operation != 0 && operation <= 3 {
                    num1to3 += 1;
                }
                if operation == 6 {
                    num6 += 1;
                }

                i += 1;
                if operation == 0 {
                    break;
                }
            }

            /* error checking */
            if num4 > 1 || num5 > 1 || num6 > 1 || (num1to3 != 0 && num5 != 0) {
                return HANTRO_NOK;
            }
        }
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function name: h264bsdCheckPpsId

        Functional description:
            Peek value of pic_parameter_set_id from the slice header. Function
            does not modify current stream positions but copies the stream
            data structure to tmp structure which is used while accessing
            stream data.

        Inputs:
            pStrmData       pointer to stream data structure

        Outputs:
            ppsId           value is stored here

        Returns:
            HANTRO_OK       success
            HANTRO_NOK      invalid stream data

------------------------------------------------------------------------------*/

pub fn h264bsdCheckPpsId(pStrmData: &mut strmData_t, ppsId: &mut u32) -> u32 {
    /* Variables */

    let mut tmp: u32;
    let mut value: u32 = 0;

    /* Code */

    /* don't touch original stream position params */
    let mut tmpStrmData = strmDataCopy(pStrmData);

    /* first_mb_in_slice */
    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }

    /* slice_type */
    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }

    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }
    if value >= MAX_NUM_PIC_PARAM_SETS as u32 {
        return HANTRO_NOK;
    }

    *ppsId = value;

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: h264bsdCheckFrameNum

        Functional description:
            Peek value of frame_num from the slice header. Function does not
            modify current stream positions but copies the stream data
            structure to tmp structure which is used while accessing stream
            data.

        Inputs:
            pStrmData       pointer to stream data structure
            maxFrameNum

        Outputs:
            frameNum        value is stored here

        Returns:
            HANTRO_OK       success
            HANTRO_NOK      invalid stream data

------------------------------------------------------------------------------*/

pub fn h264bsdCheckFrameNum(pStrmData: &mut strmData_t, maxFrameNum: u32, frameNum: &mut u32) -> u32 {
    /* Variables */

    let mut tmp: u32;
    let mut value: u32 = 0;
    let mut i: u32;

    /* Code */

    /* don't touch original stream position params */
    let mut tmpStrmData = strmDataCopy(pStrmData);

    /* skip first_mb_in_slice */
    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }

    /* skip slice_type */
    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }

    /* skip pic_parameter_set_id */
    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }

    /* log2(maxFrameNum) -> num bits to represent frame_num */
    i = 0;
    while (maxFrameNum >> i) != 0 {
        i += 1;
    }
    i -= 1;

    /* frame_num */
    tmp = h264bsdGetBits(&mut tmpStrmData, i);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    *frameNum = tmp;

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: h264bsdCheckIdrPicId

        Functional description:
            Peek value of idr_pic_id from the slice header. Function does not
            modify current stream positions but copies the stream data
            structure to tmp structure which is used while accessing stream
            data.

        Inputs:
            pStrmData       pointer to stream data structure
            maxFrameNum     max frame number from active SPS
            nalUnitType     type of the current NAL unit

        Outputs:
            idrPicId        value is stored here

        Returns:
            HANTRO_OK       success
            HANTRO_NOK      invalid stream data

------------------------------------------------------------------------------*/

pub fn h264bsdCheckIdrPicId(
    pStrmData: &mut strmData_t,
    maxFrameNum: u32,
    nalUnitType: nalUnitType_e,
    idrPicId: &mut u32,
) -> u32 {
    /* Variables */

    let mut tmp: u32;
    let mut value: u32 = 0;
    let mut i: u32;

    /* Code */

    /* nalUnitType must be equal to 5 because otherwise idrPicId is not
     * present */
    if nalUnitType != NAL_CODED_SLICE_IDR {
        return HANTRO_NOK;
    }

    /* don't touch original stream position params */
    let mut tmpStrmData = strmDataCopy(pStrmData);

    /* skip first_mb_in_slice */
    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }

    /* skip slice_type */
    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }

    /* skip pic_parameter_set_id */
    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }

    /* log2(maxFrameNum) -> num bits to represent frame_num */
    i = 0;
    while (maxFrameNum >> i) != 0 {
        i += 1;
    }
    i -= 1;

    /* skip frame_num */
    tmp = h264bsdGetBits(&mut tmpStrmData, i);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }

    /* idr_pic_id */
    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, idrPicId);
    if tmp != HANTRO_OK {
        return tmp;
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: h264bsdCheckPicOrderCntLsb

        Functional description:
            Peek value of pic_order_cnt_lsb from the slice header. Function
            does not modify current stream positions but copies the stream
            data structure to tmp structure which is used while accessing
            stream data.

        Inputs:
            pStrmData       pointer to stream data structure
            pSeqParamSet    pointer to active SPS
            nalUnitType     type of the current NAL unit

        Outputs:
            picOrderCntLsb  value is stored here

        Returns:
            HANTRO_OK       success
            HANTRO_NOK      invalid stream data

------------------------------------------------------------------------------*/

pub fn h264bsdCheckPicOrderCntLsb(
    pStrmData: &mut strmData_t,
    pSeqParamSet: &seqParamSet_t,
    nalUnitType: nalUnitType_e,
    picOrderCntLsb: &mut u32,
) -> u32 {
    /* Variables */

    let mut tmp: u32;
    let mut value: u32 = 0;
    let mut i: u32;

    /* Code */

    /* don't touch original stream position params */
    let mut tmpStrmData = strmDataCopy(pStrmData);

    /* skip first_mb_in_slice */
    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }

    /* skip slice_type */
    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }

    /* skip pic_parameter_set_id */
    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }

    /* log2(maxFrameNum) -> num bits to represent frame_num */
    i = 0;
    while (pSeqParamSet.maxFrameNum >> i) != 0 {
        i += 1;
    }
    i -= 1;

    /* skip frame_num */
    tmp = h264bsdGetBits(&mut tmpStrmData, i);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }

    /* skip idr_pic_id when necessary */
    if nalUnitType == NAL_CODED_SLICE_IDR {
        tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
        if tmp != HANTRO_OK {
            return tmp;
        }
    }

    /* log2(maxPicOrderCntLsb) -> num bits to represent pic_order_cnt_lsb */
    i = 0;
    while (pSeqParamSet.maxPicOrderCntLsb >> i) != 0 {
        i += 1;
    }
    i -= 1;

    /* pic_order_cnt_lsb */
    tmp = h264bsdGetBits(&mut tmpStrmData, i);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }
    *picOrderCntLsb = tmp;

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: h264bsdCheckDeltaPicOrderCntBottom

        Functional description:
            Peek value of delta_pic_order_cnt_bottom from the slice header.
            Function does not modify current stream positions but copies the
            stream data structure to tmp structure which is used while
            accessing stream data.

        Inputs:
            pStrmData       pointer to stream data structure
            pSeqParamSet    pointer to active SPS
            nalUnitType     type of the current NAL unit

        Outputs:
            deltaPicOrderCntBottom  value is stored here

        Returns:
            HANTRO_OK       success
            HANTRO_NOK      invalid stream data

------------------------------------------------------------------------------*/

pub fn h264bsdCheckDeltaPicOrderCntBottom(
    pStrmData: &mut strmData_t,
    pSeqParamSet: &seqParamSet_t,
    nalUnitType: nalUnitType_e,
    deltaPicOrderCntBottom: &mut i32,
) -> u32 {
    /* Variables */

    let mut tmp: u32;
    let mut value: u32 = 0;
    let mut i: u32;

    /* Code */

    /* don't touch original stream position params */
    let mut tmpStrmData = strmDataCopy(pStrmData);

    /* skip first_mb_in_slice */
    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }

    /* skip slice_type */
    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }

    /* skip pic_parameter_set_id */
    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }

    /* log2(maxFrameNum) -> num bits to represent frame_num */
    i = 0;
    while (pSeqParamSet.maxFrameNum >> i) != 0 {
        i += 1;
    }
    i -= 1;

    /* skip frame_num */
    tmp = h264bsdGetBits(&mut tmpStrmData, i);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }

    /* skip idr_pic_id when necessary */
    if nalUnitType == NAL_CODED_SLICE_IDR {
        tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
        if tmp != HANTRO_OK {
            return tmp;
        }
    }

    /* log2(maxPicOrderCntLsb) -> num bits to represent pic_order_cnt_lsb */
    i = 0;
    while (pSeqParamSet.maxPicOrderCntLsb >> i) != 0 {
        i += 1;
    }
    i -= 1;

    /* skip pic_order_cnt_lsb */
    tmp = h264bsdGetBits(&mut tmpStrmData, i);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }

    /* delta_pic_order_cnt_bottom */
    tmp = h264bsdDecodeExpGolombSigned(&mut tmpStrmData, deltaPicOrderCntBottom);
    if tmp != HANTRO_OK {
        return tmp;
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: h264bsdCheckDeltaPicOrderCnt

        Functional description:
            Peek values delta_pic_order_cnt[0] and delta_pic_order_cnt[1]
            from the slice header. Function does not modify current stream
            positions but copies the stream data structure to tmp structure
            which is used while accessing stream data.

        Inputs:
            pStrmData               pointer to stream data structure
            pSeqParamSet            pointer to active SPS
            nalUnitType             type of the current NAL unit
            picOrderPresentFlag     flag indicating if delta_pic_order_cnt[1]
                                    is present in the stream

        Outputs:
            deltaPicOrderCnt        values are stored here

        Returns:
            HANTRO_OK               success
            HANTRO_NOK              invalid stream data

------------------------------------------------------------------------------*/

pub unsafe fn h264bsdCheckDeltaPicOrderCnt(
    pStrmData: &mut strmData_t,
    pSeqParamSet: &seqParamSet_t,
    nalUnitType: nalUnitType_e,
    picOrderPresentFlag: u32,
    deltaPicOrderCnt: *mut i32,
) -> u32 {
    /* Variables */

    let mut tmp: u32;
    let mut value: u32 = 0;
    let mut i: u32;

    /* Code */

    /* don't touch original stream position params */
    let mut tmpStrmData = strmDataCopy(pStrmData);

    /* skip first_mb_in_slice */
    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }

    /* skip slice_type */
    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }

    /* skip pic_parameter_set_id */
    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }

    /* log2(maxFrameNum) -> num bits to represent frame_num */
    i = 0;
    while (pSeqParamSet.maxFrameNum >> i) != 0 {
        i += 1;
    }
    i -= 1;

    /* skip frame_num */
    tmp = h264bsdGetBits(&mut tmpStrmData, i);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }

    /* skip idr_pic_id when necessary */
    if nalUnitType == NAL_CODED_SLICE_IDR {
        tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
        if tmp != HANTRO_OK {
            return tmp;
        }
    }

    /* delta_pic_order_cnt[0] */
    tmp = h264bsdDecodeExpGolombSigned(&mut tmpStrmData, &mut *deltaPicOrderCnt.add(0));
    if tmp != HANTRO_OK {
        return tmp;
    }

    /* delta_pic_order_cnt[1] if present */
    if picOrderPresentFlag != 0 {
        tmp = h264bsdDecodeExpGolombSigned(&mut tmpStrmData, &mut *deltaPicOrderCnt.add(1));
        if tmp != HANTRO_OK {
            return tmp;
        }
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: h264bsdCheckRedundantPicCnt

        Functional description:
            Peek value of redundant_pic_cnt from the slice header. Function
            does not modify current stream positions but copies the stream
            data structure to tmp structure which is used while accessing
            stream data.

        Inputs:
            pStrmData       pointer to stream data structure
            pSeqParamSet    pointer to active SPS
            pPicParamSet    pointer to active PPS
            nalUnitType     type of the current NAL unit

        Outputs:
            redundantPicCnt value is stored here

        Returns:
            HANTRO_OK       success
            HANTRO_NOK      invalid stream data

------------------------------------------------------------------------------*/

pub fn h264bsdCheckRedundantPicCnt(
    pStrmData: &mut strmData_t,
    pSeqParamSet: &seqParamSet_t,
    pPicParamSet: &picParamSet_t,
    nalUnitType: nalUnitType_e,
    redundantPicCnt: &mut u32,
) -> u32 {
    /* Variables */

    let mut tmp: u32;
    let mut value: u32 = 0;
    let mut i: u32;
    let mut ivalue: i32 = 0;

    /* Code */

    /* don't touch original stream position params */
    let mut tmpStrmData = strmDataCopy(pStrmData);

    /* skip first_mb_in_slice */
    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }

    /* skip slice_type */
    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }

    /* skip pic_parameter_set_id */
    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }

    /* log2(maxFrameNum) -> num bits to represent frame_num */
    i = 0;
    while (pSeqParamSet.maxFrameNum >> i) != 0 {
        i += 1;
    }
    i -= 1;

    /* skip frame_num */
    tmp = h264bsdGetBits(&mut tmpStrmData, i);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }

    /* skip idr_pic_id when necessary */
    if nalUnitType == NAL_CODED_SLICE_IDR {
        tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
        if tmp != HANTRO_OK {
            return tmp;
        }
    }

    if pSeqParamSet.picOrderCntType == 0 {
        /* log2(maxPicOrderCntLsb) -> num bits to represent pic_order_cnt_lsb */
        i = 0;
        while (pSeqParamSet.maxPicOrderCntLsb >> i) != 0 {
            i += 1;
        }
        i -= 1;

        /* pic_order_cnt_lsb */
        tmp = h264bsdGetBits(&mut tmpStrmData, i);
        if tmp == END_OF_STREAM {
            return HANTRO_NOK;
        }

        if pPicParamSet.picOrderPresentFlag != 0 {
            /* skip delta_pic_order_cnt_bottom */
            tmp = h264bsdDecodeExpGolombSigned(&mut tmpStrmData, &mut ivalue);
            if tmp != HANTRO_OK {
                return tmp;
            }
        }
    }

    if pSeqParamSet.picOrderCntType == 1 && pSeqParamSet.deltaPicOrderAlwaysZeroFlag == 0 {
        /* delta_pic_order_cnt[0] */
        tmp = h264bsdDecodeExpGolombSigned(&mut tmpStrmData, &mut ivalue);
        if tmp != HANTRO_OK {
            return tmp;
        }

        /* delta_pic_order_cnt[1] if present */
        if pPicParamSet.picOrderPresentFlag != 0 {
            tmp = h264bsdDecodeExpGolombSigned(&mut tmpStrmData, &mut ivalue);
            if tmp != HANTRO_OK {
                return tmp;
            }
        }
    }

    /* redundant_pic_cnt */
    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, redundantPicCnt);
    if tmp != HANTRO_OK {
        return tmp;
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: h264bsdCheckPriorPicsFlag

        Functional description:
            Peek value of no_output_of_prior_pics_flag from the slice header.
            Function does not modify current stream positions but copies
            the stream data structure to tmp structure which is used while
            accessing stream data.

        Inputs:
            pStrmData       pointer to stream data structure
            pSeqParamSet    pointer to active SPS
            pPicParamSet    pointer to active PPS
            nalUnitType     type of the current NAL unit

        Outputs:
            noOutputOfPriorPicsFlag value is stored here

        Returns:
            HANTRO_OK       success
            HANTRO_NOK      invalid stream data

------------------------------------------------------------------------------*/

pub fn h264bsdCheckPriorPicsFlag(
    noOutputOfPriorPicsFlag: &mut u32,
    pStrmData: &strmData_t,
    pSeqParamSet: &seqParamSet_t,
    pPicParamSet: &picParamSet_t,
    nalUnitType: nalUnitType_e,
) -> u32 {
    /* Variables */

    let mut tmp: u32;
    let mut value: u32 = 0;
    let mut i: u32;
    let mut ivalue: i32 = 0;
    let _ = nalUnitType; /* lint -e715 in C: nalUnitType not referenced */

    /* Code */

    /* don't touch original stream position params */
    let mut tmpStrmData = strmDataCopy(pStrmData);

    /* skip first_mb_in_slice */
    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }

    /* slice_type */
    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }

    /* skip pic_parameter_set_id */
    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }

    /* log2(maxFrameNum) -> num bits to represent frame_num */
    i = 0;
    while (pSeqParamSet.maxFrameNum >> i) != 0 {
        i += 1;
    }
    i -= 1;

    /* skip frame_num */
    tmp = h264bsdGetBits(&mut tmpStrmData, i);
    if tmp == END_OF_STREAM {
        return HANTRO_NOK;
    }

    /* skip idr_pic_id */
    tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
    if tmp != HANTRO_OK {
        return tmp;
    }

    if pSeqParamSet.picOrderCntType == 0 {
        /* log2(maxPicOrderCntLsb) -> num bits to represent pic_order_cnt_lsb */
        i = 0;
        while (pSeqParamSet.maxPicOrderCntLsb >> i) != 0 {
            i += 1;
        }
        i -= 1;

        /* skip pic_order_cnt_lsb */
        tmp = h264bsdGetBits(&mut tmpStrmData, i);
        if tmp == END_OF_STREAM {
            return HANTRO_NOK;
        }

        if pPicParamSet.picOrderPresentFlag != 0 {
            /* skip delta_pic_order_cnt_bottom */
            tmp = h264bsdDecodeExpGolombSigned(&mut tmpStrmData, &mut ivalue);
            if tmp != HANTRO_OK {
                return tmp;
            }
        }
    }

    if pSeqParamSet.picOrderCntType == 1 && pSeqParamSet.deltaPicOrderAlwaysZeroFlag == 0 {
        /* skip delta_pic_order_cnt[0] */
        tmp = h264bsdDecodeExpGolombSigned(&mut tmpStrmData, &mut ivalue);
        if tmp != HANTRO_OK {
            return tmp;
        }

        /* skip delta_pic_order_cnt[1] if present */
        if pPicParamSet.picOrderPresentFlag != 0 {
            tmp = h264bsdDecodeExpGolombSigned(&mut tmpStrmData, &mut ivalue);
            if tmp != HANTRO_OK {
                return tmp;
            }
        }
    }

    /* skip redundant_pic_cnt */
    if pPicParamSet.redundantPicCntPresentFlag != 0 {
        tmp = h264bsdDecodeExpGolombUnsigned(&mut tmpStrmData, &mut value);
        if tmp != HANTRO_OK {
            return tmp;
        }
    }

    *noOutputOfPriorPicsFlag = h264bsdGetBits(&mut tmpStrmData, 1);
    if *noOutputOfPriorPicsFlag == END_OF_STREAM {
        return HANTRO_NOK;
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: h264bsdDecodePicOrderCnt  (h264bsd_pic_order_cnt.c)

        Functional description:
            Compute picture order count for a picture. Function implements
            computation of all POC types (0, 1 and 2), type is obtained from
            sps. See standard for description of the POC types and how POC is
            computed for each type.

            Function returns the minimum of top field and bottom field pic
            order counts.

        Inputs:
            poc         pointer to previous results
            sps         pointer to sequence parameter set
            pSliceHeader  pointer to current slice header, frame number and
                        other params needed for POC computation
            pNalUnit    pointer to current NAL unit structrue, function needs
                        to know if this is an IDR picture and also if this is
                        a reference picture

        Outputs:
            poc         results stored here for computation of next POC

        Returns:
            picture order count

------------------------------------------------------------------------------*/

pub fn h264bsdDecodePicOrderCnt(
    poc: &mut pocStorage_t,
    sps: &seqParamSet_t,
    pSliceHeader: &sliceHeader_t,
    pNalUnit: &nalUnit_t,
) -> i32 {
    /* Variables */

    let mut i: u32;
    let mut picOrderCnt: i32 = 0;
    let frameNumOffset: u32;
    let mut absFrameNum: u32;
    let mut picOrderCntCycleCnt: u32 = 0;
    let mut frameNumInPicOrderCntCycle: u32 = 0;
    let mut expectedDeltaPicOrderCntCycle: i32;
    let mut containsMmco5: u32;

    /* Code */

    /* (C had an #if 0 block here for step-by-step prevFrameNum increment
     * on frame-num gaps with picOrderCntType 1/2; disabled in C, omitted.) */

    /* check if current slice includes mmco equal to 5 */
    containsMmco5 = HANTRO_FALSE;
    if pSliceHeader.decRefPicMarking.adaptiveRefPicMarkingModeFlag != 0 {
        i = 0;
        while pSliceHeader.decRefPicMarking.operation[i as usize].memoryManagementControlOperation
            != 0
        {
            if pSliceHeader.decRefPicMarking.operation[i as usize]
                .memoryManagementControlOperation
                == 5
            {
                containsMmco5 = HANTRO_TRUE;
                break;
            }
            i += 1;
        }
    }
    match sps.picOrderCntType {
        0 => {
            /* set prevPicOrderCnt values for IDR frame */
            if IS_IDR_NAL_UNIT(pNalUnit) {
                poc.prevPicOrderCntMsb = 0;
                poc.prevPicOrderCntLsb = 0;
            }

            /* compute picOrderCntMsb (stored in picOrderCnt variable) */
            if (pSliceHeader.picOrderCntLsb < poc.prevPicOrderCntLsb)
                && ((poc.prevPicOrderCntLsb - pSliceHeader.picOrderCntLsb)
                    >= sps.maxPicOrderCntLsb / 2)
            {
                picOrderCnt = poc.prevPicOrderCntMsb + sps.maxPicOrderCntLsb as i32;
            } else if (pSliceHeader.picOrderCntLsb > poc.prevPicOrderCntLsb)
                && ((pSliceHeader.picOrderCntLsb - poc.prevPicOrderCntLsb)
                    > sps.maxPicOrderCntLsb / 2)
            {
                picOrderCnt = poc.prevPicOrderCntMsb - sps.maxPicOrderCntLsb as i32;
            } else {
                picOrderCnt = poc.prevPicOrderCntMsb;
            }

            /* standard specifies that prevPicOrderCntMsb is from previous
             * rererence frame -> replace old value only if current frame is
             * rererence frame */
            if pNalUnit.nalRefIdc != 0 {
                poc.prevPicOrderCntMsb = picOrderCnt;
            }

            /* compute top field order cnt (stored in picOrderCnt) */
            picOrderCnt += pSliceHeader.picOrderCntLsb as i32;

            /* if delta for bottom field is negative -> bottom will be the
             * minimum pic order count */
            if pSliceHeader.deltaPicOrderCntBottom < 0 {
                picOrderCnt += pSliceHeader.deltaPicOrderCntBottom;
            }

            /* standard specifies that prevPicOrderCntLsb is from previous
             * rererence frame -> replace old value only if current frame is
             * rererence frame */
            if pNalUnit.nalRefIdc != 0 {
                /* if current frame contains mmco5 -> modify values to be
                 * stored */
                if containsMmco5 != 0 {
                    poc.prevPicOrderCntMsb = 0;
                    /* prevPicOrderCntLsb should be the top field picOrderCnt
                     * if previous frame included mmco5. Top field picOrderCnt
                     * for frames containing mmco5 is obtained by subtracting
                     * the picOrderCnt from original top field order count ->
                     * value is zero if top field was the minimum, i.e. delta
                     * for bottom was positive, otherwise value is
                     * -deltaPicOrderCntBottom */
                    if pSliceHeader.deltaPicOrderCntBottom < 0 {
                        poc.prevPicOrderCntLsb =
                            (-pSliceHeader.deltaPicOrderCntBottom) as u32;
                    } else {
                        poc.prevPicOrderCntLsb = 0;
                    }
                    picOrderCnt = 0;
                } else {
                    poc.prevPicOrderCntLsb = pSliceHeader.picOrderCntLsb;
                }
            }
        }

        1 => {
            /* step 1 (in the description in the standard) */
            if IS_IDR_NAL_UNIT(pNalUnit) {
                frameNumOffset = 0;
            } else if poc.prevFrameNum > pSliceHeader.frameNum {
                frameNumOffset = poc.prevFrameNumOffset + sps.maxFrameNum;
            } else {
                frameNumOffset = poc.prevFrameNumOffset;
            }

            /* step 2 */
            if sps.numRefFramesInPicOrderCntCycle != 0 {
                absFrameNum = frameNumOffset + pSliceHeader.frameNum;
            } else {
                absFrameNum = 0;
            }

            if pNalUnit.nalRefIdc == 0 && absFrameNum > 0 {
                absFrameNum -= 1;
            }

            /* step 3 */
            if absFrameNum > 0 {
                picOrderCntCycleCnt = udiv(absFrameNum - 1, sps.numRefFramesInPicOrderCntCycle);
                frameNumInPicOrderCntCycle =
                    urem(absFrameNum - 1, sps.numRefFramesInPicOrderCntCycle);
            }

            /* step 4 */
            expectedDeltaPicOrderCntCycle = 0;
            i = 0;
            while i < sps.numRefFramesInPicOrderCntCycle {
                expectedDeltaPicOrderCntCycle +=
                    unsafe { *sps.offsetForRefFrame.add(i as usize) };
                i += 1;
            }

            /* step 5 (picOrderCnt used to store expectedPicOrderCnt) */
            if absFrameNum > 0 {
                picOrderCnt = picOrderCntCycleCnt as i32 * expectedDeltaPicOrderCntCycle;
                i = 0;
                while i <= frameNumInPicOrderCntCycle {
                    picOrderCnt += unsafe { *sps.offsetForRefFrame.add(i as usize) };
                    i += 1;
                }
            } else {
                picOrderCnt = 0;
            }

            if pNalUnit.nalRefIdc == 0 {
                picOrderCnt += sps.offsetForNonRefPic;
            }

            /* step 6 (picOrderCnt is top field order cnt if delta for bottom
             * is positive, otherwise it is bottom field order cnt) */
            picOrderCnt += pSliceHeader.deltaPicOrderCnt[0];

            if (sps.offsetForTopToBottomField + pSliceHeader.deltaPicOrderCnt[1]) < 0 {
                picOrderCnt += sps.offsetForTopToBottomField + pSliceHeader.deltaPicOrderCnt[1];
            }

            /* if current picture contains mmco5 -> set prevFrameNumOffset and
             * prevFrameNum to 0 for computation of picOrderCnt of next
             * frame, otherwise store frameNum and frameNumOffset to poc
             * structure */
            if containsMmco5 == 0 {
                poc.prevFrameNumOffset = frameNumOffset;
                poc.prevFrameNum = pSliceHeader.frameNum;
            } else {
                poc.prevFrameNumOffset = 0;
                poc.prevFrameNum = 0;
                picOrderCnt = 0;
            }
        }

        _ => {
            /* case 2 */
            /* derive frameNumOffset */
            if IS_IDR_NAL_UNIT(pNalUnit) {
                frameNumOffset = 0;
            } else if poc.prevFrameNum > pSliceHeader.frameNum {
                frameNumOffset = poc.prevFrameNumOffset + sps.maxFrameNum;
            } else {
                frameNumOffset = poc.prevFrameNumOffset;
            }

            /* derive picOrderCnt (type 2 has same value for top and bottom
             * field order cnts) */
            if IS_IDR_NAL_UNIT(pNalUnit) {
                picOrderCnt = 0;
            } else if pNalUnit.nalRefIdc == 0 {
                picOrderCnt = 2 * (frameNumOffset + pSliceHeader.frameNum) as i32 - 1;
            } else {
                picOrderCnt = 2 * (frameNumOffset + pSliceHeader.frameNum) as i32;
            }

            /* if current picture contains mmco5 -> set prevFrameNumOffset and
             * prevFrameNum to 0 for computation of picOrderCnt of next
             * frame, otherwise store frameNum and frameNumOffset to poc
             * structure */
            if containsMmco5 == 0 {
                poc.prevFrameNumOffset = frameNumOffset;
                poc.prevFrameNum = pSliceHeader.frameNum;
            } else {
                poc.prevFrameNumOffset = 0;
                poc.prevFrameNum = 0;
                picOrderCnt = 0;
            }
        }
    }

    picOrderCnt
}
