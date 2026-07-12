// Mechanical Rust port of h264bsd translation units:
//   - h264bsd_storage.c   (parameter set storage / activation / AU boundary)
//   - h264bsd_conceal.c   (error concealment)
//   - h264bsdMarkSliceCorrupted from h264bsd_slice_data.c (manifest places
//     it in this module)
// Ported per scratchpad PORT_RULES.md (bit-exact, C names verbatim,
// plain-C build: OMXDL/NEON undefined, ASSERT/DEBUG omitted).
//
// Skipped: FLASCC byte-copy branch in h264bsdConceal (non-standard build;
// plain memcpy path ported). No SEI code in these units.

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
use super::h264_dpb::*;
use super::h264_neighbour::*;
use super::h264_parse::*;
use super::h264_reconstruct::*;
use super::h264_slice_header::*;

// ============================================================================
// h264bsd_storage.c
// ============================================================================

/*------------------------------------------------------------------------------
    Function name: h264bsdInitStorage

        Functional description:
            Initialize storage structure. Sets contents of the storage to '0'
            except for the active parameter set ids, which are initialized
            to invalid values.
------------------------------------------------------------------------------*/
pub fn h264bsdInitStorage(pStorage: &mut storage_t) {
    // PORT NOTE: the C memsets the whole storage_t. The Rust storage_t
    // carries port-added Allocator hooks (fn pointers) in `allocator` and
    // `dpb[0].allocator`, set by h264bsdInit BEFORE this call; save and
    // restore them across the zeroing.
    let alloc = pStorage.allocator;
    let dpbAlloc = pStorage.dpb[0].allocator;

    unsafe {
        let p = pStorage as *mut storage_t;
        core::ptr::write_bytes(p as *mut u8, 0, core::mem::size_of::<storage_t>());
        (*p).allocator = alloc;
        (*p).dpb[0].allocator = dpbAlloc;
    }

    pStorage.activeSpsId = MAX_NUM_SEQ_PARAM_SETS as u32;
    pStorage.activePpsId = MAX_NUM_PIC_PARAM_SETS as u32;

    pStorage.aub[0].firstCallFlag = HANTRO_TRUE;
}

/*------------------------------------------------------------------------------
    Function: h264bsdStoreSeqParamSet

        Functional description:
            Store sequence parameter set into the storage. If active SPS is
            overwritten -> check if contents changes and if it does, set
            parameters to force reactivation of parameter sets

        Returns:
            HANTRO_OK                success
            MEMORY_ALLOCATION_ERROR  failure in memory allocation
------------------------------------------------------------------------------*/
pub unsafe fn h264bsdStoreSeqParamSet(
    pStorage: &mut storage_t,
    pSeqParamSet: &mut seqParamSet_t,
) -> u32 {
    let id: u32 = pSeqParamSet.seqParameterSetId;
    let alloc = pStorage.allocator;

    /* seq parameter set with id not used before -> allocate memory */
    if pStorage.sps[id as usize].is_null() {
        pStorage.sps[id as usize] = alloc.alloc_n::<seqParamSet_t>(1);
        if pStorage.sps[id as usize].is_null() {
            return MEMORY_ALLOCATION_ERROR;
        }
    }
    /* sequence parameter set with id equal to id of active sps */
    else if id == pStorage.activeSpsId {
        /* if seq parameter set contents changes
         *    -> overwrite and re-activate when next IDR picture decoded
         *    ids of active param sets set to invalid values to force
         *    re-activation. Memories allocated for old sps freed
         * otherwise free memories allocated for just decoded sps and
         * continue */
        if h264bsdCompareSeqParamSets(pSeqParamSet, &*pStorage.activeSps) != 0 {
            alloc.free_ptr((*pStorage.sps[id as usize]).offsetForRefFrame);
            (*pStorage.sps[id as usize]).offsetForRefFrame = core::ptr::null_mut();
            alloc.free_ptr((*pStorage.sps[id as usize]).vuiParameters);
            (*pStorage.sps[id as usize]).vuiParameters = core::ptr::null_mut();
            pStorage.activeSpsId = MAX_NUM_SEQ_PARAM_SETS as u32 + 1;
            pStorage.activePpsId = MAX_NUM_PIC_PARAM_SETS as u32 + 1;
            pStorage.activeSps = core::ptr::null_mut();
            pStorage.activePps = core::ptr::null_mut();
        } else {
            alloc.free_ptr(pSeqParamSet.offsetForRefFrame);
            pSeqParamSet.offsetForRefFrame = core::ptr::null_mut();
            alloc.free_ptr(pSeqParamSet.vuiParameters);
            pSeqParamSet.vuiParameters = core::ptr::null_mut();
            return HANTRO_OK;
        }
    }
    /* overwrite seq param set other than active one -> free memories
     * allocated for old param set */
    else {
        alloc.free_ptr((*pStorage.sps[id as usize]).offsetForRefFrame);
        (*pStorage.sps[id as usize]).offsetForRefFrame = core::ptr::null_mut();
        alloc.free_ptr((*pStorage.sps[id as usize]).vuiParameters);
        (*pStorage.sps[id as usize]).vuiParameters = core::ptr::null_mut();
    }

    *pStorage.sps[id as usize] = *pSeqParamSet;

    HANTRO_OK
}

/*------------------------------------------------------------------------------
    Function: h264bsdStorePicParamSet

        Functional description:
            Store picture parameter set into the storage. If active PPS is
            overwritten -> check if active SPS changes and if it does -> set
            parameters to force reactivation of parameter sets

        Returns:
            HANTRO_OK                success
            MEMORY_ALLOCATION_ERROR  failure in memory allocation
------------------------------------------------------------------------------*/
pub unsafe fn h264bsdStorePicParamSet(
    pStorage: &mut storage_t,
    pPicParamSet: &mut picParamSet_t,
) -> u32 {
    let id: u32 = pPicParamSet.picParameterSetId;
    let alloc = pStorage.allocator;

    /* pic parameter set with id not used before -> allocate memory */
    if pStorage.pps[id as usize].is_null() {
        pStorage.pps[id as usize] = alloc.alloc_n::<picParamSet_t>(1);
        if pStorage.pps[id as usize].is_null() {
            return MEMORY_ALLOCATION_ERROR;
        }
    }
    /* picture parameter set with id equal to id of active pps */
    else if id == pStorage.activePpsId {
        /* check whether seq param set changes, force re-activation of
         * param set if it does. Set activeSpsId to invalid value to
         * accomplish this */
        if pPicParamSet.seqParameterSetId != pStorage.activeSpsId {
            pStorage.activePpsId = MAX_NUM_PIC_PARAM_SETS as u32 + 1;
        }
        /* free memories allocated for old param set */
        alloc.free_ptr((*pStorage.pps[id as usize]).runLength);
        (*pStorage.pps[id as usize]).runLength = core::ptr::null_mut();
        alloc.free_ptr((*pStorage.pps[id as usize]).topLeft);
        (*pStorage.pps[id as usize]).topLeft = core::ptr::null_mut();
        alloc.free_ptr((*pStorage.pps[id as usize]).bottomRight);
        (*pStorage.pps[id as usize]).bottomRight = core::ptr::null_mut();
        alloc.free_ptr((*pStorage.pps[id as usize]).sliceGroupId);
        (*pStorage.pps[id as usize]).sliceGroupId = core::ptr::null_mut();
    }
    /* overwrite pic param set other than active one -> free memories
     * allocated for old param set */
    else {
        alloc.free_ptr((*pStorage.pps[id as usize]).runLength);
        (*pStorage.pps[id as usize]).runLength = core::ptr::null_mut();
        alloc.free_ptr((*pStorage.pps[id as usize]).topLeft);
        (*pStorage.pps[id as usize]).topLeft = core::ptr::null_mut();
        alloc.free_ptr((*pStorage.pps[id as usize]).bottomRight);
        (*pStorage.pps[id as usize]).bottomRight = core::ptr::null_mut();
        alloc.free_ptr((*pStorage.pps[id as usize]).sliceGroupId);
        (*pStorage.pps[id as usize]).sliceGroupId = core::ptr::null_mut();
    }

    *pStorage.pps[id as usize] = *pPicParamSet;

    HANTRO_OK
}

/*------------------------------------------------------------------------------
    Function: h264bsdActivateParamSets

        Functional description:
            Activate certain SPS/PPS combination. This function shall be
            called in the beginning of each picture. Picture parameter set
            can be changed as wanted, but sequence parameter set may only be
            changed when the starting picture is an IDR picture.

            When new SPS is activated the function allocates memory for
            macroblock storages and slice group map and (re-)initializes the
            decoded picture buffer. If this is not the first activation the old
            allocations are freed and FreeDpb called before new allocations.

        Returns:
            HANTRO_OK       success
            HANTRO_NOK      non-existing or invalid param set combination,
                            trying to change SPS with non-IDR picture
            MEMORY_ALLOCATION_ERROR     failure in memory allocation
------------------------------------------------------------------------------*/
pub unsafe fn h264bsdActivateParamSets(pStorage: &mut storage_t, ppsId: u32, isIdr: u32) -> u32 {
    let mut tmp: u32;
    let mut flag: u32;

    /* check that pps and corresponding sps exist */
    if pStorage.pps[ppsId as usize].is_null()
        || pStorage.sps[(*pStorage.pps[ppsId as usize]).seqParameterSetId as usize].is_null()
    {
        return HANTRO_NOK;
    }

    /* check that pps parameters do not violate picture size constraints */
    tmp = CheckPps(
        &mut *pStorage.pps[ppsId as usize],
        &mut *pStorage.sps[(*pStorage.pps[ppsId as usize]).seqParameterSetId as usize],
    );
    if tmp != HANTRO_OK {
        return tmp;
    }

    /* first activation part1 */
    if pStorage.activePpsId == MAX_NUM_PIC_PARAM_SETS as u32 {
        pStorage.activePpsId = ppsId;
        pStorage.activePps = pStorage.pps[ppsId as usize];
        pStorage.activeSpsId = (*pStorage.activePps).seqParameterSetId;
        pStorage.activeSps = pStorage.sps[pStorage.activeSpsId as usize];
        pStorage.picSizeInMbs =
            (*pStorage.activeSps).picWidthInMbs * (*pStorage.activeSps).picHeightInMbs;

        pStorage.currImage[0].width = (*pStorage.activeSps).picWidthInMbs;
        pStorage.currImage[0].height = (*pStorage.activeSps).picHeightInMbs;

        pStorage.pendingActivation = HANTRO_TRUE;
    }
    /* first activation part2 */
    else if pStorage.pendingActivation != 0 {
        pStorage.pendingActivation = HANTRO_FALSE;

        let alloc = pStorage.allocator;
        alloc.free_ptr(pStorage.mb);
        pStorage.mb = core::ptr::null_mut();
        alloc.free_ptr(pStorage.sliceGroupMap);
        pStorage.sliceGroupMap = core::ptr::null_mut();

        pStorage.mb = alloc.alloc_n::<mbStorage_t>(pStorage.picSizeInMbs as usize);
        pStorage.sliceGroupMap = alloc.alloc_n::<u32>(pStorage.picSizeInMbs as usize);
        if pStorage.mb.is_null() || pStorage.sliceGroupMap.is_null() {
            return MEMORY_ALLOCATION_ERROR;
        }

        core::ptr::write_bytes(
            pStorage.mb as *mut u8,
            0,
            pStorage.picSizeInMbs as usize * core::mem::size_of::<mbStorage_t>(),
        );

        h264bsdInitMbNeighbours(
            pStorage.mb,
            (*pStorage.activeSps).picWidthInMbs,
            pStorage.picSizeInMbs,
        );

        /* dpb output reordering disabled if
         * 1) application set noReordering flag
         * 2) POC type equal to 2
         * 3) num_reorder_frames in vui equal to 0 */
        if pStorage.noReordering != 0
            || (*pStorage.activeSps).picOrderCntType == 2
            || ((*pStorage.activeSps).vuiParametersPresentFlag != 0
                && (*(*pStorage.activeSps).vuiParameters).bitstreamRestrictionFlag != 0
                && (*(*pStorage.activeSps).vuiParameters).numReorderFrames == 0)
        {
            flag = HANTRO_TRUE;
        } else {
            flag = HANTRO_FALSE;
        }

        tmp = h264bsdResetDpb(
            &mut pStorage.dpb[0],
            (*pStorage.activeSps).picWidthInMbs * (*pStorage.activeSps).picHeightInMbs,
            (*pStorage.activeSps).maxDpbSize,
            (*pStorage.activeSps).numRefFrames,
            (*pStorage.activeSps).maxFrameNum,
            flag,
        );
        if tmp != HANTRO_OK {
            return tmp;
        }
    } else if ppsId != pStorage.activePpsId {
        /* sequence parameter set shall not change but before an IDR picture */
        if (*pStorage.pps[ppsId as usize]).seqParameterSetId != pStorage.activeSpsId {
            if isIdr != 0 {
                pStorage.activePpsId = ppsId;
                pStorage.activePps = pStorage.pps[ppsId as usize];
                pStorage.activeSpsId = (*pStorage.activePps).seqParameterSetId;
                pStorage.activeSps = pStorage.sps[pStorage.activeSpsId as usize];
                pStorage.picSizeInMbs =
                    (*pStorage.activeSps).picWidthInMbs * (*pStorage.activeSps).picHeightInMbs;

                pStorage.currImage[0].width = (*pStorage.activeSps).picWidthInMbs;
                pStorage.currImage[0].height = (*pStorage.activeSps).picHeightInMbs;

                pStorage.pendingActivation = HANTRO_TRUE;
            } else {
                return HANTRO_NOK;
            }
        } else {
            pStorage.activePpsId = ppsId;
            pStorage.activePps = pStorage.pps[ppsId as usize];
        }
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------
    Function: h264bsdResetStorage

        Functional description:
            Reset contents of the storage. This should be called before
            processing of new image is started.
------------------------------------------------------------------------------*/
pub unsafe fn h264bsdResetStorage(pStorage: &mut storage_t) {
    let mut i: u32;

    pStorage.slice[0].numDecodedMbs = 0;
    pStorage.slice[0].sliceId = 0;

    i = 0;
    while i < pStorage.picSizeInMbs {
        (*pStorage.mb.add(i as usize)).sliceId = 0;
        (*pStorage.mb.add(i as usize)).decoded = 0;
        i += 1;
    }
}

/*------------------------------------------------------------------------------
    Function: h264bsdIsStartOfPicture

        Functional description:
            Determine if the decoder is in the start of a picture. This
            information is needed to decide if h264bsdActivateParamSets and
            h264bsdCheckGapsInFrameNum functions should be called. Function
            considers that new picture is starting if no slice headers
            have been successfully decoded for the current access unit.

        Returns:
            HANTRO_TRUE        new picture is starting
            HANTRO_FALSE       not starting
------------------------------------------------------------------------------*/
pub unsafe fn h264bsdIsStartOfPicture(pStorage: &mut storage_t) -> u32 {
    if pStorage.validSliceInAccessUnit == HANTRO_FALSE {
        HANTRO_TRUE
    } else {
        HANTRO_FALSE
    }
}

/*------------------------------------------------------------------------------
    Function: h264bsdIsEndOfPicture

        Functional description:
            Determine if the decoder is in the end of a picture. This
            information is needed to determine when deblocking filtering
            and reference picture marking processes should be performed.

            If the decoder is processing primary slices the return value
            is determined by checking the value of numDecodedMbs in the
            storage. On the other hand, if the decoder is processing
            redundant slices the numDecodedMbs may not contain valid
            information and each macroblock has to be checked separately.

        Returns:
            HANTRO_TRUE        end of picture
            HANTRO_FALSE       not
------------------------------------------------------------------------------*/
pub unsafe fn h264bsdIsEndOfPicture(pStorage: &mut storage_t) -> u32 {
    let mut i: u32;
    let mut tmp: u32;

    /* primary picture */
    if pStorage.sliceHeader[0].redundantPicCnt == 0 {
        if pStorage.slice[0].numDecodedMbs == pStorage.picSizeInMbs {
            return HANTRO_TRUE;
        }
    } else {
        i = 0;
        tmp = 0;
        while i < pStorage.picSizeInMbs {
            tmp += if (*pStorage.mb.add(i as usize)).decoded != 0 { 1 } else { 0 };
            i += 1;
        }

        if tmp == pStorage.picSizeInMbs {
            return HANTRO_TRUE;
        }
    }

    HANTRO_FALSE
}

/*------------------------------------------------------------------------------
    Function: h264bsdComputeSliceGroupMap

        Functional description:
            Compute slice group map. Just call h264bsdDecodeSliceGroupMap with
            appropriate parameters.
------------------------------------------------------------------------------*/
pub unsafe fn h264bsdComputeSliceGroupMap(pStorage: &mut storage_t, sliceGroupChangeCycle: u32) {
    h264bsdDecodeSliceGroupMap(
        pStorage.sliceGroupMap,
        &*pStorage.activePps,
        sliceGroupChangeCycle,
        (*pStorage.activeSps).picWidthInMbs,
        (*pStorage.activeSps).picHeightInMbs,
    );
}

/*------------------------------------------------------------------------------
    Function: h264bsdCheckAccessUnitBoundary

        Functional description:
            Check if next NAL unit starts a new access unit. Following
            conditions specify start of a new access unit:

                -NAL unit types 6-11, 13-18 (e.g. SPS, PPS)

           following conditions checked only for slice NAL units, values
           compared to ones obtained from previous slice:

                -NAL unit type differs (slice / IDR slice)
                -frame_num differs
                -nal_ref_idc differs and one of the values is 0
                -POC information differs
                -both are IDR slices and idr_pic_id differs

        Outputs:
            accessUnitBoundaryFlag  the result is stored here, TRUE for
                                    access unit boundary, FALSE otherwise

        Returns:
            HANTRO_OK           success
            HANTRO_NOK          failure, invalid stream data
            PARAM_SET_ERROR     invalid param set usage
------------------------------------------------------------------------------*/
pub unsafe fn h264bsdCheckAccessUnitBoundary(
    strm: &mut strmData_t,
    nuNext: &nalUnit_t,
    storage: &mut storage_t,
    accessUnitBoundaryFlag: &mut u32,
) -> u32 {
    let mut tmp: u32;
    let mut ppsId: u32 = 0;
    let mut frameNum: u32 = 0;
    let mut idrPicId: u32 = 0;
    let mut picOrderCntLsb: u32 = 0;
    let mut deltaPicOrderCntBottom: i32 = 0;
    let mut deltaPicOrderCnt: [i32; 2] = [0; 2];
    let sps: *mut seqParamSet_t;
    let pps: *mut picParamSet_t;

    /* initialize default output to FALSE */
    *accessUnitBoundaryFlag = HANTRO_FALSE;

    if (nuNext.nalUnitType > 5 && nuNext.nalUnitType < 12)
        || (nuNext.nalUnitType > 12 && nuNext.nalUnitType <= 18)
    {
        *accessUnitBoundaryFlag = HANTRO_TRUE;
        return HANTRO_OK;
    } else if nuNext.nalUnitType != NAL_CODED_SLICE && nuNext.nalUnitType != NAL_CODED_SLICE_IDR {
        return HANTRO_OK;
    }

    /* check if this is the very first call to this function */
    if storage.aub[0].firstCallFlag != 0 {
        *accessUnitBoundaryFlag = HANTRO_TRUE;
        storage.aub[0].firstCallFlag = HANTRO_FALSE;
    }

    /* get picture parameter set id */
    tmp = h264bsdCheckPpsId(strm, &mut ppsId);
    if tmp != HANTRO_OK {
        return tmp;
    }

    /* store sps and pps in separate pointers just to make names shorter */
    pps = storage.pps[ppsId as usize];
    if pps.is_null()
        || storage.sps[(*pps).seqParameterSetId as usize].is_null()
        || (storage.activeSpsId != MAX_NUM_SEQ_PARAM_SETS as u32
            && (*pps).seqParameterSetId != storage.activeSpsId
            && nuNext.nalUnitType != NAL_CODED_SLICE_IDR)
    {
        return PARAM_SET_ERROR;
    }
    sps = storage.sps[(*pps).seqParameterSetId as usize];

    if storage.aub[0].nuPrev[0].nalRefIdc != nuNext.nalRefIdc
        && (storage.aub[0].nuPrev[0].nalRefIdc == 0 || nuNext.nalRefIdc == 0)
    {
        *accessUnitBoundaryFlag = HANTRO_TRUE;
    }

    if (storage.aub[0].nuPrev[0].nalUnitType == NAL_CODED_SLICE_IDR
        && nuNext.nalUnitType != NAL_CODED_SLICE_IDR)
        || (storage.aub[0].nuPrev[0].nalUnitType != NAL_CODED_SLICE_IDR
            && nuNext.nalUnitType == NAL_CODED_SLICE_IDR)
    {
        *accessUnitBoundaryFlag = HANTRO_TRUE;
    }

    tmp = h264bsdCheckFrameNum(strm, (*sps).maxFrameNum, &mut frameNum);
    if tmp != HANTRO_OK {
        return HANTRO_NOK;
    }

    if storage.aub[0].prevFrameNum != frameNum {
        storage.aub[0].prevFrameNum = frameNum;
        *accessUnitBoundaryFlag = HANTRO_TRUE;
    }

    if nuNext.nalUnitType == NAL_CODED_SLICE_IDR {
        tmp = h264bsdCheckIdrPicId(strm, (*sps).maxFrameNum, nuNext.nalUnitType, &mut idrPicId);
        if tmp != HANTRO_OK {
            return HANTRO_NOK;
        }

        if storage.aub[0].nuPrev[0].nalUnitType == NAL_CODED_SLICE_IDR
            && storage.aub[0].prevIdrPicId != idrPicId
        {
            *accessUnitBoundaryFlag = HANTRO_TRUE;
        }

        storage.aub[0].prevIdrPicId = idrPicId;
    }

    if (*sps).picOrderCntType == 0 {
        tmp = h264bsdCheckPicOrderCntLsb(strm, &*sps, nuNext.nalUnitType, &mut picOrderCntLsb);
        if tmp != HANTRO_OK {
            return HANTRO_NOK;
        }

        if storage.aub[0].prevPicOrderCntLsb != picOrderCntLsb {
            storage.aub[0].prevPicOrderCntLsb = picOrderCntLsb;
            *accessUnitBoundaryFlag = HANTRO_TRUE;
        }

        if (*pps).picOrderPresentFlag != 0 {
            tmp = h264bsdCheckDeltaPicOrderCntBottom(
                strm,
                &*sps,
                nuNext.nalUnitType,
                &mut deltaPicOrderCntBottom,
            );
            if tmp != HANTRO_OK {
                return tmp;
            }

            if storage.aub[0].prevDeltaPicOrderCntBottom != deltaPicOrderCntBottom {
                storage.aub[0].prevDeltaPicOrderCntBottom = deltaPicOrderCntBottom;
                *accessUnitBoundaryFlag = HANTRO_TRUE;
            }
        }
    } else if (*sps).picOrderCntType == 1 && (*sps).deltaPicOrderAlwaysZeroFlag == 0 {
        tmp = h264bsdCheckDeltaPicOrderCnt(
            strm,
            &*sps,
            nuNext.nalUnitType,
            (*pps).picOrderPresentFlag,
            deltaPicOrderCnt.as_mut_ptr(),
        );
        if tmp != HANTRO_OK {
            return tmp;
        }

        if storage.aub[0].prevDeltaPicOrderCnt[0] != deltaPicOrderCnt[0] {
            storage.aub[0].prevDeltaPicOrderCnt[0] = deltaPicOrderCnt[0];
            *accessUnitBoundaryFlag = HANTRO_TRUE;
        }

        if (*pps).picOrderPresentFlag != 0 {
            if storage.aub[0].prevDeltaPicOrderCnt[1] != deltaPicOrderCnt[1] {
                storage.aub[0].prevDeltaPicOrderCnt[1] = deltaPicOrderCnt[1];
                *accessUnitBoundaryFlag = HANTRO_TRUE;
            }
        }
    }

    storage.aub[0].nuPrev[0] = *nuNext;

    HANTRO_OK
}

/*------------------------------------------------------------------------------
    Function: CheckPps

        Functional description:
            Check picture parameter set. Contents of the picture parameter
            set information that depends on the image dimensions is checked
            against the dimensions in the sps.

        Returns:
            HANTRO_OK      everything ok
            HANTRO_NOK     invalid data in picture parameter set
------------------------------------------------------------------------------*/
unsafe fn CheckPps(pps: &mut picParamSet_t, sps: &mut seqParamSet_t) -> u32 {
    let mut i: u32;
    let picSize: u32;

    picSize = sps.picWidthInMbs * sps.picHeightInMbs;

    /* check slice group params */
    if pps.numSliceGroups > 1 {
        if pps.sliceGroupMapType == 0 {
            i = 0;
            while i < pps.numSliceGroups {
                if *pps.runLength.add(i as usize) > picSize {
                    return HANTRO_NOK;
                }
                i += 1;
            }
        } else if pps.sliceGroupMapType == 2 {
            i = 0;
            while i < pps.numSliceGroups - 1 {
                if *pps.topLeft.add(i as usize) > *pps.bottomRight.add(i as usize)
                    || *pps.bottomRight.add(i as usize) >= picSize
                {
                    return HANTRO_NOK;
                }

                if urem(*pps.topLeft.add(i as usize), sps.picWidthInMbs)
                    > urem(*pps.bottomRight.add(i as usize), sps.picWidthInMbs)
                {
                    return HANTRO_NOK;
                }
                i += 1;
            }
        } else if pps.sliceGroupMapType > 2 && pps.sliceGroupMapType < 6 {
            if pps.sliceGroupChangeRate > picSize {
                return HANTRO_NOK;
            }
        } else if pps.sliceGroupMapType == 6 && pps.picSizeInMapUnits < picSize {
            return HANTRO_NOK;
        }
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------
    Function: h264bsdValidParamSets

        Functional description:
            Check if any valid SPS/PPS combination exists in the storage.
            Function tries each PPS in the buffer and checks if corresponding
            SPS exists and calls CheckPps to determine if the PPS conforms
            to image dimensions of the SPS.

        Returns:
            HANTRO_OK   there is at least one valid combination
            HANTRO_NOK  no valid combinations found
------------------------------------------------------------------------------*/
pub unsafe fn h264bsdValidParamSets(pStorage: &mut storage_t) -> u32 {
    let mut i: u32;

    i = 0;
    while i < MAX_NUM_PIC_PARAM_SETS as u32 {
        if !pStorage.pps[i as usize].is_null()
            && !pStorage.sps[(*pStorage.pps[i as usize]).seqParameterSetId as usize].is_null()
            && CheckPps(
                &mut *pStorage.pps[i as usize],
                &mut *pStorage.sps[(*pStorage.pps[i as usize]).seqParameterSetId as usize],
            ) == HANTRO_OK
        {
            return HANTRO_OK;
        }
        i += 1;
    }

    HANTRO_NOK
}

// ============================================================================
// h264bsdMarkSliceCorrupted (from h264bsd_slice_data.c)
// ============================================================================

/*------------------------------------------------------------------------------
    Function name: h264bsdMarkSliceCorrupted

        Functional description:
            Mark macroblocks of the slice corrupted. If lastMbAddr in the slice
            storage is set -> picWidthInMbs (or at least 10) macroblocks back
            from the lastMbAddr are marked corrupted. However, if lastMbAddr
            is not set -> all macroblocks of the slice are marked.
------------------------------------------------------------------------------*/
pub unsafe fn h264bsdMarkSliceCorrupted(pStorage: &mut storage_t, firstMbInSlice: u32) {
    let mut tmp: u32;
    let mut i: u32;
    let sliceId: u32;
    let mut currMbAddr: u32;

    currMbAddr = firstMbInSlice;

    sliceId = pStorage.slice[0].sliceId;

    /* DecodeSliceData sets lastMbAddr for I slices -> if it was set, go back
     * MAX(picWidthInMbs, 10) macroblocks and start marking from there */
    if pStorage.slice[0].lastMbAddr != 0 {
        i = pStorage.slice[0].lastMbAddr - 1;
        tmp = 0;
        while i > currMbAddr {
            if (*pStorage.mb.add(i as usize)).sliceId == sliceId {
                tmp += 1;
                if tmp >= MAX!((*pStorage.activeSps).picWidthInMbs, 10) {
                    break;
                }
            }
            i -= 1;
        }
        currMbAddr = i;
    }

    loop {
        if (*pStorage.mb.add(currMbAddr as usize)).sliceId == sliceId
            && (*pStorage.mb.add(currMbAddr as usize)).decoded != 0
        {
            (*pStorage.mb.add(currMbAddr as usize)).decoded -= 1;
        } else {
            break;
        }

        currMbAddr =
            h264bsdNextMbAddress(pStorage.sliceGroupMap, pStorage.picSizeInMbs, currMbAddr);

        if currMbAddr == 0 {
            break;
        }
    }
}

// ============================================================================
// h264bsd_conceal.c
// ============================================================================

/*------------------------------------------------------------------------------
    Function name: h264bsdConceal

        Functional description:
            Perform error concealment for a picture. Two types of concealment
            is performed based on sliceType:
                1) copy from previous picture for P-slices.
                2) concealment from neighbour pixels for I-slices

            I-type concealment determines frequency domain coefficients
            from the neighbour pixels, applies integer transform (the same
            transform used in the residual processing) and uses the results
            as pixel values for concealed macroblocks. Transform produces
            4x4 array and one pixel value is used for 4x4 luma blocks and
            2x2 chroma blocks.

            The error concealment is started by searching the first properly
            decoded macroblock and concealing the row containing it, then
            all rows above, finally rows below.

            If all macroblocks of the picture are lost, the concealment is
            copy of previous picture for P-type and setting the image to
            constant gray (pixel value 128) for I-type.

            Concealment sets quantization parameter of the concealed
            macroblocks to value 40 and macroblock type to intra to enable
            deblocking filter to smooth the edges of the concealed areas.

        Returns:
            HANTRO_OK
------------------------------------------------------------------------------*/
pub unsafe fn h264bsdConceal(
    pStorage: &mut storage_t,
    currImage: &mut image_t,
    sliceType: u32,
) -> u32 {
    let mut i: u32;
    let mut j: u32;
    let mut row: u32;
    let mut col: u32;
    let width: u32;
    let height: u32;
    let mut refData: *mut u8;
    let mut mb: *mut mbStorage_t;

    width = currImage.width;
    height = currImage.height;
    refData = core::ptr::null_mut();
    /* use reference picture with smallest available index */
    if IS_P_SLICE(sliceType) || pStorage.intraConcealmentFlag != 0 {
        i = 0;
        loop {
            refData = h264bsdGetRefPicData(&pStorage.dpb[0], i);
            i += 1;
            if i >= 16 {
                break;
            }
            if !refData.is_null() {
                break;
            }
        }
    }

    i = 0;
    row = 0;
    col = 0;
    /* find first properly decoded macroblock -> start point for concealment */
    while i < pStorage.picSizeInMbs && (*pStorage.mb.add(i as usize)).decoded == 0 {
        i += 1;
        col += 1;
        if col == width {
            row += 1;
            col = 0;
        }
    }

    /* whole picture lost -> copy previous or set grey */
    if i == pStorage.picSizeInMbs {
        if (IS_I_SLICE(sliceType) && pStorage.intraConcealmentFlag == 0) || refData.is_null() {
            core::ptr::write_bytes(currImage.data, 128, (width * height * 384) as usize);
        } else {
            core::ptr::copy_nonoverlapping(
                refData as *const u8,
                currImage.data,
                (width * height * 384) as usize,
            );
        }

        pStorage.numConcealedMbs = pStorage.picSizeInMbs;

        /* no filtering if whole picture concealed */
        i = 0;
        while i < pStorage.picSizeInMbs {
            (*pStorage.mb.add(i as usize)).disableDeblockingFilterIdc = 1;
            i += 1;
        }

        return HANTRO_OK;
    }

    /* start from the row containing the first correct macroblock, conceal the
     * row in question, all rows above that row and then continue downwards */
    mb = pStorage.mb.add((row * width) as usize);
    /* C: for (j = col; j--;) */
    j = col;
    while j != 0 {
        j -= 1;
        ConcealMb(mb.add(j as usize), currImage, row, j, sliceType, refData);
        (*mb.add(j as usize)).decoded = 1;
        pStorage.numConcealedMbs += 1;
    }
    j = col + 1;
    while j < width {
        if (*mb.add(j as usize)).decoded == 0 {
            ConcealMb(mb.add(j as usize), currImage, row, j, sliceType, refData);
            (*mb.add(j as usize)).decoded = 1;
            pStorage.numConcealedMbs += 1;
        }
        j += 1;
    }
    /* if previous row(s) could not be concealed -> conceal them now */
    if row != 0 {
        j = 0;
        while j < width {
            i = row - 1;
            mb = pStorage.mb.add((i * width + j) as usize);
            /* C: do { ... mb -= width; } while (i--); */
            loop {
                ConcealMb(mb, currImage, i, j, sliceType, refData);
                (*mb).decoded = 1;
                pStorage.numConcealedMbs += 1;
                mb = mb.wrapping_sub(width as usize);
                if i == 0 {
                    break;
                }
                i -= 1;
            }
            j += 1;
        }
    }

    /* process rows below the one containing the first correct macroblock */
    i = row + 1;
    while i < height {
        mb = pStorage.mb.add((i * width) as usize);

        j = 0;
        while j < width {
            if (*mb.add(j as usize)).decoded == 0 {
                ConcealMb(mb.add(j as usize), currImage, i, j, sliceType, refData);
                (*mb.add(j as usize)).decoded = 1;
                pStorage.numConcealedMbs += 1;
            }
            j += 1;
        }
        i += 1;
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------
    Function name: ConcealMb

        Functional description:
            Perform error concealment for one macroblock, location of the
            macroblock in the picture indicated by row and col
------------------------------------------------------------------------------*/
unsafe fn ConcealMb(
    pMb: *mut mbStorage_t,
    currImage: &mut image_t,
    row: u32,
    col: u32,
    sliceType: u32,
    refData: *mut u8,
) -> u32 {
    let mut i: u32;
    let mut j: u32;
    let mut comp: u32;
    let mut hor: u32;
    let mut ver: u32;
    let mbNum: u32;
    let width: u32;
    let height: u32;
    let mut mbPos: *mut u8;
    let mut data: [u8; 384] = [0; 384];
    let mut pData: *mut u8;
    let mut tmp: i32;
    let mut firstPhase: [i32; 16] = [0; 16];
    let mut pTmp: *const i32;
    /* neighbours above, below, left and right */
    let mut a: [i32; 4] = [0, 0, 0, 0];
    let mut b: [i32; 4] = [0; 4];
    let mut l: [i32; 4] = [0, 0, 0, 0];
    let mut r: [i32; 4] = [0; 4];
    let mut A: u32;
    let mut B: u32;
    let mut L: u32;
    let mut R: u32;

    width = currImage.width;
    height = currImage.height;
    mbNum = row * width + col;

    h264bsdSetCurrImageMbPointers(currImage, mbNum);

    mbPos = currImage.data.add((row * 16 * width * 16 + col * 16) as usize);
    A = HANTRO_FALSE;
    B = HANTRO_FALSE;
    L = HANTRO_FALSE;
    R = HANTRO_FALSE;

    /* set qpY to 40 to enable some filtering in deblocking (stetson value) */
    (*pMb).qpY = 40;
    (*pMb).disableDeblockingFilterIdc = 0;
    /* mbType set to intra to perform filtering despite the values of other
     * boundary strength determination fields */
    (*pMb).mbType = I_4x4;
    (*pMb).filterOffsetA = 0;
    (*pMb).filterOffsetB = 0;
    (*pMb).chromaQpIndexOffset = 0;

    if IS_I_SLICE(sliceType) {
        data.fill(0);
    } else {
        let mv = mv_t { hor: 0, ver: 0 };
        let refImage = image_t {
            data: refData,
            width,
            height,
            luma: core::ptr::null_mut(),
            cb: core::ptr::null_mut(),
            cr: core::ptr::null_mut(),
        };
        if !refImage.data.is_null() {
            h264bsdPredictSamples(
                data.as_mut_ptr(),
                &mv,
                &refImage,
                col * 16,
                row * 16,
                0,
                0,
                16,
                16,
            );
            h264bsdWriteMacroblock(currImage, data.as_ptr());

            return HANTRO_OK;
        } else {
            data.fill(0);
        }
    }

    firstPhase.fill(0);

    /* counter for number of neighbours used */
    j = 0;
    hor = 0;
    ver = 0;
    if row != 0 && (*pMb.sub(width as usize)).decoded != 0 {
        A = HANTRO_TRUE;
        pData = mbPos.sub((width * 16) as usize);
        a[0] = *pData as i32; pData = pData.add(1);
        a[0] += *pData as i32; pData = pData.add(1);
        a[0] += *pData as i32; pData = pData.add(1);
        a[0] += *pData as i32; pData = pData.add(1);
        a[1] = *pData as i32; pData = pData.add(1);
        a[1] += *pData as i32; pData = pData.add(1);
        a[1] += *pData as i32; pData = pData.add(1);
        a[1] += *pData as i32; pData = pData.add(1);
        a[2] = *pData as i32; pData = pData.add(1);
        a[2] += *pData as i32; pData = pData.add(1);
        a[2] += *pData as i32; pData = pData.add(1);
        a[2] += *pData as i32; pData = pData.add(1);
        a[3] = *pData as i32; pData = pData.add(1);
        a[3] += *pData as i32; pData = pData.add(1);
        a[3] += *pData as i32; pData = pData.add(1);
        a[3] += *pData as i32;
        j += 1;
        hor += 1;
        firstPhase[0] += a[0] + a[1] + a[2] + a[3];
        firstPhase[1] += a[0] + a[1] - a[2] - a[3];
    }
    if row != height - 1 && (*pMb.add(width as usize)).decoded != 0 {
        B = HANTRO_TRUE;
        pData = mbPos.add((16 * width * 16) as usize);
        b[0] = *pData as i32; pData = pData.add(1);
        b[0] += *pData as i32; pData = pData.add(1);
        b[0] += *pData as i32; pData = pData.add(1);
        b[0] += *pData as i32; pData = pData.add(1);
        b[1] = *pData as i32; pData = pData.add(1);
        b[1] += *pData as i32; pData = pData.add(1);
        b[1] += *pData as i32; pData = pData.add(1);
        b[1] += *pData as i32; pData = pData.add(1);
        b[2] = *pData as i32; pData = pData.add(1);
        b[2] += *pData as i32; pData = pData.add(1);
        b[2] += *pData as i32; pData = pData.add(1);
        b[2] += *pData as i32; pData = pData.add(1);
        b[3] = *pData as i32; pData = pData.add(1);
        b[3] += *pData as i32; pData = pData.add(1);
        b[3] += *pData as i32; pData = pData.add(1);
        b[3] += *pData as i32;
        j += 1;
        hor += 1;
        firstPhase[0] += b[0] + b[1] + b[2] + b[3];
        firstPhase[1] += b[0] + b[1] - b[2] - b[3];
    }
    if col != 0 && (*pMb.sub(1)).decoded != 0 {
        L = HANTRO_TRUE;
        pData = mbPos.sub(1);
        l[0] = *pData as i32;
        l[0] += *pData.add((16 * width) as usize) as i32;
        l[0] += *pData.add((32 * width) as usize) as i32;
        l[0] += *pData.add((48 * width) as usize) as i32;
        pData = pData.add((64 * width) as usize);
        l[1] = *pData as i32;
        l[1] += *pData.add((16 * width) as usize) as i32;
        l[1] += *pData.add((32 * width) as usize) as i32;
        l[1] += *pData.add((48 * width) as usize) as i32;
        pData = pData.add((64 * width) as usize);
        l[2] = *pData as i32;
        l[2] += *pData.add((16 * width) as usize) as i32;
        l[2] += *pData.add((32 * width) as usize) as i32;
        l[2] += *pData.add((48 * width) as usize) as i32;
        pData = pData.add((64 * width) as usize);
        l[3] = *pData as i32;
        l[3] += *pData.add((16 * width) as usize) as i32;
        l[3] += *pData.add((32 * width) as usize) as i32;
        l[3] += *pData.add((48 * width) as usize) as i32;
        j += 1;
        ver += 1;
        firstPhase[0] += l[0] + l[1] + l[2] + l[3];
        firstPhase[4] += l[0] + l[1] - l[2] - l[3];
    }
    if col != width - 1 && (*pMb.add(1)).decoded != 0 {
        R = HANTRO_TRUE;
        pData = mbPos.add(16);
        r[0] = *pData as i32;
        r[0] += *pData.add((16 * width) as usize) as i32;
        r[0] += *pData.add((32 * width) as usize) as i32;
        r[0] += *pData.add((48 * width) as usize) as i32;
        pData = pData.add((64 * width) as usize);
        r[1] = *pData as i32;
        r[1] += *pData.add((16 * width) as usize) as i32;
        r[1] += *pData.add((32 * width) as usize) as i32;
        r[1] += *pData.add((48 * width) as usize) as i32;
        pData = pData.add((64 * width) as usize);
        r[2] = *pData as i32;
        r[2] += *pData.add((16 * width) as usize) as i32;
        r[2] += *pData.add((32 * width) as usize) as i32;
        r[2] += *pData.add((48 * width) as usize) as i32;
        pData = pData.add((64 * width) as usize);
        r[3] = *pData as i32;
        r[3] += *pData.add((16 * width) as usize) as i32;
        r[3] += *pData.add((32 * width) as usize) as i32;
        r[3] += *pData.add((48 * width) as usize) as i32;
        j += 1;
        ver += 1;
        firstPhase[0] += r[0] + r[1] + r[2] + r[3];
        firstPhase[4] += r[0] + r[1] - r[2] - r[3];
    }

    if hor == 0 && L != 0 && R != 0 {
        firstPhase[1] = (l[0] + l[1] + l[2] + l[3] - r[0] - r[1] - r[2] - r[3]) >> 5;
    } else if hor != 0 {
        firstPhase[1] >>= 3 + hor;
    }

    if ver == 0 && A != 0 && B != 0 {
        firstPhase[4] = (a[0] + a[1] + a[2] + a[3] - b[0] - b[1] - b[2] - b[3]) >> 5;
    } else if ver != 0 {
        firstPhase[4] >>= 3 + ver;
    }

    match j {
        1 => {
            firstPhase[0] >>= 4;
        }
        2 => {
            firstPhase[0] >>= 5;
        }
        3 => {
            /* approximate (firstPhase[0]*4/3)>>6 */
            firstPhase[0] = (21 * firstPhase[0]) >> 10;
        }
        _ => {
            /* 4 */
            firstPhase[0] >>= 6;
        }
    }

    Transform(firstPhase.as_mut_ptr());

    i = 0;
    pData = data.as_mut_ptr();
    pTmp = firstPhase.as_ptr();
    while i < 256 {
        tmp = *pTmp.add(((i & 0xF) >> 2) as usize);
        *pData = CLIP1!(tmp) as u8;
        pData = pData.add(1);

        i += 1;
        if (i & 0x3F) == 0 {
            pTmp = pTmp.add(4);
        }
    }

    /* chroma components */
    mbPos = currImage
        .data
        .add((width * height * 256 + row * 8 * width * 8 + col * 8) as usize);
    comp = 0;
    while comp < 2 {
        firstPhase.fill(0);

        /* counter for number of neighbours used */
        j = 0;
        hor = 0;
        ver = 0;
        if A != 0 {
            pData = mbPos.sub((width * 8) as usize);
            a[0] = *pData as i32; pData = pData.add(1);
            a[0] += *pData as i32; pData = pData.add(1);
            a[1] = *pData as i32; pData = pData.add(1);
            a[1] += *pData as i32; pData = pData.add(1);
            a[2] = *pData as i32; pData = pData.add(1);
            a[2] += *pData as i32; pData = pData.add(1);
            a[3] = *pData as i32; pData = pData.add(1);
            a[3] += *pData as i32;
            j += 1;
            hor += 1;
            firstPhase[0] += a[0] + a[1] + a[2] + a[3];
            firstPhase[1] += a[0] + a[1] - a[2] - a[3];
        }
        if B != 0 {
            pData = mbPos.add((8 * width * 8) as usize);
            b[0] = *pData as i32; pData = pData.add(1);
            b[0] += *pData as i32; pData = pData.add(1);
            b[1] = *pData as i32; pData = pData.add(1);
            b[1] += *pData as i32; pData = pData.add(1);
            b[2] = *pData as i32; pData = pData.add(1);
            b[2] += *pData as i32; pData = pData.add(1);
            b[3] = *pData as i32; pData = pData.add(1);
            b[3] += *pData as i32;
            j += 1;
            hor += 1;
            firstPhase[0] += b[0] + b[1] + b[2] + b[3];
            firstPhase[1] += b[0] + b[1] - b[2] - b[3];
        }
        if L != 0 {
            pData = mbPos.sub(1);
            l[0] = *pData as i32;
            l[0] += *pData.add((8 * width) as usize) as i32;
            pData = pData.add((16 * width) as usize);
            l[1] = *pData as i32;
            l[1] += *pData.add((8 * width) as usize) as i32;
            pData = pData.add((16 * width) as usize);
            l[2] = *pData as i32;
            l[2] += *pData.add((8 * width) as usize) as i32;
            pData = pData.add((16 * width) as usize);
            l[3] = *pData as i32;
            l[3] += *pData.add((8 * width) as usize) as i32;
            j += 1;
            ver += 1;
            firstPhase[0] += l[0] + l[1] + l[2] + l[3];
            firstPhase[4] += l[0] + l[1] - l[2] - l[3];
        }
        if R != 0 {
            pData = mbPos.add(8);
            r[0] = *pData as i32;
            r[0] += *pData.add((8 * width) as usize) as i32;
            pData = pData.add((16 * width) as usize);
            r[1] = *pData as i32;
            r[1] += *pData.add((8 * width) as usize) as i32;
            pData = pData.add((16 * width) as usize);
            r[2] = *pData as i32;
            r[2] += *pData.add((8 * width) as usize) as i32;
            pData = pData.add((16 * width) as usize);
            r[3] = *pData as i32;
            r[3] += *pData.add((8 * width) as usize) as i32;
            j += 1;
            ver += 1;
            firstPhase[0] += r[0] + r[1] + r[2] + r[3];
            firstPhase[4] += r[0] + r[1] - r[2] - r[3];
        }
        if hor == 0 && L != 0 && R != 0 {
            firstPhase[1] = (l[0] + l[1] + l[2] + l[3] - r[0] - r[1] - r[2] - r[3]) >> 4;
        } else if hor != 0 {
            firstPhase[1] >>= 2 + hor;
        }

        if ver == 0 && A != 0 && B != 0 {
            firstPhase[4] = (a[0] + a[1] + a[2] + a[3] - b[0] - b[1] - b[2] - b[3]) >> 4;
        } else if ver != 0 {
            firstPhase[4] >>= 2 + ver;
        }

        match j {
            1 => {
                firstPhase[0] >>= 3;
            }
            2 => {
                firstPhase[0] >>= 4;
            }
            3 => {
                /* approximate (firstPhase[0]*4/3)>>5 */
                firstPhase[0] = (21 * firstPhase[0]) >> 9;
            }
            _ => {
                /* 4 */
                firstPhase[0] >>= 5;
            }
        }

        Transform(firstPhase.as_mut_ptr());

        pData = data.as_mut_ptr().add((256 + comp * 64) as usize);
        i = 0;
        pTmp = firstPhase.as_ptr();
        while i < 64 {
            tmp = *pTmp.add(((i & 0x7) >> 1) as usize);
            *pData = CLIP1!(tmp) as u8;
            pData = pData.add(1);

            i += 1;
            if (i & 0xF) == 0 {
                pTmp = pTmp.add(4);
            }
        }

        /* increment pointers for cr */
        mbPos = mbPos.add((width * height * 64) as usize);
        comp += 1;
    }

    h264bsdWriteMacroblock(currImage, data.as_ptr());

    HANTRO_OK
}

/*------------------------------------------------------------------------------
    Function name: Transform

        Functional description:
            Simplified transform, assuming that only dc component and lowest
            horizontal and lowest vertical component may be non-zero
------------------------------------------------------------------------------*/
unsafe fn Transform(data: *mut i32) {
    let mut col: u32;
    let mut tmp0: i32;
    let mut tmp1: i32;

    if *data.add(1) == 0 && *data.add(4) == 0 {
        let d0 = *data.add(0);
        *data.add(1) = d0;
        *data.add(2) = d0;
        *data.add(3) = d0;
        *data.add(4) = d0;
        *data.add(5) = d0;
        *data.add(6) = d0;
        *data.add(7) = d0;
        *data.add(8) = d0;
        *data.add(9) = d0;
        *data.add(10) = d0;
        *data.add(11) = d0;
        *data.add(12) = d0;
        *data.add(13) = d0;
        *data.add(14) = d0;
        *data.add(15) = d0;
        return;
    }
    /* first horizontal transform for rows 0 and 1 */
    tmp0 = *data.add(0);
    tmp1 = *data.add(1);
    *data.add(0) = tmp0 + tmp1;
    *data.add(1) = tmp0 + (tmp1 >> 1);
    *data.add(2) = tmp0 - (tmp1 >> 1);
    *data.add(3) = tmp0 - tmp1;

    tmp0 = *data.add(4);
    *data.add(5) = tmp0;
    *data.add(6) = tmp0;
    *data.add(7) = tmp0;

    /* then vertical transform */
    let mut data = data;
    col = 4;
    while col != 0 {
        col -= 1;
        tmp0 = *data.add(0);
        tmp1 = *data.add(4);
        *data.add(0) = tmp0 + tmp1;
        *data.add(4) = tmp0 + (tmp1 >> 1);
        *data.add(8) = tmp0 - (tmp1 >> 1);
        *data.add(12) = tmp0 - tmp1;
        data = data.add(1);
    }
}
