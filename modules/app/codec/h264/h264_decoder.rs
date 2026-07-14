// Mechanical Rust port of h264bsd_decoder.c (h264bsd, Apache-2.0),
// per the port rules in scratchpad/PORT_RULES.md. Top-level decoder
// API: h264bsdDecode state machine (NAL dispatch, access-unit boundary
// handling, picture completion, conceal fallback, output flushing).
//
// SKIPPED (dead in this build / JS-wrapper-only, per rules):
// - h264bsdNextOutputPictureRGBA / BGRA / YCbCrA and
//   h264bsdConvertToRGBA / BGRA / YCbCrA (color-space converters; the
//   port consumes YUV directly). storage_t has no conversionBuffer,
//   so the corresponding FREE in h264bsdShutdown is dropped too.
// - h264bsdAlloc / h264bsdFree (storage-sized malloc/free wrappers).
// - h264bsdCheckValidParamSets, h264bsdVideoRange,
//   h264bsdMatrixCoefficients, h264bsdSampleAspectRatio,
//   h264bsdProfile (query helpers only used by the JS wrapper;
//   unreachable from h264bsdDecode).
// - h264bsdCurrentImage (listed in the C table of contents but not
//   present in this translation unit).
// SEI NAL units are skipped (not decoded), exactly as the C does.

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
use super::h264_parse::*;
use super::h264_slice_header::*;
use super::h264_slice_data::*;
use super::h264_storage::*;
use super::h264_dpb::*;
use super::h264_deblock::*;

/*------------------------------------------------------------------------------

    Function name: h264bsdInit

        Functional description:
            Initialize the decoder.

        Inputs:
            noOutputReordering  flag to indicate the decoder that it does not
                                have to perform reordering of display images.

        Outputs:
            pStorage            pointer to initialized storage structure

------------------------------------------------------------------------------*/

pub unsafe fn h264bsdInit(pStorage: &mut storage_t, noOutputReordering: u32, alloc: Allocator) -> u32 {
    /* Variables */
    let size: usize;
    /* Code */

    /* Port addition: install allocation hooks before anything else so
     * all downstream ALLOCATE/FREE sites (storage + dpb) can use them. */
    pStorage.allocator = alloc;
    pStorage.dpb[0].allocator = alloc;

    h264bsdInitStorage(pStorage);

    /* allocate mbLayer to be next multiple of 64 to enable use of
     * specific NEON optimized "memset" for clearing the structure */
    size = (core::mem::size_of::<macroblockLayer_t>() + 63) & !0x3F;

    pStorage.mbLayer = (alloc.alloc)(alloc.ctx, size) as *mut macroblockLayer_t;
    if pStorage.mbLayer.is_null() {
        return HANTRO_NOK;
    }

    if noOutputReordering != 0 {
        pStorage.noReordering = HANTRO_TRUE;
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: h264bsdDecode

        Functional description:
            Decode a NAL unit. This function calls other modules to perform
            tasks like
                * extract and decode NAL unit from the byte stream
                * decode parameter sets
                * decode slice header and slice data
                * conceal errors in the picture
                * perform deblocking filtering

            This function contains top level control logic of the decoder.

        Inputs:
            pStorage        pointer to storage data structure
            byteStrm        pointer to stream buffer given by application
            len             length of the buffer in bytes
            picId           identifier for a picture, assigned by the
                            application

        Outputs:
            readBytes       number of bytes read from the stream is stored
                            here

        Returns:
            H264BSD_RDY             decoding finished, nothing special
            H264BSD_PIC_RDY         decoding of a picture finished
            H264BSD_HDRS_RDY        param sets activated, information like
                                    picture dimensions etc can be read
            H264BSD_ERROR           error in decoding
            H264BSD_PARAM_SET_ERROR serius error in decoding, failed to
                                    activate param sets

------------------------------------------------------------------------------*/

pub unsafe fn h264bsdDecode(
    pStorage: &mut storage_t,
    byteStrm: *mut u8,
    len: u32,
    picId: u32,
    readBytes: &mut u32,
) -> u32 {
    /* Variables */

    let mut tmp: u32;
    let mut ppsId: u32 = 0;
    let mut spsId: u32;
    let picOrderCnt: i32;
    let mut nalUnit: nalUnit_t = core::mem::zeroed();
    let mut seqParamSet: seqParamSet_t = core::mem::zeroed();
    let mut picParamSet: picParamSet_t = core::mem::zeroed();
    let mut strm: strmData_t = strmData_t::zeroed();
    let mut accessUnitBoundaryFlag: u32 = HANTRO_FALSE;
    let mut picReady: u32 = HANTRO_FALSE;

    /* Code */

    /* if previous buffer was not finished and same pointer given -> skip NAL
     * unit extraction */
    if pStorage.prevBufNotFinished != 0 && byteStrm as *const u8 == pStorage.prevBufPointer {
        strm = core::ptr::read(&pStorage.strm[0]);
        strm.pStrmCurrPos = strm.pStrmBuffStart;
        strm.strmBuffReadBits = 0;
        strm.bitPosInWord = 0;
        *readBytes = pStorage.prevBytesConsumed;
    } else {
        tmp = h264bsdExtractNalUnit(byteStrm, len, &mut strm, readBytes);
        if tmp != HANTRO_OK {
            return H264BSD_ERROR;
        }
        /* store stream */
        pStorage.strm[0] = core::ptr::read(&strm);
        pStorage.prevBytesConsumed = *readBytes;
        pStorage.prevBufPointer = byteStrm;
    }
    pStorage.prevBufNotFinished = HANTRO_FALSE;

    tmp = h264bsdDecodeNalUnit(&mut strm, &mut nalUnit);
    if tmp != HANTRO_OK {
        return H264BSD_ERROR;
    }

    /* Discard unspecified, reserved, SPS extension and auxiliary picture slices */
    if nalUnit.nalUnitType == 0 || nalUnit.nalUnitType >= 13 {
        return H264BSD_RDY;
    }

    tmp = h264bsdCheckAccessUnitBoundary(&mut strm, &nalUnit, pStorage, &mut accessUnitBoundaryFlag);
    if tmp != HANTRO_OK {
        if tmp == PARAM_SET_ERROR {
            return H264BSD_PARAM_SET_ERROR;
        } else {
            return H264BSD_ERROR;
        }
    }

    if accessUnitBoundaryFlag != 0 {
        /* conceal if picture started and param sets activated */
        if pStorage.picStarted != 0 && !pStorage.activeSps.is_null() {
            /* return error if second phase of
             * initialization is not completed */
            if pStorage.pendingActivation != 0 {
                return H264BSD_ERROR;
            }

            if pStorage.validSliceInAccessUnit == 0 {
                {
                    let dpb: *mut dpbStorage_t = pStorage.dpb.as_mut_ptr();
                    pStorage.currImage[0].data = h264bsdAllocateDpbImage(&mut *dpb);
                    h264bsdInitRefPicList(&mut *dpb);
                }
                let currImage: *mut image_t = pStorage.currImage.as_mut_ptr();
                tmp = h264bsdConceal(pStorage, &mut *currImage, P_SLICE);
            } else {
                let currImage: *mut image_t = pStorage.currImage.as_mut_ptr();
                let sliceType = pStorage.sliceHeader[0].sliceType;
                tmp = h264bsdConceal(pStorage, &mut *currImage, sliceType);
            }

            picReady = HANTRO_TRUE;

            /* current NAL unit should be decoded on next activation -> set
             * readBytes to 0 */
            *readBytes = 0;
            pStorage.prevBufNotFinished = HANTRO_TRUE;
        } else {
            pStorage.validSliceInAccessUnit = HANTRO_FALSE;
        }
        pStorage.skipRedundantSlices = HANTRO_FALSE;
    }

    if picReady == 0 {
        match nalUnit.nalUnitType {
            NAL_SEQ_PARAM_SET => {
                tmp = h264bsdDecodeSeqParamSet(&mut strm, &mut seqParamSet, &pStorage.allocator);
                if tmp != HANTRO_OK {
                    pStorage.allocator.free_ptr(seqParamSet.offsetForRefFrame);
                    seqParamSet.offsetForRefFrame = core::ptr::null_mut();
                    pStorage.allocator.free_ptr(seqParamSet.vuiParameters);
                    seqParamSet.vuiParameters = core::ptr::null_mut();
                    return H264BSD_ERROR;
                }
                tmp = h264bsdStoreSeqParamSet(pStorage, &mut seqParamSet);
            }

            NAL_PIC_PARAM_SET => {
                tmp = h264bsdDecodePicParamSet(&mut strm, &mut picParamSet, &pStorage.allocator);
                if tmp != HANTRO_OK {
                    pStorage.allocator.free_ptr(picParamSet.runLength);
                    picParamSet.runLength = core::ptr::null_mut();
                    pStorage.allocator.free_ptr(picParamSet.topLeft);
                    picParamSet.topLeft = core::ptr::null_mut();
                    pStorage.allocator.free_ptr(picParamSet.bottomRight);
                    picParamSet.bottomRight = core::ptr::null_mut();
                    pStorage.allocator.free_ptr(picParamSet.sliceGroupId);
                    picParamSet.sliceGroupId = core::ptr::null_mut();
                    return H264BSD_ERROR;
                }
                tmp = h264bsdStorePicParamSet(pStorage, &mut picParamSet);
            }

            /* NAL_CODED_SLICE_IDR falls through to NAL_CODED_SLICE in C */
            NAL_CODED_SLICE_IDR | NAL_CODED_SLICE => {
                /* picture successfully finished and still decoding same old
                 * access unit -> no need to decode redundant slices */
                if pStorage.skipRedundantSlices != 0 {
                    return H264BSD_RDY;
                }

                pStorage.picStarted = HANTRO_TRUE;

                if h264bsdIsStartOfPicture(pStorage) != 0 {
                    pStorage.numConcealedMbs = 0;
                    pStorage.currentPicId = picId;

                    tmp = h264bsdCheckPpsId(&mut strm, &mut ppsId);
                    /* store old activeSpsId and return headers ready
                     * indication if activeSps changes */
                    spsId = pStorage.activeSpsId;
                    tmp = h264bsdActivateParamSets(
                        pStorage,
                        ppsId,
                        if IS_IDR_NAL_UNIT(&nalUnit) { HANTRO_TRUE } else { HANTRO_FALSE },
                    );
                    if tmp != HANTRO_OK {
                        pStorage.activePpsId = MAX_NUM_PIC_PARAM_SETS as u32;
                        pStorage.activePps = core::ptr::null_mut();
                        pStorage.activeSpsId = MAX_NUM_SEQ_PARAM_SETS as u32;
                        pStorage.activeSps = core::ptr::null_mut();
                        pStorage.pendingActivation = HANTRO_FALSE;

                        if tmp == MEMORY_ALLOCATION_ERROR {
                            return H264BSD_MEMALLOC_ERROR;
                        } else {
                            return H264BSD_PARAM_SET_ERROR;
                        }
                    }

                    if spsId != pStorage.activeSpsId {
                        let mut oldSPS: *mut seqParamSet_t = core::ptr::null_mut();
                        let newSPS: *mut seqParamSet_t = pStorage.activeSps;
                        let mut noOutputOfPriorPicsFlag: u32 = 1;

                        if pStorage.oldSpsId < MAX_NUM_SEQ_PARAM_SETS as u32 {
                            oldSPS = pStorage.sps[pStorage.oldSpsId as usize];
                        }

                        *readBytes = 0;
                        pStorage.prevBufNotFinished = HANTRO_TRUE;

                        if nalUnit.nalUnitType == NAL_CODED_SLICE_IDR {
                            tmp = h264bsdCheckPriorPicsFlag(
                                &mut noOutputOfPriorPicsFlag,
                                &strm,
                                &*newSPS,
                                &*pStorage.activePps,
                                nalUnit.nalUnitType,
                            );
                        } else {
                            tmp = HANTRO_NOK;
                        }

                        if tmp != HANTRO_OK
                            || noOutputOfPriorPicsFlag != 0
                            || pStorage.dpb[0].noReordering != 0
                            || oldSPS.is_null()
                            || (*oldSPS).picWidthInMbs != (*newSPS).picWidthInMbs
                            || (*oldSPS).picHeightInMbs != (*newSPS).picHeightInMbs
                            || (*oldSPS).maxDpbSize != (*newSPS).maxDpbSize
                        {
                            pStorage.dpb[0].flushed = 0;
                        } else {
                            h264bsdFlushDpb(&mut pStorage.dpb[0]);
                        }

                        pStorage.oldSpsId = pStorage.activeSpsId;

                        return H264BSD_HDRS_RDY;
                    }
                }

                /* return error if second phase of
                 * initialization is not completed */
                if pStorage.pendingActivation != 0 {
                    return H264BSD_ERROR;
                }
                {
                    let activeSps: *mut seqParamSet_t = pStorage.activeSps;
                    let activePps: *mut picParamSet_t = pStorage.activePps;
                    tmp = h264bsdDecodeSliceHeader(
                        &mut strm,
                        &mut pStorage.sliceHeader[1],
                        &*activeSps,
                        &*activePps,
                        &nalUnit,
                    );
                }
                if tmp != HANTRO_OK {
                    return H264BSD_ERROR;
                }
                if h264bsdIsStartOfPicture(pStorage) != 0 {
                    if !IS_IDR_NAL_UNIT(&nalUnit) {
                        let frameNum = pStorage.sliceHeader[1].frameNum;
                        let gapsAllowed = (*pStorage.activeSps).gapsInFrameNumValueAllowedFlag;
                        tmp = h264bsdCheckGapsInFrameNum(
                            &mut pStorage.dpb[0],
                            frameNum,
                            if nalUnit.nalRefIdc != 0 { HANTRO_TRUE } else { HANTRO_FALSE },
                            gapsAllowed,
                        );
                        if tmp != HANTRO_OK {
                            return H264BSD_ERROR;
                        }
                    }
                    pStorage.currImage[0].data = h264bsdAllocateDpbImage(&mut pStorage.dpb[0]);
                }

                /* store slice header to storage if successfully decoded */
                pStorage.sliceHeader[0] = pStorage.sliceHeader[1];
                pStorage.validSliceInAccessUnit = HANTRO_TRUE;
                pStorage.prevNalUnit[0] = nalUnit;

                let sliceGroupChangeCycle = pStorage.sliceHeader[0].sliceGroupChangeCycle;
                h264bsdComputeSliceGroupMap(pStorage, sliceGroupChangeCycle);

                h264bsdInitRefPicList(&mut pStorage.dpb[0]);
                {
                    let dpb: *mut dpbStorage_t = pStorage.dpb.as_mut_ptr();
                    let frameNum = pStorage.sliceHeader[0].frameNum;
                    let numRefIdxL0Active = pStorage.sliceHeader[0].numRefIdxL0Active;
                    tmp = h264bsdReorderRefPicList(
                        &mut *dpb,
                        &mut pStorage.sliceHeader[0].refPicListReordering,
                        frameNum,
                        numRefIdxL0Active,
                    );
                }
                if tmp != HANTRO_OK {
                    return H264BSD_ERROR;
                }

                {
                    let currImage: *mut image_t = pStorage.currImage.as_mut_ptr();
                    let sliceHeader: *mut sliceHeader_t = pStorage.sliceHeader.as_mut_ptr();
                    tmp = h264bsdDecodeSliceData(&mut strm, pStorage, &mut *currImage, &mut *sliceHeader);
                }
                if tmp != HANTRO_OK {
                    let firstMbInSlice = pStorage.sliceHeader[0].firstMbInSlice;
                    h264bsdMarkSliceCorrupted(pStorage, firstMbInSlice);
                    return H264BSD_ERROR;
                }

                if h264bsdIsEndOfPicture(pStorage) != 0 {
                    picReady = HANTRO_TRUE;
                    pStorage.skipRedundantSlices = HANTRO_TRUE;
                }
            }

            NAL_SEI => {
                /* SEI MESSAGE, NOT DECODED */
            }

            _ => {
                /* NOT IMPLEMENTED YET */
            }
        }
    }

    if picReady != 0 {
        {
            let currImage: *mut image_t = pStorage.currImage.as_mut_ptr();
            h264bsdFilterPicture(&mut *currImage, pStorage.mb);
        }

        h264bsdResetStorage(pStorage);

        {
            let activeSps: *mut seqParamSet_t = pStorage.activeSps;
            let sliceHeader: *const sliceHeader_t = pStorage.sliceHeader.as_ptr();
            let prevNalUnit: *const nalUnit_t = pStorage.prevNalUnit.as_ptr();
            picOrderCnt = h264bsdDecodePicOrderCnt(
                &mut pStorage.poc[0],
                &*activeSps,
                &*sliceHeader,
                &*prevNalUnit,
            );
        }

        if pStorage.validSliceInAccessUnit != 0 {
            let currImage: *const image_t = pStorage.currImage.as_ptr();
            let frameNum = pStorage.sliceHeader[0].frameNum;
            let isIdr = if IS_IDR_NAL_UNIT(&pStorage.prevNalUnit[0]) { HANTRO_TRUE } else { HANTRO_FALSE };
            let currentPicId = pStorage.currentPicId;
            let numConcealedMbs = pStorage.numConcealedMbs;
            if pStorage.prevNalUnit[0].nalRefIdc != 0 {
                let mark: *mut decRefPicMarking_t = &mut pStorage.sliceHeader[0].decRefPicMarking;
                let dpb: *mut dpbStorage_t = pStorage.dpb.as_mut_ptr();
                tmp = h264bsdMarkDecRefPic(
                    &mut *dpb,
                    mark,
                    currImage,
                    frameNum,
                    picOrderCnt,
                    isIdr,
                    currentPicId,
                    numConcealedMbs,
                );
            }
            /* non-reference picture, just store for possible display
             * reordering */
            else {
                let dpb: *mut dpbStorage_t = pStorage.dpb.as_mut_ptr();
                tmp = h264bsdMarkDecRefPic(
                    &mut *dpb,
                    core::ptr::null_mut(),
                    currImage,
                    frameNum,
                    picOrderCnt,
                    isIdr,
                    currentPicId,
                    numConcealedMbs,
                );
            }
        }

        pStorage.picStarted = HANTRO_FALSE;
        pStorage.validSliceInAccessUnit = HANTRO_FALSE;

        H264BSD_PIC_RDY
    } else {
        H264BSD_RDY
    }
}

/*------------------------------------------------------------------------------

    Function: h264bsdShutdown

        Functional description:
            Shutdown a decoder instance. Function frees all the memories
            allocated for the decoder instance.

        Inputs:
            pStorage    pointer to storage data structure

------------------------------------------------------------------------------*/

pub unsafe fn h264bsdShutdown(pStorage: &mut storage_t) {
    /* Variables */

    let mut i: usize;

    /* Code */

    let alloc = pStorage.allocator;

    i = 0;
    while i < MAX_NUM_SEQ_PARAM_SETS {
        if !pStorage.sps[i].is_null() {
            alloc.free_ptr((*pStorage.sps[i]).offsetForRefFrame);
            (*pStorage.sps[i]).offsetForRefFrame = core::ptr::null_mut();
            alloc.free_ptr((*pStorage.sps[i]).vuiParameters);
            (*pStorage.sps[i]).vuiParameters = core::ptr::null_mut();
            alloc.free_ptr(pStorage.sps[i]);
            pStorage.sps[i] = core::ptr::null_mut();
        }
        i += 1;
    }

    i = 0;
    while i < MAX_NUM_PIC_PARAM_SETS {
        if !pStorage.pps[i].is_null() {
            alloc.free_ptr((*pStorage.pps[i]).runLength);
            (*pStorage.pps[i]).runLength = core::ptr::null_mut();
            alloc.free_ptr((*pStorage.pps[i]).topLeft);
            (*pStorage.pps[i]).topLeft = core::ptr::null_mut();
            alloc.free_ptr((*pStorage.pps[i]).bottomRight);
            (*pStorage.pps[i]).bottomRight = core::ptr::null_mut();
            alloc.free_ptr((*pStorage.pps[i]).sliceGroupId);
            (*pStorage.pps[i]).sliceGroupId = core::ptr::null_mut();
            alloc.free_ptr(pStorage.pps[i]);
            pStorage.pps[i] = core::ptr::null_mut();
        }
        i += 1;
    }

    alloc.free_ptr(pStorage.mbLayer);
    pStorage.mbLayer = core::ptr::null_mut();
    alloc.free_ptr(pStorage.mb);
    pStorage.mb = core::ptr::null_mut();
    alloc.free_ptr(pStorage.sliceGroupMap);
    pStorage.sliceGroupMap = core::ptr::null_mut();

    /* C frees pStorage->conversionBuffer here; SKIPPED (no conversion
     * buffer in this port, see file header). */

    h264bsdFreeDpb(&mut pStorage.dpb[0]);
}

/*------------------------------------------------------------------------------

    Function: h264bsdNextOutputPicture

        Functional description:
            Get next output picture in display order.

        Inputs:
            pStorage    pointer to storage data structure

        Outputs:
            picId       identifier of the picture will be stored here
            isIdrPic    IDR flag of the picture will be stored here
            numErrMbs   number of concealed macroblocks in the picture
                        will be stored here

        Returns:
            pointer to the picture data
            NULL if no pictures available for display

------------------------------------------------------------------------------*/

pub unsafe fn h264bsdNextOutputPicture(
    pStorage: &mut storage_t,
    picId: &mut u32,
    isIdrPic: &mut u32,
    numErrMbs: &mut u32,
) -> *mut u8 {
    /* Variables */

    let pOut: *mut dpbOutPicture_t;

    /* Code */

    pOut = h264bsdDpbOutputPicture(&mut pStorage.dpb[0]);

    if !pOut.is_null() {
        *picId = (*pOut).picId;
        *isIdrPic = (*pOut).isIdr;
        *numErrMbs = (*pOut).numErrMbs;
        (*pOut).data
    } else {
        core::ptr::null_mut()
    }
}

/*------------------------------------------------------------------------------

    Function: h264bsdPicWidth

        Functional description:
            Get width of the picture in macroblocks

        Returns:
            picture width
            0 if parameters sets not yet activated

------------------------------------------------------------------------------*/

pub unsafe fn h264bsdPicWidth(pStorage: &mut storage_t) -> u32 {
    if !pStorage.activeSps.is_null() {
        (*pStorage.activeSps).picWidthInMbs
    } else {
        0
    }
}

/*------------------------------------------------------------------------------

    Function: h264bsdPicHeight

        Functional description:
            Get height of the picture in macroblocks

        Returns:
            picture width
            0 if parameters sets not yet activated

------------------------------------------------------------------------------*/

pub unsafe fn h264bsdPicHeight(pStorage: &mut storage_t) -> u32 {
    if !pStorage.activeSps.is_null() {
        (*pStorage.activeSps).picHeightInMbs
    } else {
        0
    }
}

/*------------------------------------------------------------------------------

    Function: h264bsdFlushBuffer

        Functional description:
            Flush the decoded picture buffer, see dpb.c for details

        Inputs:
            pStorage    pointer to storage data structure

------------------------------------------------------------------------------*/

pub unsafe fn h264bsdFlushBuffer(pStorage: &mut storage_t) {
    h264bsdFlushDpb(&mut pStorage.dpb[0]);
}

/*------------------------------------------------------------------------------

    Function: h264bsdCroppingParams

        Functional description:
            Get cropping parameters of the active SPS

        Outputs:
            croppingFlag    flag indicating if cropping params present is
                            stored here
            leftOffset      cropping left offset in pixels is stored here
            width           width of the image after cropping is stored here
            topOffset       cropping top offset in pixels is stored here
            height          height of the image after cropping is stored here

------------------------------------------------------------------------------*/

pub unsafe fn h264bsdCroppingParams(
    pStorage: &mut storage_t,
    croppingFlag: &mut u32,
    leftOffset: &mut u32,
    width: &mut u32,
    topOffset: &mut u32,
    height: &mut u32,
) {
    if !pStorage.activeSps.is_null() && (*pStorage.activeSps).frameCroppingFlag != 0 {
        *croppingFlag = 1;
        *leftOffset = 2 * (*pStorage.activeSps).frameCropLeftOffset;
        *width = 16 * (*pStorage.activeSps).picWidthInMbs
            - 2 * ((*pStorage.activeSps).frameCropLeftOffset
                + (*pStorage.activeSps).frameCropRightOffset);
        *topOffset = 2 * (*pStorage.activeSps).frameCropTopOffset;
        *height = 16 * (*pStorage.activeSps).picHeightInMbs
            - 2 * ((*pStorage.activeSps).frameCropTopOffset
                + (*pStorage.activeSps).frameCropBottomOffset);
    } else {
        *croppingFlag = 0;
        *leftOffset = 0;
        *width = 0;
        *topOffset = 0;
        *height = 0;
    }
}
