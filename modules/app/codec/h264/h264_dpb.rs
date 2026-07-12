// Mechanical Rust port of h264bsd_dpb.c (decoded picture buffer) per the
// h264bsd -> Rust port rules (scratchpad PORT_RULES.md). C names kept
// verbatim; logic (ShellSort ordering, sliding-window + adaptive MMCO
// marking, gap handling) ported 1:1 for bit-exact parity with the C
// reference.
//
// Ported functions: ComparePictures, h264bsdReorderRefPicList, Mmcop1..6,
// h264bsdMarkDecRefPic, h264bsdGetRefPicData, h264bsdAllocateDpbImage,
// SlidingWindowRefPicMarking, h264bsdInitDpb, h264bsdResetDpb,
// h264bsdInitRefPicList, FindDpbPic, SetPicNums, h264bsdCheckGapsInFrameNum,
// FindSmallestPicOrderCnt, OutputPicture, h264bsdDpbOutputPicture,
// h264bsdFlushDpb, h264bsdFreeDpb, ShellSort. Nothing skipped.
//
// Allocation goes through `dpb.allocator` (C malloc/free); the caller sets
// the field before h264bsdInitDpb.

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

/* macros to determine picture status. Note that IS_SHORT_TERM macro returns
 * true also for non-existing pictures because non-existing pictures are
 * regarded short term pictures according to H.264 standard */
#[inline(always)]
fn IS_REFERENCE(a: &dpbPicture_t) -> bool {
    a.status != 0
}
#[inline(always)]
fn IS_EXISTING(a: &dpbPicture_t) -> bool {
    a.status > NON_EXISTING
}
#[inline(always)]
fn IS_SHORT_TERM(a: &dpbPicture_t) -> bool {
    a.status == NON_EXISTING || a.status == SHORT_TERM
}
#[inline(always)]
fn IS_LONG_TERM(a: &dpbPicture_t) -> bool {
    a.status == LONG_TERM
}

/* macro to set a picture unused for reference */
#[inline(always)]
fn SET_UNUSED(a: &mut dpbPicture_t) {
    a.status = UNUSED;
}

const MAX_NUM_REF_IDX_L0_ACTIVE: u32 = 16;

/*------------------------------------------------------------------------------
    Function: ComparePictures

        Functional description:
            Function to compare dpb pictures, used by the ShellSort() function.
            Order of the pictures after sorting shall be as follows:
                1) short term reference pictures starting with the largest
                   picNum
                2) long term reference pictures starting with the smallest
                   longTermPicNum
                3) pictures unused for reference but needed for display
                4) other pictures

        Returns:
            -1      pic 1 is greater than pic 2
             0      equal from comparison point of view
             1      pic 2 is greater then pic 1
------------------------------------------------------------------------------*/
unsafe fn ComparePictures(ptr1: *const dpbPicture_t, ptr2: *const dpbPicture_t) -> i32 {
    let pic1: &dpbPicture_t = &*ptr1;
    let pic2: &dpbPicture_t = &*ptr2;

    /* both are non-reference pictures, check if needed for display */
    if !IS_REFERENCE(pic1) && !IS_REFERENCE(pic2) {
        if pic1.toBeDisplayed != 0 && pic2.toBeDisplayed == 0 {
            -1
        } else if pic1.toBeDisplayed == 0 && pic2.toBeDisplayed != 0 {
            1
        } else {
            0
        }
    }
    /* only pic 1 needed for reference -> greater */
    else if !IS_REFERENCE(pic2) {
        -1
    }
    /* only pic 2 needed for reference -> greater */
    else if !IS_REFERENCE(pic1) {
        1
    }
    /* both are short term reference pictures -> check picNum */
    else if IS_SHORT_TERM(pic1) && IS_SHORT_TERM(pic2) {
        if pic1.picNum > pic2.picNum {
            -1
        } else if pic1.picNum < pic2.picNum {
            1
        } else {
            0
        }
    }
    /* only pic 1 is short term -> greater */
    else if IS_SHORT_TERM(pic1) {
        -1
    }
    /* only pic 2 is short term -> greater */
    else if IS_SHORT_TERM(pic2) {
        1
    }
    /* both are long term reference pictures -> check picNum (contains the
     * longTermPicNum */
    else {
        if pic1.picNum > pic2.picNum {
            1
        } else if pic1.picNum < pic2.picNum {
            -1
        } else {
            0
        }
    }
}

/*------------------------------------------------------------------------------
    Function: h264bsdReorderRefPicList

        Functional description:
            Function to perform reference picture list reordering based on
            reordering commands received in the slice header. See details
            of the process in the H.264 standard.

        Returns:
            HANTRO_OK      success
            HANTRO_NOK     if non-existing pictures referred to in the
                           reordering commands
------------------------------------------------------------------------------*/
pub unsafe fn h264bsdReorderRefPicList(
    dpb: &mut dpbStorage_t,
    order: &mut refPicListReordering_t,
    currFrameNum: u32,
    numRefIdxActive: u32,
) -> u32 {
    let mut i: u32;
    let mut j: u32;
    let mut k: u32;
    let mut picNumPred: u32;
    let mut refIdx: u32;
    let mut picNum: i32;
    let mut picNumNoWrap: i32;
    let mut index: i32;
    let mut isShortTerm: u32;

    /* set dpb picture numbers for sorting */
    SetPicNums(dpb, currFrameNum);

    if order.refPicListReorderingFlagL0 == 0 {
        return HANTRO_OK;
    }

    refIdx = 0;
    picNumPred = currFrameNum;

    i = 0;
    while order.command[i as usize].reorderingOfPicNumsIdc < 3 {
        /* short term */
        if order.command[i as usize].reorderingOfPicNumsIdc < 2 {
            if order.command[i as usize].reorderingOfPicNumsIdc == 0 {
                picNumNoWrap =
                    picNumPred as i32 - order.command[i as usize].absDiffPicNum as i32;
                if picNumNoWrap < 0 {
                    picNumNoWrap += dpb.maxFrameNum as i32;
                }
            } else {
                picNumNoWrap = picNumPred
                    .wrapping_add(order.command[i as usize].absDiffPicNum)
                    as i32;
                if picNumNoWrap >= dpb.maxFrameNum as i32 {
                    picNumNoWrap -= dpb.maxFrameNum as i32;
                }
            }
            picNumPred = picNumNoWrap as u32;
            picNum = picNumNoWrap;
            if picNumNoWrap as u32 > currFrameNum {
                picNum -= dpb.maxFrameNum as i32;
            }
            isShortTerm = HANTRO_TRUE;
        }
        /* long term */
        else {
            picNum = order.command[i as usize].longTermPicNum as i32;
            isShortTerm = HANTRO_FALSE;
        }
        /* find corresponding picture from dpb */
        index = FindDpbPic(dpb, picNum, isShortTerm);
        if index < 0 || !IS_EXISTING(&*dpb.buffer.add(index as usize)) {
            return HANTRO_NOK;
        }

        /* shift pictures */
        j = numRefIdxActive;
        while j > refIdx {
            *dpb.list.add(j as usize) = *dpb.list.add((j - 1) as usize);
            j -= 1;
        }
        /* put picture into the list */
        *dpb.list.add(refIdx as usize) = dpb.buffer.add(index as usize);
        refIdx += 1;
        /* remove later references to the same picture */
        j = refIdx;
        k = refIdx;
        while j <= numRefIdxActive {
            if *dpb.list.add(j as usize) != dpb.buffer.add(index as usize) {
                *dpb.list.add(k as usize) = *dpb.list.add(j as usize);
                k += 1;
            }
            j += 1;
        }

        i += 1;
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------
    Function: Mmcop1

        Functional description:
            Function to mark a short-term reference picture unused for
            reference, memory_management_control_operation equal to 1

        Returns:
            HANTRO_OK      success
            HANTRO_NOK     failure, picture does not exist in the buffer
------------------------------------------------------------------------------*/
fn Mmcop1(dpb: &mut dpbStorage_t, currPicNum: u32, differenceOfPicNums: u32) -> u32 {
    let index: i32;
    let picNum: i32;

    picNum = currPicNum as i32 - differenceOfPicNums as i32;

    index = FindDpbPic(dpb, picNum, HANTRO_TRUE);
    if index < 0 {
        return HANTRO_NOK;
    }

    unsafe {
        SET_UNUSED(&mut *dpb.buffer.add(index as usize));
        dpb.numRefFrames = dpb.numRefFrames.wrapping_sub(1);
        if (*dpb.buffer.add(index as usize)).toBeDisplayed == 0 {
            dpb.fullness = dpb.fullness.wrapping_sub(1);
        }
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------
    Function: Mmcop2

        Functional description:
            Function to mark a long-term reference picture unused for
            reference, memory_management_control_operation equal to 2

        Returns:
            HANTRO_OK      success
            HANTRO_NOK     failure, picture does not exist in the buffer
------------------------------------------------------------------------------*/
fn Mmcop2(dpb: &mut dpbStorage_t, longTermPicNum: u32) -> u32 {
    let index: i32;

    index = FindDpbPic(dpb, longTermPicNum as i32, HANTRO_FALSE);
    if index < 0 {
        return HANTRO_NOK;
    }

    unsafe {
        SET_UNUSED(&mut *dpb.buffer.add(index as usize));
        dpb.numRefFrames = dpb.numRefFrames.wrapping_sub(1);
        if (*dpb.buffer.add(index as usize)).toBeDisplayed == 0 {
            dpb.fullness = dpb.fullness.wrapping_sub(1);
        }
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------
    Function: Mmcop3

        Functional description:
            Function to assing a longTermFrameIdx to a short-term reference
            frame (i.e. to change it to a long-term reference picture),
            memory_management_control_operation equal to 3

        Returns:
            HANTRO_OK      success
            HANTRO_NOK     failure, short-term picture does not exist in the
                           buffer or is a non-existing picture, or invalid
                           longTermFrameIdx given
------------------------------------------------------------------------------*/
fn Mmcop3(
    dpb: &mut dpbStorage_t,
    currPicNum: u32,
    differenceOfPicNums: u32,
    longTermFrameIdx: u32,
) -> u32 {
    let index: i32;
    let picNum: i32;
    let mut i: u32;

    if (dpb.maxLongTermFrameIdx == NO_LONG_TERM_FRAME_INDICES)
        || (longTermFrameIdx > dpb.maxLongTermFrameIdx)
    {
        return HANTRO_NOK;
    }

    /* check if a long term picture with the same longTermFrameIdx already
     * exist and remove it if necessary */
    unsafe {
        i = 0;
        while i < dpb.maxRefFrames {
            if IS_LONG_TERM(&*dpb.buffer.add(i as usize))
                && (*dpb.buffer.add(i as usize)).picNum as u32 == longTermFrameIdx
            {
                SET_UNUSED(&mut *dpb.buffer.add(i as usize));
                dpb.numRefFrames = dpb.numRefFrames.wrapping_sub(1);
                if (*dpb.buffer.add(i as usize)).toBeDisplayed == 0 {
                    dpb.fullness = dpb.fullness.wrapping_sub(1);
                }
                break;
            }
            i += 1;
        }
    }

    picNum = currPicNum as i32 - differenceOfPicNums as i32;

    index = FindDpbPic(dpb, picNum, HANTRO_TRUE);
    if index < 0 {
        return HANTRO_NOK;
    }
    unsafe {
        if !IS_EXISTING(&*dpb.buffer.add(index as usize)) {
            return HANTRO_NOK;
        }

        (*dpb.buffer.add(index as usize)).status = LONG_TERM;
        (*dpb.buffer.add(index as usize)).picNum = longTermFrameIdx as i32;
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------
    Function: Mmcop4

        Functional description:
            Function to set maxLongTermFrameIdx,
            memory_management_control_operation equal to 4

        Returns:
            HANTRO_OK      success
------------------------------------------------------------------------------*/
fn Mmcop4(dpb: &mut dpbStorage_t, maxLongTermFrameIdx: u32) -> u32 {
    let mut i: u32;

    dpb.maxLongTermFrameIdx = maxLongTermFrameIdx;

    unsafe {
        i = 0;
        while i < dpb.maxRefFrames {
            if IS_LONG_TERM(&*dpb.buffer.add(i as usize))
                && (((*dpb.buffer.add(i as usize)).picNum as u32 > maxLongTermFrameIdx)
                    || (dpb.maxLongTermFrameIdx == NO_LONG_TERM_FRAME_INDICES))
            {
                SET_UNUSED(&mut *dpb.buffer.add(i as usize));
                dpb.numRefFrames = dpb.numRefFrames.wrapping_sub(1);
                if (*dpb.buffer.add(i as usize)).toBeDisplayed == 0 {
                    dpb.fullness = dpb.fullness.wrapping_sub(1);
                }
            }
            i += 1;
        }
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------
    Function: Mmcop5

        Functional description:
            Function to mark all reference pictures unused for reference and
            set maxLongTermFrameIdx to NO_LONG_TERM_FRAME_INDICES,
            memory_management_control_operation equal to 5. Function flushes
            the buffer and places all pictures that are needed for display into
            the output buffer.

        Returns:
            HANTRO_OK      success
------------------------------------------------------------------------------*/
fn Mmcop5(dpb: &mut dpbStorage_t) -> u32 {
    let mut i: u32;

    unsafe {
        i = 0;
        while i < 16 {
            if IS_REFERENCE(&*dpb.buffer.add(i as usize)) {
                SET_UNUSED(&mut *dpb.buffer.add(i as usize));
                if (*dpb.buffer.add(i as usize)).toBeDisplayed == 0 {
                    dpb.fullness = dpb.fullness.wrapping_sub(1);
                }
            }
            i += 1;
        }
    }

    /* output all pictures */
    while OutputPicture(dpb) == HANTRO_OK {}
    dpb.numRefFrames = 0;
    dpb.maxLongTermFrameIdx = NO_LONG_TERM_FRAME_INDICES;
    dpb.prevRefFrameNum = 0;

    HANTRO_OK
}

/*------------------------------------------------------------------------------
    Function: Mmcop6

        Functional description:
            Function to assign longTermFrameIdx to the current picture,
            memory_management_control_operation equal to 6

        Returns:
            HANTRO_OK      success
            HANTRO_NOK     invalid longTermFrameIdx or no room for current
                           picture in the buffer
------------------------------------------------------------------------------*/
fn Mmcop6(dpb: &mut dpbStorage_t, frameNum: u32, picOrderCnt: i32, longTermFrameIdx: u32) -> u32 {
    let mut i: u32;

    if (dpb.maxLongTermFrameIdx == NO_LONG_TERM_FRAME_INDICES)
        || (longTermFrameIdx > dpb.maxLongTermFrameIdx)
    {
        return HANTRO_NOK;
    }

    /* check if a long term picture with the same longTermFrameIdx already
     * exist and remove it if necessary */
    unsafe {
        i = 0;
        while i < dpb.maxRefFrames {
            if IS_LONG_TERM(&*dpb.buffer.add(i as usize))
                && (*dpb.buffer.add(i as usize)).picNum as u32 == longTermFrameIdx
            {
                SET_UNUSED(&mut *dpb.buffer.add(i as usize));
                dpb.numRefFrames = dpb.numRefFrames.wrapping_sub(1);
                if (*dpb.buffer.add(i as usize)).toBeDisplayed == 0 {
                    dpb.fullness = dpb.fullness.wrapping_sub(1);
                }
                break;
            }
            i += 1;
        }
    }

    if dpb.numRefFrames < dpb.maxRefFrames {
        unsafe {
            (*dpb.currentOut).frameNum = frameNum;
            (*dpb.currentOut).picNum = longTermFrameIdx as i32;
            (*dpb.currentOut).picOrderCnt = picOrderCnt;
            (*dpb.currentOut).status = LONG_TERM;
            if dpb.noReordering != 0 {
                (*dpb.currentOut).toBeDisplayed = HANTRO_FALSE;
            } else {
                (*dpb.currentOut).toBeDisplayed = HANTRO_TRUE;
            }
        }
        dpb.numRefFrames += 1;
        dpb.fullness += 1;
        HANTRO_OK
    }
    /* if there is no room, return an error */
    else {
        HANTRO_NOK
    }
}

/*------------------------------------------------------------------------------
    Function: h264bsdMarkDecRefPic

        Functional description:
            Function to perform reference picture marking process. This
            function should be called both for reference and non-reference
            pictures.  Non-reference pictures shall have mark pointer set to
            NULL.

        Outputs:
            dpb         'buffer' modified, possible output frames placed into
                        'outBuf'

        Returns:
            HANTRO_OK   success
            HANTRO_NOK  failure
------------------------------------------------------------------------------*/
pub unsafe fn h264bsdMarkDecRefPic(
    dpb: &mut dpbStorage_t,
    mark: *mut decRefPicMarking_t,
    image: *const image_t,
    frameNum: u32,
    picOrderCnt: i32,
    isIdr: u32,
    picId: u32,
    numErrMbs: u32,
) -> u32 {
    /* PORT NOTE: manifest names the C's `currentPicId` param `picId`. */
    let mut frameNum = frameNum;
    let mut i: u32;
    let mut status: u32;
    let mut markedAsLongTerm: u32;
    let toBeDisplayed: u32;

    if (*image).data != (*dpb.currentOut).data {
        return HANTRO_NOK;
    }

    dpb.lastContainsMmco5 = HANTRO_FALSE;
    status = HANTRO_OK;

    toBeDisplayed = if dpb.noReordering != 0 {
        HANTRO_FALSE
    } else {
        HANTRO_TRUE
    };

    /* non-reference picture, stored for display reordering purposes */
    if mark.is_null() {
        (*dpb.currentOut).status = UNUSED;
        (*dpb.currentOut).frameNum = frameNum;
        (*dpb.currentOut).picNum = frameNum as i32;
        (*dpb.currentOut).picOrderCnt = picOrderCnt;
        (*dpb.currentOut).toBeDisplayed = toBeDisplayed;
        if dpb.noReordering == 0 {
            dpb.fullness += 1;
        }
    }
    /* IDR picture */
    else if isIdr != 0 {
        /* h264bsdCheckGapsInFrameNum not called for IDR pictures -> have to
         * reset numOut and outIndex here */
        dpb.numOut = 0;
        dpb.outIndex = 0;

        /* flush the buffer */
        Mmcop5(dpb);
        /* if noOutputOfPriorPicsFlag was set -> the pictures preceding the
         * IDR picture shall not be output -> set output buffer empty */
        if (*mark).noOutputOfPriorPicsFlag != 0 || dpb.noReordering != 0 {
            dpb.numOut = 0;
            dpb.outIndex = 0;
        }

        if (*mark).longTermReferenceFlag != 0 {
            (*dpb.currentOut).status = LONG_TERM;
            dpb.maxLongTermFrameIdx = 0;
        } else {
            (*dpb.currentOut).status = SHORT_TERM;
            dpb.maxLongTermFrameIdx = NO_LONG_TERM_FRAME_INDICES;
        }
        (*dpb.currentOut).frameNum = 0;
        (*dpb.currentOut).picNum = 0;
        (*dpb.currentOut).picOrderCnt = 0;
        (*dpb.currentOut).toBeDisplayed = toBeDisplayed;
        dpb.fullness = 1;
        dpb.numRefFrames = 1;
    }
    /* reference picture */
    else {
        markedAsLongTerm = HANTRO_FALSE;
        if (*mark).adaptiveRefPicMarkingModeFlag != 0 {
            i = 0;
            while (*mark).operation[i as usize].memoryManagementControlOperation != 0 {
                match (*mark).operation[i as usize].memoryManagementControlOperation {
                    1 => {
                        status = Mmcop1(
                            dpb,
                            frameNum,
                            (*mark).operation[i as usize].differenceOfPicNums,
                        );
                    }

                    2 => {
                        status = Mmcop2(dpb, (*mark).operation[i as usize].longTermPicNum);
                    }

                    3 => {
                        status = Mmcop3(
                            dpb,
                            frameNum,
                            (*mark).operation[i as usize].differenceOfPicNums,
                            (*mark).operation[i as usize].longTermFrameIdx,
                        );
                    }

                    4 => {
                        status = Mmcop4(dpb, (*mark).operation[i as usize].maxLongTermFrameIdx);
                    }

                    5 => {
                        status = Mmcop5(dpb);
                        dpb.lastContainsMmco5 = HANTRO_TRUE;
                        frameNum = 0;
                    }

                    6 => {
                        status = Mmcop6(
                            dpb,
                            frameNum,
                            picOrderCnt,
                            (*mark).operation[i as usize].longTermFrameIdx,
                        );
                        if status == HANTRO_OK {
                            markedAsLongTerm = HANTRO_TRUE;
                        }
                    }

                    /* invalid memory management control operation */
                    _ => {
                        status = HANTRO_NOK;
                    }
                }
                if status != HANTRO_OK {
                    break;
                }
                i += 1;
            }
        } else {
            status = SlidingWindowRefPicMarking(dpb);
        }
        /* if current picture was not marked as long-term reference by
         * memory management control operation 6 -> mark current as short
         * term and insert it into dpb (if there is room) */
        if markedAsLongTerm == 0 {
            if dpb.numRefFrames < dpb.maxRefFrames {
                (*dpb.currentOut).frameNum = frameNum;
                (*dpb.currentOut).picNum = frameNum as i32;
                (*dpb.currentOut).picOrderCnt = picOrderCnt;
                (*dpb.currentOut).status = SHORT_TERM;
                (*dpb.currentOut).toBeDisplayed = toBeDisplayed;
                dpb.fullness += 1;
                dpb.numRefFrames += 1;
            }
            /* no room */
            else {
                status = HANTRO_NOK;
            }
        }
    }

    (*dpb.currentOut).isIdr = isIdr;
    (*dpb.currentOut).picId = picId;
    (*dpb.currentOut).numErrMbs = numErrMbs;

    /* dpb was initialized to not to reorder the pictures -> output current
     * picture immediately */
    if dpb.noReordering != 0 {
        (*dpb.outBuf.add(dpb.numOut as usize)).data = (*dpb.currentOut).data;
        (*dpb.outBuf.add(dpb.numOut as usize)).isIdr = (*dpb.currentOut).isIdr;
        (*dpb.outBuf.add(dpb.numOut as usize)).picId = (*dpb.currentOut).picId;
        (*dpb.outBuf.add(dpb.numOut as usize)).numErrMbs = (*dpb.currentOut).numErrMbs;
        dpb.numOut += 1;
    } else {
        /* output pictures if buffer full */
        while dpb.fullness > dpb.dpbSize {
            i = OutputPicture(dpb);
        }
    }

    /* sort dpb */
    ShellSort(dpb.buffer, dpb.dpbSize + 1);

    status
}

/*------------------------------------------------------------------------------
    Function: h264bsdGetRefPicData

        Functional description:
            Function to get reference picture data from the reference picture
            list

        Returns:
            pointer to desired reference picture data
            NULL if invalid index or non-existing picture referred
------------------------------------------------------------------------------*/
pub unsafe fn h264bsdGetRefPicData(dpb: &dpbStorage_t, index: u32) -> *mut u8 {
    if index > 16 || (*dpb.list.add(index as usize)).is_null() {
        core::ptr::null_mut()
    } else if !IS_EXISTING(&**dpb.list.add(index as usize)) {
        core::ptr::null_mut()
    } else {
        (**dpb.list.add(index as usize)).data
    }
}

/*------------------------------------------------------------------------------
    Function: h264bsdAllocateDpbImage

        Functional description:
            function to allocate memory for a image. This function does not
            really allocate any memory but reserves one of the buffer
            positions for decoding of current picture

        Returns:
            pointer to memory area for the image
------------------------------------------------------------------------------*/
pub unsafe fn h264bsdAllocateDpbImage(dpb: &mut dpbStorage_t) -> *mut u8 {
    dpb.currentOut = dpb.buffer.add(dpb.dpbSize as usize);

    (*dpb.currentOut).data
}

/*------------------------------------------------------------------------------
    Function: SlidingWindowRefPicMarking

        Functional description:
            Function to perform sliding window refence picture marking process.

        Outputs:
            HANTRO_OK      success
            HANTRO_NOK     failure, no short-term reference frame found that
                           could be marked unused
------------------------------------------------------------------------------*/
fn SlidingWindowRefPicMarking(dpb: &mut dpbStorage_t) -> u32 {
    let mut index: i32;
    let mut picNum: i32;
    let mut i: u32;

    if dpb.numRefFrames < dpb.maxRefFrames {
        return HANTRO_OK;
    } else {
        index = -1;
        picNum = 0;
        /* find the oldest short term picture */
        unsafe {
            i = 0;
            while i < dpb.numRefFrames {
                if IS_SHORT_TERM(&*dpb.buffer.add(i as usize)) {
                    if (*dpb.buffer.add(i as usize)).picNum < picNum || index == -1 {
                        index = i as i32;
                        picNum = (*dpb.buffer.add(i as usize)).picNum;
                    }
                }
                i += 1;
            }
            if index >= 0 {
                SET_UNUSED(&mut *dpb.buffer.add(index as usize));
                dpb.numRefFrames = dpb.numRefFrames.wrapping_sub(1);
                if (*dpb.buffer.add(index as usize)).toBeDisplayed == 0 {
                    dpb.fullness = dpb.fullness.wrapping_sub(1);
                }

                return HANTRO_OK;
            }
        }
    }

    HANTRO_NOK
}

/*------------------------------------------------------------------------------
    Function: h264bsdInitDpb

        Functional description:
            Function to initialize DPB. Reserves memories for the buffer,
            reference picture list and output buffer. dpbSize indicates
            the maximum DPB size indicated by the levelIdc in the stream.
            If noReordering flag is FALSE the DPB stores dpbSize pictures
            for display reordering purposes. On the other hand, if the
            flag is TRUE the DPB only stores maxRefFrames reference pictures
            and outputs all the pictures immediately.

        Returns:
            HANTRO_OK       success
            MEMORY_ALLOCATION_ERROR if memory allocation failed
------------------------------------------------------------------------------*/
pub unsafe fn h264bsdInitDpb(
    dpb: &mut dpbStorage_t,
    picSizeInMbs: u32,
    dpbSize: u32,
    numRefFrames: u32,
    maxFrameNum: u32,
    noReordering: u32,
) -> u32 {
    /* PORT NOTE: manifest names the C's `maxRefFrames` param `numRefFrames`. */
    let mut i: u32;

    dpb.maxLongTermFrameIdx = NO_LONG_TERM_FRAME_INDICES;
    dpb.maxRefFrames = MAX!(numRefFrames, 1);
    if noReordering != 0 {
        dpb.dpbSize = dpb.maxRefFrames;
    } else {
        dpb.dpbSize = dpbSize;
    }
    dpb.maxFrameNum = maxFrameNum;
    dpb.noReordering = noReordering;
    dpb.fullness = 0;
    dpb.numRefFrames = 0;
    dpb.prevRefFrameNum = 0;

    dpb.buffer = dpb
        .allocator
        .alloc_n::<dpbPicture_t>((MAX_NUM_REF_IDX_L0_ACTIVE + 1) as usize);
    if dpb.buffer.is_null() {
        return MEMORY_ALLOCATION_ERROR;
    }
    core::ptr::write_bytes(
        dpb.buffer as *mut u8,
        0,
        (MAX_NUM_REF_IDX_L0_ACTIVE + 1) as usize * core::mem::size_of::<dpbPicture_t>(),
    );
    i = 0;
    while i < dpb.dpbSize + 1 {
        /* Allocate needed amount of memory, which is:
         * image size + 32 + 15, where 32 cames from the fact that in ARM OpenMax
         * DL implementation Functions may read beyond the end of an array,
         * by a maximum of 32 bytes. And +15 cames for the need to align memory
         * to 16-byte boundary */
        (*dpb.buffer.add(i as usize)).pAllocatedData = dpb
            .allocator
            .alloc_n::<u8>((picSizeInMbs * 384 + 32 + 15) as usize);
        if (*dpb.buffer.add(i as usize)).pAllocatedData.is_null() {
            return MEMORY_ALLOCATION_ERROR;
        }

        /* ALIGN(ptr, 16) */
        (*dpb.buffer.add(i as usize)).data =
            (((*dpb.buffer.add(i as usize)).pAllocatedData as usize + 15) & !15usize) as *mut u8;
        i += 1;
    }

    dpb.list = dpb
        .allocator
        .alloc_n::<*mut dpbPicture_t>((MAX_NUM_REF_IDX_L0_ACTIVE + 1) as usize);
    dpb.outBuf = dpb
        .allocator
        .alloc_n::<dpbOutPicture_t>((dpb.dpbSize + 1) as usize);

    if dpb.list.is_null() || dpb.outBuf.is_null() {
        return MEMORY_ALLOCATION_ERROR;
    }

    core::ptr::write_bytes(
        dpb.list as *mut u8,
        0,
        (MAX_NUM_REF_IDX_L0_ACTIVE + 1) as usize * core::mem::size_of::<*mut dpbPicture_t>(),
    );

    dpb.numOut = 0;
    dpb.outIndex = 0;

    HANTRO_OK
}

/*------------------------------------------------------------------------------
    Function: h264bsdResetDpb

        Functional description:
            Function to reset DPB. This function should be called when an IDR
            slice (other than the first) activates new sequence parameter set.
            Function calls h264bsdFreeDpb to free old allocated memories and
            h264bsdInitDpb to re-initialize the DPB. Same inputs, outputs and
            returns as for h264bsdInitDpb.
------------------------------------------------------------------------------*/
pub unsafe fn h264bsdResetDpb(
    dpb: &mut dpbStorage_t,
    picSizeInMbs: u32,
    dpbSize: u32,
    numRefFrames: u32,
    maxFrameNum: u32,
    noReordering: u32,
) -> u32 {
    h264bsdFreeDpb(dpb);

    h264bsdInitDpb(dpb, picSizeInMbs, dpbSize, numRefFrames, maxFrameNum, noReordering)
}

/*------------------------------------------------------------------------------
    Function: h264bsdInitRefPicList

        Functional description:
            Function to initialize reference picture list. Function just
            sets pointers in the list according to pictures in the buffer.
            The buffer is assumed to contain pictures sorted according to
            what the H.264 standard says about initial reference picture list.

        Outputs:
            dpb     'list' field initialized
------------------------------------------------------------------------------*/
pub unsafe fn h264bsdInitRefPicList(dpb: &mut dpbStorage_t) {
    let mut i: u32;

    i = 0;
    while i < dpb.numRefFrames {
        *dpb.list.add(i as usize) = dpb.buffer.add(i as usize);
        i += 1;
    }
}

/*------------------------------------------------------------------------------
    Function: FindDpbPic

        Functional description:
            Function to find a reference picture from the buffer. The picture
            to be found is identified by picNum and isShortTerm flag.

        Returns:
            index of the picture in the buffer
            -1 if the specified picture was not found in the buffer
------------------------------------------------------------------------------*/
fn FindDpbPic(dpb: &mut dpbStorage_t, picNum: i32, isShortTerm: u32) -> i32 {
    let mut i: u32 = 0;
    let mut found: u32 = HANTRO_FALSE;

    unsafe {
        if isShortTerm != 0 {
            while i < dpb.maxRefFrames && found == 0 {
                if IS_SHORT_TERM(&*dpb.buffer.add(i as usize))
                    && (*dpb.buffer.add(i as usize)).picNum == picNum
                {
                    found = HANTRO_TRUE;
                } else {
                    i += 1;
                }
            }
        } else {
            while i < dpb.maxRefFrames && found == 0 {
                if IS_LONG_TERM(&*dpb.buffer.add(i as usize))
                    && (*dpb.buffer.add(i as usize)).picNum == picNum
                {
                    found = HANTRO_TRUE;
                } else {
                    i += 1;
                }
            }
        }
    }

    if found != 0 {
        i as i32
    } else {
        -1
    }
}

/*------------------------------------------------------------------------------
    Function: SetPicNums

        Functional description:
            Function to set picNum values for short-term pictures in the
            buffer. Numbering of pictures is based on frame numbers and as
            frame numbers are modulo maxFrameNum -> frame numbers of older
            pictures in the buffer may be bigger than the currFrameNum.
            picNums will be set so that current frame has the largest picNum
            and all the short-term frames in the buffer will get smaller picNum
            representing their "distance" from the current frame. This
            function kind of maps the modulo arithmetic back to normal.
------------------------------------------------------------------------------*/
fn SetPicNums(dpb: &mut dpbStorage_t, currFrameNum: u32) {
    let mut i: u32;
    let mut frameNumWrap: i32;

    unsafe {
        i = 0;
        while i < dpb.numRefFrames {
            if IS_SHORT_TERM(&*dpb.buffer.add(i as usize)) {
                if (*dpb.buffer.add(i as usize)).frameNum > currFrameNum {
                    frameNumWrap =
                        (*dpb.buffer.add(i as usize)).frameNum as i32 - dpb.maxFrameNum as i32;
                } else {
                    frameNumWrap = (*dpb.buffer.add(i as usize)).frameNum as i32;
                }
                (*dpb.buffer.add(i as usize)).picNum = frameNumWrap;
            }
            i += 1;
        }
    }
}

/*------------------------------------------------------------------------------
    Function: h264bsdCheckGapsInFrameNum

        Functional description:
            Function to check gaps in frame_num and generate non-existing
            (short term) reference pictures if necessary. This function should
            be called only for non-IDR pictures.

        Outputs:
            dpb         'buffer' possibly modified by inserting non-existing
                        pictures with sliding window marking process

        Returns:
            HANTRO_OK   success
            HANTRO_NOK  error in sliding window reference picture marking or
                        frameNum equal to previous reference frame used for
                        a reference picture
------------------------------------------------------------------------------*/
pub unsafe fn h264bsdCheckGapsInFrameNum(
    dpb: &mut dpbStorage_t,
    frameNum: u32,
    isRefPic: u32,
    gapsAllowed: u32,
) -> u32 {
    let mut unUsedShortTermFrameNum: u32;
    let tmp: *mut u8;

    dpb.numOut = 0;
    dpb.outIndex = 0;

    if gapsAllowed == 0 {
        return HANTRO_OK;
    }

    if (frameNum != dpb.prevRefFrameNum)
        && (frameNum != urem(dpb.prevRefFrameNum + 1, dpb.maxFrameNum))
    {
        unUsedShortTermFrameNum = urem(dpb.prevRefFrameNum + 1, dpb.maxFrameNum);

        /* store data pointer of last buffer position to be used as next
         * "allocated" data pointer if last buffer position after this process
         * contains data pointer located in outBuf (buffer placed in the output
         * shall not be overwritten by the current picture) */
        tmp = (*dpb.buffer.add(dpb.dpbSize as usize)).data;
        loop {
            SetPicNums(dpb, unUsedShortTermFrameNum);

            if SlidingWindowRefPicMarking(dpb) != HANTRO_OK {
                return HANTRO_NOK;
            }

            /* output pictures if buffer full */
            while dpb.fullness >= dpb.dpbSize {
                OutputPicture(dpb);
            }

            /* add to end of list */
            (*dpb.buffer.add(dpb.dpbSize as usize)).status = NON_EXISTING;
            (*dpb.buffer.add(dpb.dpbSize as usize)).frameNum = unUsedShortTermFrameNum;
            (*dpb.buffer.add(dpb.dpbSize as usize)).picNum = unUsedShortTermFrameNum as i32;
            (*dpb.buffer.add(dpb.dpbSize as usize)).picOrderCnt = 0;
            (*dpb.buffer.add(dpb.dpbSize as usize)).toBeDisplayed = HANTRO_FALSE;
            dpb.fullness += 1;
            dpb.numRefFrames += 1;

            /* sort the buffer */
            ShellSort(dpb.buffer, dpb.dpbSize + 1);

            unUsedShortTermFrameNum = urem(unUsedShortTermFrameNum + 1, dpb.maxFrameNum);

            if unUsedShortTermFrameNum == frameNum {
                break;
            }
        }

        /* pictures placed in output buffer -> check that 'data' in
         * buffer position dpbSize is not in the output buffer (this will be
         * "allocated" by h264bsdAllocateDpbImage). If it is -> exchange data
         * pointer with the one stored in the beginning */
        if dpb.numOut != 0 {
            let mut i: u32;

            i = 0;
            while i < dpb.numOut {
                if (*dpb.outBuf.add(i as usize)).data
                    == (*dpb.buffer.add(dpb.dpbSize as usize)).data
                {
                    /* find buffer position containing data pointer stored in
                     * tmp */
                    /* PORT NOTE: the C reuses loop variable `i` for the inner
                     * loop; preserved verbatim. */
                    i = 0;
                    while i < dpb.dpbSize {
                        if (*dpb.buffer.add(i as usize)).data == tmp {
                            (*dpb.buffer.add(i as usize)).data =
                                (*dpb.buffer.add(dpb.dpbSize as usize)).data;
                            (*dpb.buffer.add(dpb.dpbSize as usize)).data = tmp;
                            break;
                        }
                        i += 1;
                    }
                    break;
                }
                i += 1;
            }
        }
    }
    /* frameNum for reference pictures shall not be the same as for previous
     * reference picture, otherwise accesses to pictures in the buffer cannot
     * be solved unambiguously */
    else if isRefPic != 0 && frameNum == dpb.prevRefFrameNum {
        return HANTRO_NOK;
    }

    /* save current frame_num in prevRefFrameNum. For non-reference frame
     * prevFrameNum is set to frame number of last non-existing frame above */
    if isRefPic != 0 {
        dpb.prevRefFrameNum = frameNum;
    } else if frameNum != dpb.prevRefFrameNum {
        dpb.prevRefFrameNum = urem(frameNum + dpb.maxFrameNum - 1, dpb.maxFrameNum);
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------
    Function: FindSmallestPicOrderCnt

        Functional description:
            Function to find picture with smallest picture order count. This
            will be the next picture in display order.

        Returns:
            pointer to the picture, NULL if no pictures to be displayed
------------------------------------------------------------------------------*/
fn FindSmallestPicOrderCnt(dpb: &mut dpbStorage_t) -> *mut dpbPicture_t {
    let mut i: u32;
    let mut picOrderCnt: i32;
    let mut tmp: *mut dpbPicture_t;

    picOrderCnt = 0x7FFFFFFF;
    tmp = core::ptr::null_mut();

    unsafe {
        i = 0;
        while i <= dpb.dpbSize {
            if (*dpb.buffer.add(i as usize)).toBeDisplayed != 0
                && ((*dpb.buffer.add(i as usize)).picOrderCnt < picOrderCnt)
            {
                tmp = dpb.buffer.add(i as usize);
                picOrderCnt = (*dpb.buffer.add(i as usize)).picOrderCnt;
            }
            i += 1;
        }
    }

    tmp
}

/*------------------------------------------------------------------------------
    Function: OutputPicture

        Functional description:
            Function to put next display order picture into the output buffer.

        Returns:
            HANTRO_OK      success
            HANTRO_NOK     no pictures to display
------------------------------------------------------------------------------*/
fn OutputPicture(dpb: &mut dpbStorage_t) -> u32 {
    let tmp: *mut dpbPicture_t;

    if dpb.noReordering != 0 {
        return HANTRO_NOK;
    }

    tmp = FindSmallestPicOrderCnt(dpb);

    /* no pictures to be displayed */
    if tmp.is_null() {
        return HANTRO_NOK;
    }

    unsafe {
        (*dpb.outBuf.add(dpb.numOut as usize)).data = (*tmp).data;
        (*dpb.outBuf.add(dpb.numOut as usize)).isIdr = (*tmp).isIdr;
        (*dpb.outBuf.add(dpb.numOut as usize)).picId = (*tmp).picId;
        (*dpb.outBuf.add(dpb.numOut as usize)).numErrMbs = (*tmp).numErrMbs;
        dpb.numOut += 1;

        (*tmp).toBeDisplayed = HANTRO_FALSE;
        if !IS_REFERENCE(&*tmp) {
            dpb.fullness = dpb.fullness.wrapping_sub(1);
        }
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------
    Function: h264bsdDpbOutputPicture

        Functional description:
            Function to get next display order picture from the output buffer.

        Return:
            pointer to output picture structure, NULL if no pictures to
            display
------------------------------------------------------------------------------*/
pub unsafe fn h264bsdDpbOutputPicture(dpb: &mut dpbStorage_t) -> *mut dpbOutPicture_t {
    if dpb.outIndex < dpb.numOut {
        let out = dpb.outBuf.add(dpb.outIndex as usize);
        dpb.outIndex += 1;
        out
    } else {
        core::ptr::null_mut()
    }
}

/*------------------------------------------------------------------------------
    Function: h264bsdFlushDpb

        Functional description:
            Function to flush the DPB. Function puts all pictures needed for
            display into the output buffer. This function shall be called in
            the end of the stream to obtain pictures buffered for display
            re-ordering purposes.
------------------------------------------------------------------------------*/
pub unsafe fn h264bsdFlushDpb(dpb: &mut dpbStorage_t) {
    /* don't do anything if buffer not reserved */
    if !dpb.buffer.is_null() {
        dpb.flushed = 1;
        /* output all pictures */
        while OutputPicture(dpb) == HANTRO_OK {}
    }
}

/*------------------------------------------------------------------------------
    Function: h264bsdFreeDpb

        Functional description:
            Function to free memories reserved for the DPB.
------------------------------------------------------------------------------*/
pub unsafe fn h264bsdFreeDpb(dpb: &mut dpbStorage_t) {
    let mut i: u32;

    if !dpb.buffer.is_null() {
        i = 0;
        while i < dpb.dpbSize + 1 {
            dpb.allocator
                .free_ptr((*dpb.buffer.add(i as usize)).pAllocatedData);
            (*dpb.buffer.add(i as usize)).pAllocatedData = core::ptr::null_mut();
            i += 1;
        }
    }
    dpb.allocator.free_ptr(dpb.buffer);
    dpb.buffer = core::ptr::null_mut();
    dpb.allocator.free_ptr(dpb.list);
    dpb.list = core::ptr::null_mut();
    dpb.allocator.free_ptr(dpb.outBuf);
    dpb.outBuf = core::ptr::null_mut();
}

/*------------------------------------------------------------------------------
    Function: ShellSort

        Functional description:
            Sort pictures in the buffer. Function implements Shell's method,
            i.e. diminishing increment sort. See e.g. "Numerical Recipes in C"
            for more information.
------------------------------------------------------------------------------*/
unsafe fn ShellSort(pPic: *mut dpbPicture_t, num: u32) {
    let mut i: u32;
    let mut j: u32;
    let mut step: u32;

    step = 7;

    while step != 0 {
        i = step;
        while i < num {
            /* struct copy (dpbPicture_t is plain data, no Drop) */
            let tmpPic: dpbPicture_t = core::ptr::read(pPic.add(i as usize));
            j = i;
            while j >= step && ComparePictures(pPic.add((j - step) as usize), &tmpPic) > 0 {
                core::ptr::write(
                    pPic.add(j as usize),
                    core::ptr::read(pPic.add((j - step) as usize)),
                );
                j -= step;
            }
            core::ptr::write(pPic.add(j as usize), tmpPic);
            i += 1;
        }
        step >>= 1;
    }
}
