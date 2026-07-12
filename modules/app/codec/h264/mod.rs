// H.264 baseline-profile decoder — mechanical Rust port of h264bsd
// (github.com/oneam/h264bsd, extracted from the Android Open Source
// Project's On2/Hantro decoder; Apache-2.0, same as this repo).
//
// Port discipline (see .context/h264_mkv_codec_plan.md):
// - C names kept VERBATIM (functions, structs, fields) so any decoded
//   YUV divergence can be diffed against the C reference stage by
//   stage. Hence the non_snake_case/non_camel_case allowances.
// - C enums used arithmetically become u32 consts / type aliases.
// - Struct-internal links (neighbour mbs, picture data, DPB lists)
//   stay raw pointers exactly as in C; top-level function parameters
//   use references. Pixel loops use raw pointers as in C.
// - Where C ALLOCATE()s, the port calls an `Allocator` (module arena
//   on target, malloc shim in the host replica). NOTE: the arena
//   allocator's free is a no-op; parameter-set churn leaks by design
//   until a small pool is added (avcC feeds each set exactly once).
// - Decode output is normative: the port must be BIT-EXACT vs the C
//   reference (which is byte-exact vs ffmpeg on the fixture corpus).
//
// This file is the shared foundation: types from all h264bsd headers,
// cfg/util constants, the bit reader (h264bsd_stream.c), util
// (h264bsd_util.c) and exp-golomb decode (h264bsd_vlc.c). The
// remaining .c files are ported 1:1 into the sibling files declared
// at the bottom.

#![allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code,
    reason = "mechanical port of h264bsd keeps C names verbatim for stage-by-stage parity diffing against the reference decoder"
)]

// ============================================================================
// Return codes / cfg (h264bsd_util.h, h264bsd_cfg.h)
// ============================================================================

pub const HANTRO_OK: u32 = 0;
pub const HANTRO_NOK: u32 = 1;
pub const HANTRO_TRUE: u32 = 1;
pub const HANTRO_FALSE: u32 = 0;

pub const MEMORY_ALLOCATION_ERROR: u32 = 0xFFFF;
pub const PARAM_SET_ERROR: u32 = 0xFFF0;
pub const END_OF_STREAM: u32 = 0xFFFF_FFFF;
pub const EMPTY_RESIDUAL_INDICATOR: u32 = 0xFF_FFFF;

pub const MAX_NUM_REF_PICS: usize = 16;
pub const MAX_NUM_SLICE_GROUPS: usize = 8;
pub const MAX_NUM_SEQ_PARAM_SETS: usize = 32;
pub const MAX_NUM_PIC_PARAM_SETS: usize = 256;
pub const MAX_CPB_CNT: usize = 32;

pub const NO_LONG_TERM_FRAME_INDICES: u32 = 0xFFFF;
pub const MAX_NUM_MMC_OPERATIONS: usize = 2 * MAX_NUM_REF_PICS + 2 + 1;

/// h264bsdDecode return values (h264bsd_decoder.h).
pub const H264BSD_RDY: u32 = 0;
pub const H264BSD_PIC_RDY: u32 = 1;
pub const H264BSD_HDRS_RDY: u32 = 2;
pub const H264BSD_ERROR: u32 = 3;
pub const H264BSD_PARAM_SET_ERROR: u32 = 4;
pub const H264BSD_MEMALLOC_ERROR: u32 = 5;

// C macros MARK_RESIDUAL_EMPTY / IS_RESIDUAL_EMPTY operate on
// i32 residual[16] blocks.
#[inline(always)]
pub fn MARK_RESIDUAL_EMPTY(residual: &mut [i32]) {
    residual[0] = EMPTY_RESIDUAL_INDICATOR as i32;
}
#[inline(always)]
pub fn IS_RESIDUAL_EMPTY(residual: &[i32]) -> bool {
    residual[0] == EMPTY_RESIDUAL_INDICATOR as i32
}

// Type-generic C macros → macro_rules (used across all port files).
#[macro_export]
macro_rules! MIN {
    ($a:expr, $b:expr) => {{ let a = $a; let b = $b; if a < b { a } else { b } }};
}
#[macro_export]
macro_rules! MAX {
    ($a:expr, $b:expr) => {{ let a = $a; let b = $b; if a > b { a } else { b } }};
}
#[macro_export]
macro_rules! ABS {
    ($a:expr) => {{ let a = $a; if a < 0 { -a } else { a } }};
}
#[macro_export]
macro_rules! CLIP3 {
    ($x:expr, $y:expr, $z:expr) => {{
        let x = $x; let y = $y; let z = $z;
        if z < x { x } else if z > y { y } else { z }
    }};
}
#[macro_export]
macro_rules! CLIP1 {
    ($z:expr) => {{ let z = $z; if z < 0 { 0 } else if z > 255 { 255 } else { z } }};
}
// (The macros are #[macro_export]-hoisted to the crate root and in
// textual scope for every sibling module declared below.)

/// Division/remainder with a zero-divisor guard. PIC module builds
/// link with no panic machinery, so every runtime division must be
/// provably non-panicking; divisor 0 (malformed stream) yields 0,
/// matching "garbage in, bounded garbage out" concealment behaviour
/// (div-by-zero is UB in the C original).
#[inline(always)]
pub fn udiv(a: u32, b: u32) -> u32 {
    if b == 0 { 0 } else { a / b }
}
#[inline(always)]
pub fn urem(a: u32, b: u32) -> u32 {
    if b == 0 { 0 } else { a % b }
}

// ============================================================================
// Allocator (replaces C ALLOCATE/FREE)
// ============================================================================

/// Allocation hooks. On target this is a bump allocator over the
/// module arena (free is a no-op); the host replica backs it with
/// malloc/free. Returned pointers must be 8-byte aligned and zeroed
/// is NOT guaranteed (C code memsets where it matters).
#[derive(Clone, Copy)]
pub struct Allocator {
    pub ctx: *mut u8,
    pub alloc: unsafe fn(ctx: *mut u8, bytes: usize) -> *mut u8,
    pub free: unsafe fn(ctx: *mut u8, ptr: *mut u8),
}

impl Allocator {
    /// C `ALLOCATE(ptr, count, type)` equivalent; null on failure.
    #[inline]
    pub unsafe fn alloc_n<T>(&self, count: usize) -> *mut T {
        (self.alloc)(self.ctx, count * core::mem::size_of::<T>()) as *mut T
    }
    #[inline]
    pub unsafe fn free_ptr<T>(&self, ptr: *mut T) {
        if !ptr.is_null() {
            (self.free)(self.ctx, ptr as *mut u8);
        }
    }
}

// ============================================================================
// Stream (h264bsd_stream.h)
// ============================================================================

#[repr(C)]
pub struct strmData_t {
    /// pointer to start of stream buffer
    pub pStrmBuffStart: *const u8,
    /// current read address in stream buffer
    pub pStrmCurrPos: *const u8,
    /// bit position in stream buffer byte
    pub bitPosInWord: u32,
    /// size of stream buffer (bytes)
    pub strmBuffSize: u32,
    /// number of bits read from stream buffer
    pub strmBuffReadBits: u32,
}

impl strmData_t {
    pub const fn zeroed() -> Self {
        strmData_t {
            pStrmBuffStart: core::ptr::null(),
            pStrmCurrPos: core::ptr::null(),
            bitPosInWord: 0,
            strmBuffSize: 0,
            strmBuffReadBits: 0,
        }
    }
}

// ============================================================================
// NAL unit (h264bsd_nal_unit.h)
// ============================================================================

pub type nalUnitType_e = u32;
pub const NAL_CODED_SLICE: u32 = 1;
pub const NAL_CODED_SLICE_IDR: u32 = 5;
pub const NAL_SEI: u32 = 6;
pub const NAL_SEQ_PARAM_SET: u32 = 7;
pub const NAL_PIC_PARAM_SET: u32 = 8;
pub const NAL_ACCESS_UNIT_DELIMITER: u32 = 9;
pub const NAL_END_OF_SEQUENCE: u32 = 10;
pub const NAL_END_OF_STREAM: u32 = 11;
pub const NAL_FILLER_DATA: u32 = 12;
pub const NAL_MAX_TYPE_VALUE: u32 = 31;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct nalUnit_t {
    pub nalUnitType: nalUnitType_e,
    pub nalRefIdc: u32,
}

#[inline(always)]
pub fn IS_IDR_NAL_UNIT(pNalUnit: &nalUnit_t) -> bool {
    pNalUnit.nalUnitType == NAL_CODED_SLICE_IDR
}

// ============================================================================
// VUI (h264bsd_vui.h)
// ============================================================================

pub const ASPECT_RATIO_UNSPECIFIED: u32 = 0;
pub const ASPECT_RATIO_EXTENDED_SAR: u32 = 255;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct hrdParameters_t {
    pub cpbCnt: u32,
    pub bitRateScale: u32,
    pub cpbSizeScale: u32,
    pub bitRateValue: [u32; MAX_CPB_CNT],
    pub cpbSizeValue: [u32; MAX_CPB_CNT],
    pub cbrFlag: [u32; MAX_CPB_CNT],
    pub initialCpbRemovalDelayLength: u32,
    pub cpbRemovalDelayLength: u32,
    pub dpbOutputDelayLength: u32,
    pub timeOffsetLength: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct vuiParameters_t {
    pub aspectRatioPresentFlag: u32,
    pub aspectRatioIdc: u32,
    pub sarWidth: u32,
    pub sarHeight: u32,
    pub overscanInfoPresentFlag: u32,
    pub overscanAppropriateFlag: u32,
    pub videoSignalTypePresentFlag: u32,
    pub videoFormat: u32,
    pub videoFullRangeFlag: u32,
    pub colourDescriptionPresentFlag: u32,
    pub colourPrimaries: u32,
    pub transferCharacteristics: u32,
    pub matrixCoefficients: u32,
    pub chromaLocInfoPresentFlag: u32,
    pub chromaSampleLocTypeTopField: u32,
    pub chromaSampleLocTypeBottomField: u32,
    pub timingInfoPresentFlag: u32,
    pub numUnitsInTick: u32,
    pub timeScale: u32,
    pub fixedFrameRateFlag: u32,
    pub nalHrdParametersPresentFlag: u32,
    pub nalHrdParameters: hrdParameters_t,
    pub vclHrdParametersPresentFlag: u32,
    pub vclHrdParameters: hrdParameters_t,
    pub lowDelayHrdFlag: u32,
    pub picStructPresentFlag: u32,
    pub bitstreamRestrictionFlag: u32,
    pub motionVectorsOverPicBoundariesFlag: u32,
    pub maxBytesPerPicDenom: u32,
    pub maxBitsPerMbDenom: u32,
    pub log2MaxMvLengthHorizontal: u32,
    pub log2MaxMvLengthVertical: u32,
    pub numReorderFrames: u32,
    pub maxDecFrameBuffering: u32,
}

// ============================================================================
// Parameter sets (h264bsd_seq_param_set.h / h264bsd_pic_param_set.h)
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct seqParamSet_t {
    pub profileIdc: u32,
    pub levelIdc: u32,
    pub seqParameterSetId: u32,
    pub maxFrameNum: u32,
    pub picOrderCntType: u32,
    pub maxPicOrderCntLsb: u32,
    pub deltaPicOrderAlwaysZeroFlag: u32,
    pub offsetForNonRefPic: i32,
    pub offsetForTopToBottomField: i32,
    pub numRefFramesInPicOrderCntCycle: u32,
    pub offsetForRefFrame: *mut i32,
    pub numRefFrames: u32,
    pub gapsInFrameNumValueAllowedFlag: u32,
    pub picWidthInMbs: u32,
    pub picHeightInMbs: u32,
    pub frameCroppingFlag: u32,
    pub frameCropLeftOffset: u32,
    pub frameCropRightOffset: u32,
    pub frameCropTopOffset: u32,
    pub frameCropBottomOffset: u32,
    pub vuiParametersPresentFlag: u32,
    pub vuiParameters: *mut vuiParameters_t,
    pub maxDpbSize: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct picParamSet_t {
    pub picParameterSetId: u32,
    pub seqParameterSetId: u32,
    pub picOrderPresentFlag: u32,
    pub numSliceGroups: u32,
    pub sliceGroupMapType: u32,
    pub runLength: *mut u32,
    pub topLeft: *mut u32,
    pub bottomRight: *mut u32,
    pub sliceGroupChangeDirectionFlag: u32,
    pub sliceGroupChangeRate: u32,
    pub picSizeInMapUnits: u32,
    pub sliceGroupId: *mut u32,
    pub numRefIdxL0Active: u32,
    pub picInitQp: u32,
    pub chromaQpIndexOffset: i32,
    pub deblockingFilterControlPresentFlag: u32,
    pub constrainedIntraPredFlag: u32,
    pub redundantPicCntPresentFlag: u32,
}

// ============================================================================
// Slice header (h264bsd_slice_header.h)
// ============================================================================

pub const P_SLICE: u32 = 0;
pub const I_SLICE: u32 = 2;

#[inline(always)]
pub fn IS_P_SLICE(sliceType: u32) -> bool {
    sliceType == P_SLICE || sliceType == P_SLICE + 5
}
#[inline(always)]
pub fn IS_I_SLICE(sliceType: u32) -> bool {
    sliceType == I_SLICE || sliceType == I_SLICE + 5
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct refPicListReorderingOperation_t {
    pub reorderingOfPicNumsIdc: u32,
    pub absDiffPicNum: u32,
    pub longTermPicNum: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct refPicListReordering_t {
    pub refPicListReorderingFlagL0: u32,
    pub command: [refPicListReorderingOperation_t; MAX_NUM_REF_PICS + 1],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct memoryManagementOperation_t {
    pub memoryManagementControlOperation: u32,
    pub differenceOfPicNums: u32,
    pub longTermPicNum: u32,
    pub longTermFrameIdx: u32,
    pub maxLongTermFrameIdx: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct decRefPicMarking_t {
    pub noOutputOfPriorPicsFlag: u32,
    pub longTermReferenceFlag: u32,
    pub adaptiveRefPicMarkingModeFlag: u32,
    pub operation: [memoryManagementOperation_t; MAX_NUM_MMC_OPERATIONS],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct sliceHeader_t {
    pub firstMbInSlice: u32,
    pub sliceType: u32,
    pub picParameterSetId: u32,
    pub frameNum: u32,
    pub idrPicId: u32,
    pub picOrderCntLsb: u32,
    pub deltaPicOrderCntBottom: i32,
    pub deltaPicOrderCnt: [i32; 2],
    pub redundantPicCnt: u32,
    pub numRefIdxActiveOverrideFlag: u32,
    pub numRefIdxL0Active: u32,
    pub sliceQpDelta: i32,
    pub disableDeblockingFilterIdc: u32,
    pub sliceAlphaC0Offset: i32,
    pub sliceBetaOffset: i32,
    pub sliceGroupChangeCycle: u32,
    pub refPicListReordering: refPicListReordering_t,
    pub decRefPicMarking: decRefPicMarking_t,
}

// ============================================================================
// POC (h264bsd_pic_order_cnt.h)
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct pocStorage_t {
    pub prevPicOrderCntLsb: u32,
    pub prevPicOrderCntMsb: i32,
    pub prevFrameNum: u32,
    pub prevFrameNumOffset: u32,
}

// ============================================================================
// Image (h264bsd_image.h)
// ============================================================================

#[repr(C)]
pub struct image_t {
    pub data: *mut u8,
    /// width in macroblocks
    pub width: u32,
    /// height in macroblocks
    pub height: u32,
    /* current MB's components */
    pub luma: *mut u8,
    pub cb: *mut u8,
    pub cr: *mut u8,
}

// ============================================================================
// DPB (h264bsd_dpb.h)
// ============================================================================

pub type dpbPictureStatus_e = u32;
pub const UNUSED: u32 = 0;
pub const NON_EXISTING: u32 = 1;
pub const SHORT_TERM: u32 = 2;
pub const LONG_TERM: u32 = 3;

#[repr(C)]
pub struct dpbPicture_t {
    /// 16-byte aligned pointer of pAllocatedData
    pub data: *mut u8,
    /// allocated picture pointer; (size + 15) bytes
    pub pAllocatedData: *mut u8,
    pub picNum: i32,
    pub frameNum: u32,
    pub picOrderCnt: i32,
    pub status: dpbPictureStatus_e,
    pub toBeDisplayed: u32,
    pub picId: u32,
    pub numErrMbs: u32,
    pub isIdr: u32,
}

#[repr(C)]
pub struct dpbOutPicture_t {
    pub data: *mut u8,
    pub picId: u32,
    pub numErrMbs: u32,
    pub isIdr: u32,
}

#[repr(C)]
pub struct dpbStorage_t {
    pub buffer: *mut dpbPicture_t,
    pub list: *mut *mut dpbPicture_t,
    pub currentOut: *mut dpbPicture_t,
    pub outBuf: *mut dpbOutPicture_t,
    pub numOut: u32,
    pub outIndex: u32,
    pub maxRefFrames: u32,
    pub dpbSize: u32,
    pub maxFrameNum: u32,
    pub maxLongTermFrameIdx: u32,
    pub numRefFrames: u32,
    pub fullness: u32,
    pub prevRefFrameNum: u32,
    pub lastContainsMmco5: u32,
    pub noReordering: u32,
    pub flushed: u32,
    /// Port addition: allocation hooks for the DPB's picture buffers
    /// (the C used malloc/free). Set from `storage_t::allocator` by
    /// h264bsdInit before any dpb call.
    pub allocator: Allocator,
}

// ============================================================================
// Macroblock layer (h264bsd_macroblock_layer.h)
// ============================================================================

pub type mbType_e = u32;
pub const P_Skip: u32 = 0;
pub const P_L0_16x16: u32 = 1;
pub const P_L0_L0_16x8: u32 = 2;
pub const P_L0_L0_8x16: u32 = 3;
pub const P_8x8: u32 = 4;
pub const P_8x8ref0: u32 = 5;
pub const I_4x4: u32 = 6;
pub const I_16x16_0_0_0: u32 = 7;
pub const I_16x16_1_0_0: u32 = 8;
pub const I_16x16_2_0_0: u32 = 9;
pub const I_16x16_3_0_0: u32 = 10;
pub const I_16x16_0_1_0: u32 = 11;
pub const I_16x16_1_1_0: u32 = 12;
pub const I_16x16_2_1_0: u32 = 13;
pub const I_16x16_3_1_0: u32 = 14;
pub const I_16x16_0_2_0: u32 = 15;
pub const I_16x16_1_2_0: u32 = 16;
pub const I_16x16_2_2_0: u32 = 17;
pub const I_16x16_3_2_0: u32 = 18;
pub const I_16x16_0_0_1: u32 = 19;
pub const I_16x16_1_0_1: u32 = 20;
pub const I_16x16_2_0_1: u32 = 21;
pub const I_16x16_3_0_1: u32 = 22;
pub const I_16x16_0_1_1: u32 = 23;
pub const I_16x16_1_1_1: u32 = 24;
pub const I_16x16_2_1_1: u32 = 25;
pub const I_16x16_3_1_1: u32 = 26;
pub const I_16x16_0_2_1: u32 = 27;
pub const I_16x16_1_2_1: u32 = 28;
pub const I_16x16_2_2_1: u32 = 29;
pub const I_16x16_3_2_1: u32 = 30;
pub const I_PCM: u32 = 31;

pub type subMbType_e = u32;
pub const P_L0_8x8: u32 = 0;
pub const P_L0_8x4: u32 = 1;
pub const P_L0_4x8: u32 = 2;
pub const P_L0_4x4: u32 = 3;

pub type mbPartMode_e = u32;
pub const MB_P_16x16: u32 = 0;
pub const MB_P_16x8: u32 = 1;
pub const MB_P_8x16: u32 = 2;
pub const MB_P_8x8: u32 = 3;

pub type subMbPartMode_e = u32;
pub const MB_SP_8x8: u32 = 0;
pub const MB_SP_8x4: u32 = 1;
pub const MB_SP_4x8: u32 = 2;
pub const MB_SP_4x4: u32 = 3;

pub type mbPartPredMode_e = u32;
pub const PRED_MODE_INTRA4x4: u32 = 0;
pub const PRED_MODE_INTRA16x16: u32 = 1;
pub const PRED_MODE_INTER: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct mv_t {
    /* MvPrediction16x16 assumes that MVs are 16bits */
    pub hor: i16,
    pub ver: i16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct mbPred_t {
    pub prevIntra4x4PredModeFlag: [u32; 16],
    pub remIntra4x4PredMode: [u32; 16],
    pub intraChromaPredMode: u32,
    pub refIdxL0: [u32; 4],
    pub mvdL0: [mv_t; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct subMbPred_t {
    pub subMbType: [subMbType_e; 4],
    pub refIdxL0: [u32; 4],
    pub mvdL0: [[mv_t; 4]; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct residual_t {
    pub totalCoeff: [i16; 27],
    pub level: [[i32; 16]; 26],
    pub coeffMap: [u32; 24],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct macroblockLayer_t {
    pub mbType: mbType_e,
    pub codedBlockPattern: u32,
    pub mbQpDelta: i32,
    pub mbPred: mbPred_t,
    pub subMbPred: subMbPred_t,
    pub residual: residual_t,
}

#[repr(C)]
pub struct mbStorage_t {
    pub mbType: mbType_e,
    pub sliceId: u32,
    pub disableDeblockingFilterIdc: u32,
    pub filterOffsetA: i32,
    pub filterOffsetB: i32,
    pub qpY: u32,
    pub chromaQpIndexOffset: i32,
    pub totalCoeff: [i16; 27],
    pub intra4x4PredMode: [u8; 16],
    pub refPic: [u32; 4],
    pub refAddr: [*mut u8; 4],
    pub mv: [mv_t; 16],
    pub decoded: u32,
    pub mbA: *mut mbStorage_t,
    pub mbB: *mut mbStorage_t,
    pub mbC: *mut mbStorage_t,
    pub mbD: *mut mbStorage_t,
}

#[inline(always)]
pub fn IS_INTRA_MB(a: &mbStorage_t) -> bool {
    a.mbType > 5
}
#[inline(always)]
pub fn IS_I_PCM_MB(a: &mbStorage_t) -> bool {
    a.mbType == 31
}

// ============================================================================
// Neighbour (h264bsd_neighbour.h)
// ============================================================================

pub type neighbourMb_e = u32;
pub const MB_A: u32 = 0;
pub const MB_B: u32 = 1;
pub const MB_C: u32 = 2;
pub const MB_D: u32 = 3;
pub const MB_CURR: u32 = 4;
pub const MB_NA: u32 = 0xFF;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct neighbour_t {
    pub mb: neighbourMb_e,
    pub index: u8,
}

// ============================================================================
// Storage (h264bsd_storage.h)
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct sliceStorage_t {
    pub sliceId: u32,
    pub numDecodedMbs: u32,
    pub lastMbAddr: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct aubCheck_t {
    pub nuPrev: [nalUnit_t; 1],
    pub prevFrameNum: u32,
    pub prevIdrPicId: u32,
    pub prevPicOrderCntLsb: u32,
    pub prevDeltaPicOrderCntBottom: i32,
    pub prevDeltaPicOrderCnt: [i32; 2],
    pub firstCallFlag: u32,
}

#[repr(C)]
pub struct storage_t {
    /* active parameter set ids and pointers */
    pub oldSpsId: u32,
    pub activePpsId: u32,
    pub activeSpsId: u32,
    pub activePps: *mut picParamSet_t,
    pub activeSps: *mut seqParamSet_t,
    pub sps: [*mut seqParamSet_t; MAX_NUM_SEQ_PARAM_SETS],
    pub pps: [*mut picParamSet_t; MAX_NUM_PIC_PARAM_SETS],

    /* current slice group map, recomputed for each slice */
    pub sliceGroupMap: *mut u32,

    pub picSizeInMbs: u32,

    pub skipRedundantSlices: u32,
    pub picStarted: u32,

    /* flag to indicate if current access unit contains any valid slices */
    pub validSliceInAccessUnit: u32,

    pub slice: [sliceStorage_t; 1],

    /* number of concealed macroblocks in the current image */
    pub numConcealedMbs: u32,

    /* picId given by application */
    pub currentPicId: u32,

    /* macroblock specific storages, size determined by image dimensions */
    pub mb: *mut mbStorage_t,

    pub noReordering: u32,
    pub dpb: [dpbStorage_t; 1],
    pub poc: [pocStorage_t; 1],
    pub aub: [aubCheck_t; 1],
    pub currImage: [image_t; 1],
    pub prevNalUnit: [nalUnit_t; 1],

    /* slice header; [1] is temporary storage while decoding, [0] the
     * last successfully decoded */
    pub sliceHeader: [sliceHeader_t; 2],

    /* old stream buffer bookkeeping for partial-buffer processing */
    pub prevBufNotFinished: u32,
    pub prevBufPointer: *const u8,
    pub prevBytesConsumed: u32,
    pub strm: [strmData_t; 1],

    /* mb layer kept here to avoid excessive stack */
    pub mbLayer: *mut macroblockLayer_t,

    /* activate parameter sets after returning HEADERS_RDY */
    pub pendingActivation: u32,
    /* 0 gray picture for corrupted intra, 1 previous frame if available */
    pub intraConcealmentFlag: u32,

    /* allocation hooks (port addition; replaces C malloc/free) */
    pub allocator: Allocator,
}

// ============================================================================
// decContainer (h264bsd_container.h)
// ============================================================================

pub const DEC_UNINITIALIZED: u32 = 0;
pub const DEC_INITIALIZED: u32 = 1;
pub const DEC_NEW_HEADERS: u32 = 2;

#[repr(C)]
pub struct decContainer_t {
    pub decStat: u32,
    pub picNumber: u32,
    pub storage: storage_t,
}

// ============================================================================
// h264bsd_stream.c
// ============================================================================

/// Read and remove bits from the stream buffer. Returns the bits, or
/// END_OF_STREAM if not enough bits left.
pub fn h264bsdGetBits(pStrmData: &mut strmData_t, numBits: u32) -> u32 {
    let out = if numBits == 0 { 0 } else { h264bsdShowBits32(pStrmData) >> (32 - numBits) };
    if h264bsdFlushBits(pStrmData, numBits) == HANTRO_OK {
        out
    } else {
        END_OF_STREAM
    }
}

/// Peek the next 32 bits (MSB-first); bits beyond the end of the
/// stream read as 0.
pub fn h264bsdShowBits32(pStrmData: &strmData_t) -> u32 {
    unsafe {
        let mut pStrm = pStrmData.pStrmCurrPos;
        /* number of bits left in the buffer */
        let mut bits =
            pStrmData.strmBuffSize as i32 * 8 - pStrmData.strmBuffReadBits as i32;

        /* at least 32-bits in the buffer */
        if bits >= 32 {
            let bitPosInWord = pStrmData.bitPosInWord;
            let mut out = ((*pStrm.add(0) as u32) << 24)
                | ((*pStrm.add(1) as u32) << 16)
                | ((*pStrm.add(2) as u32) << 8)
                | (*pStrm.add(3) as u32);
            if bitPosInWord != 0 {
                let byte = *pStrm.add(4) as u32;
                let tmp = 8 - bitPosInWord;
                out <<= bitPosInWord;
                out |= byte >> tmp;
            }
            out
        }
        /* at least one bit in the buffer */
        else if bits > 0 {
            let mut shift = (24 + pStrmData.bitPosInWord) as i32;
            let mut out = (*pStrm as u32) << shift;
            pStrm = pStrm.add(1);
            bits -= (8 - pStrmData.bitPosInWord) as i32;
            while bits > 0 {
                shift -= 8;
                out |= (*pStrm as u32) << shift;
                pStrm = pStrm.add(1);
                bits -= 8;
            }
            out
        } else {
            0
        }
    }
}

/// Remove bits from the stream buffer. Returns HANTRO_OK, or
/// END_OF_STREAM if not enough bits left.
pub fn h264bsdFlushBits(pStrmData: &mut strmData_t, numBits: u32) -> u32 {
    pStrmData.strmBuffReadBits += numBits;
    pStrmData.bitPosInWord = pStrmData.strmBuffReadBits & 0x7;
    if pStrmData.strmBuffReadBits <= 8 * pStrmData.strmBuffSize {
        pStrmData.pStrmCurrPos = unsafe {
            pStrmData
                .pStrmBuffStart
                .add((pStrmData.strmBuffReadBits >> 3) as usize)
        };
        HANTRO_OK
    } else {
        END_OF_STREAM
    }
}

pub fn h264bsdIsByteAligned(pStrmData: &strmData_t) -> u32 {
    if pStrmData.bitPosInWord == 0 {
        HANTRO_TRUE
    } else {
        HANTRO_FALSE
    }
}

// ============================================================================
// h264bsd_util.c
// ============================================================================

static stuffingTable: [u32; 8] = [0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80];

pub static h264bsdQpC: [u32; 52] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    25, 26, 27, 28, 29, 29, 30, 31, 32, 32, 33, 34, 34, 35, 35, 36, 36, 37, 37, 37, 38, 38, 38,
    39, 39, 39, 39,
];

/// Count leading zeros in a right-aligned code word of `length` bits.
pub fn h264bsdCountLeadingZeros(value: u32, length: u32) -> u32 {
    let mut zeros = 0;
    let mut mask: u32 = 1 << (length - 1);
    while mask != 0 && (value & mask) == 0 {
        zeros += 1;
        mask >>= 1;
    }
    zeros
}

/// Check RBSP trailing bits ('1' bit then zero or more '0' bits to
/// the byte boundary).
pub fn h264bsdRbspTrailingBits(pStrmData: &mut strmData_t) -> u32 {
    let stuffingLength = 8 - pStrmData.bitPosInWord;
    let stuffing = h264bsdGetBits(pStrmData, stuffingLength);
    if stuffing == END_OF_STREAM {
        return HANTRO_NOK;
    }
    if stuffing != stuffingTable[stuffingLength as usize - 1] {
        HANTRO_NOK
    } else {
        HANTRO_OK
    }
}

/// More data in the current RBSP?
pub fn h264bsdMoreRbspData(pStrmData: &strmData_t) -> u32 {
    let bits = pStrmData.strmBuffSize * 8 - pStrmData.strmBuffReadBits;
    if bits == 0 {
        return HANTRO_FALSE;
    }
    if bits > 8 || (h264bsdShowBits32(pStrmData) >> (32 - bits)) != (1u32 << (bits - 1)) {
        HANTRO_TRUE
    } else {
        HANTRO_FALSE
    }
}

/// Address of the next macroblock in the current slice group; 0 if
/// none of the following macroblocks belong to the same group.
pub unsafe fn h264bsdNextMbAddress(
    pSliceGroupMap: *const u32,
    picSizeInMbs: u32,
    currMbAddr: u32,
) -> u32 {
    let sliceGroup = *pSliceGroupMap.add(currMbAddr as usize);
    let mut i = currMbAddr + 1;
    while i < picSizeInMbs && *pSliceGroupMap.add(i as usize) != sliceGroup {
        i += 1;
    }
    if i == picSizeInMbs {
        i = 0;
    }
    i
}

/// Set luma and chroma pointers in image_t for current MB.
pub fn h264bsdSetCurrImageMbPointers(image: &mut image_t, mbNum: u32) {
    let width = image.width;
    let row = udiv(mbNum, width);
    let col = urem(mbNum, width);
    let tmp = row * width;
    let picSize = width * image.height;
    unsafe {
        image.luma = image.data.add((col * 16 + tmp * 256) as usize);
        image.cb = image
            .data
            .add((picSize * 256 + tmp * 64 + col * 8) as usize);
        image.cr = image.cb.add((picSize * 64) as usize);
    }
}

// ============================================================================
// h264bsd_vlc.c
// ============================================================================

pub const BIG_CODE_NUM: u32 = 0xFFFF_FFFF;

static codedBlockPatternIntra4x4: [u8; 48] = [
    47, 31, 15, 0, 23, 27, 29, 30, 7, 11, 13, 14, 39, 43, 45, 46, 16, 3, 5, 10, 12, 19, 21, 26,
    28, 35, 37, 42, 44, 1, 2, 4, 8, 17, 18, 20, 24, 6, 9, 22, 25, 32, 33, 34, 36, 40, 38, 41,
];

static codedBlockPatternInter: [u8; 48] = [
    0, 16, 1, 2, 4, 8, 32, 3, 5, 10, 12, 15, 47, 7, 11, 13, 14, 6, 9, 31, 35, 37, 42, 44, 33,
    34, 36, 40, 39, 43, 45, 46, 17, 18, 20, 24, 19, 21, 26, 28, 23, 27, 29, 30, 22, 25, 38, 41,
];

/// Decode unsigned Exp-Golomb code.
pub fn h264bsdDecodeExpGolombUnsigned(pStrmData: &mut strmData_t, codeNum: &mut u32) -> u32 {
    let mut bits = h264bsdShowBits32(pStrmData);

    /* first bit is 1 -> code length 1 */
    if bits >= 0x8000_0000 {
        h264bsdFlushBits(pStrmData, 1);
        *codeNum = 0;
        HANTRO_OK
    }
    /* second bit is 1 -> code length 3 */
    else if bits >= 0x4000_0000 {
        if h264bsdFlushBits(pStrmData, 3) == END_OF_STREAM {
            return HANTRO_NOK;
        }
        *codeNum = 1 + ((bits >> 29) & 0x1);
        HANTRO_OK
    }
    /* third bit is 1 -> code length 5 */
    else if bits >= 0x2000_0000 {
        if h264bsdFlushBits(pStrmData, 5) == END_OF_STREAM {
            return HANTRO_NOK;
        }
        *codeNum = 3 + ((bits >> 27) & 0x3);
        HANTRO_OK
    }
    /* fourth bit is 1 -> code length 7 */
    else if bits >= 0x1000_0000 {
        if h264bsdFlushBits(pStrmData, 7) == END_OF_STREAM {
            return HANTRO_NOK;
        }
        *codeNum = 7 + ((bits >> 25) & 0x7);
        HANTRO_OK
    }
    /* other code lengths */
    else {
        let numZeros = 4 + h264bsdCountLeadingZeros(bits, 28);

        /* all 32 bits are zero */
        if numZeros == 32 {
            *codeNum = 0;
            h264bsdFlushBits(pStrmData, 32);
            bits = h264bsdGetBits(pStrmData, 1);
            /* check 33rd bit, must be 1 */
            if bits == 1 {
                /* cannot use h264bsdGetBits, limited to 31 bits */
                bits = h264bsdShowBits32(pStrmData);
                if h264bsdFlushBits(pStrmData, 32) == END_OF_STREAM {
                    return HANTRO_NOK;
                }
                /* code num 2^32 - 1, needed for unsigned mapping */
                if bits == 0 {
                    *codeNum = BIG_CODE_NUM;
                    return HANTRO_OK;
                }
                /* code num 2^32, needed for unsigned mapping
                 * (results in -2^31) */
                else if bits == 1 {
                    *codeNum = BIG_CODE_NUM;
                    return HANTRO_NOK;
                }
            }
            /* if more zeros than 32, it is an error */
            return HANTRO_NOK;
        } else {
            h264bsdFlushBits(pStrmData, numZeros + 1);
        }

        bits = h264bsdGetBits(pStrmData, numZeros);
        if bits == END_OF_STREAM {
            return HANTRO_NOK;
        }

        *codeNum = (1u32 << numZeros) - 1 + bits;
        HANTRO_OK
    }
}

/// Decode signed Exp-Golomb code.
pub fn h264bsdDecodeExpGolombSigned(pStrmData: &mut strmData_t, value: &mut i32) -> u32 {
    let mut codeNum: u32 = 0;
    let status = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut codeNum);

    if codeNum == BIG_CODE_NUM {
        /* BIG_CODE_NUM with OK status would be 2^31, out of i32 range */
        if status == HANTRO_OK {
            return HANTRO_NOK;
        } else {
            /* codeNum 2^32 results in -2^31 */
            *value = i32::MIN;
            return HANTRO_OK;
        }
    } else if status == HANTRO_OK {
        *value = if codeNum & 0x1 != 0 {
            ((codeNum + 1) >> 1) as i32
        } else {
            -(((codeNum + 1) >> 1) as i32)
        };
        return HANTRO_OK;
    }

    HANTRO_NOK
}

/// Decode mapped Exp-Golomb code (codedBlockPattern).
pub fn h264bsdDecodeExpGolombMapped(
    pStrmData: &mut strmData_t,
    value: &mut u32,
    isIntra: u32,
) -> u32 {
    let mut codeNum: u32 = 0;
    let status = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut codeNum);

    if status != HANTRO_OK {
        HANTRO_NOK
    } else {
        /* range of valid codeNums [0,47] */
        if codeNum > 47 {
            return HANTRO_NOK;
        }
        if isIntra != 0 {
            *value = codedBlockPatternIntra4x4[codeNum as usize] as u32;
        } else {
            *value = codedBlockPatternInter[codeNum as usize] as u32;
        }
        HANTRO_OK
    }
}

/// Decode truncated Exp-Golomb code; range [0,1] when !greaterThanOne.
pub fn h264bsdDecodeExpGolombTruncated(
    pStrmData: &mut strmData_t,
    value: &mut u32,
    greaterThanOne: u32,
) -> u32 {
    if greaterThanOne != 0 {
        h264bsdDecodeExpGolombUnsigned(pStrmData, value)
    } else {
        *value = h264bsdGetBits(pStrmData, 1);
        if *value == END_OF_STREAM {
            return HANTRO_NOK;
        }
        *value ^= 0x1;
        HANTRO_OK
    }
}

// ============================================================================
// Ported translation units (1:1 with h264bsd .c files)
// ============================================================================
// Enabled as each port lands; see .context/h264_mkv_codec_plan.md.

pub mod h264_parse;        // nal_unit, seq_param_set, pic_param_set, vui, byte_stream
pub mod h264_slice_header; // slice_header, pic_order_cnt
pub mod h264_cavlc;        // cavlc
pub mod h264_macroblock;   // macroblock_layer
pub mod h264_slice_data;   // slice_data
pub mod h264_neighbour;    // neighbour, slice_group_map
pub mod h264_transform;    // transform
pub mod h264_intra;        // intra_prediction
pub mod h264_inter;        // inter_prediction
pub mod h264_reconstruct;  // reconstruct, image
pub mod h264_deblock;      // deblocking
pub mod h264_dpb;          // dpb
pub mod h264_storage;      // storage, conceal, slice-corrupt marking
pub mod h264_decoder;      // decoder (top-level API)
