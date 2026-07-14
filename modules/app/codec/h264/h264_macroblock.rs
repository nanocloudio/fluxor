// Mechanical Rust port of h264bsd_macroblock_layer.c (h264bsd), per the
// port rules in scratchpad/PORT_RULES.md. Plain-C build paths only
// (H264DEC_OMXDL / H264DEC_NEON undefined): the OMXDL variants of
// DecodeResidual / ProcessIntra4x4Residual / ProcessChromaResidual /
// ProcessIntra16x16Residual and the chromaIndex/lumaIndex tables are
// SKIPPED (dead in this build).
//
// h264bsdClearMbLayer is declared in h264bsd_macroblock_layer.h but its C
// implementation is NEON assembly (dead in the plain build); it is ported
// here as a plain byte clear of `size` bytes to satisfy the manifest.

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
use super::h264_cavlc::*;
use super::h264_transform::*;
use super::h264_intra::*;
use super::h264_inter::*;
use super::h264_reconstruct::*;
use super::h264_neighbour::*;

/*------------------------------------------------------------------------------
    3. Module defines
------------------------------------------------------------------------------*/

/* mapping of dc coefficients array to luma blocks */
static dcCoeffIndex: [u32; 16] = [0, 1, 4, 5, 2, 3, 6, 7, 8, 9, 12, 13, 10, 11, 14, 15];

/*------------------------------------------------------------------------------

    Function name: h264bsdDecodeMacroblockLayer

        Functional description:
          Parse macroblock specific information from bit stream.

        Inputs:
          pStrmData         pointer to stream data structure
          pMb               pointer to macroblock storage structure
          sliceType         type of the current slice
          numRefIdxActive   maximum reference index

        Outputs:
          pMbLayer          stores the macroblock data parsed from stream

        Returns:
          HANTRO_OK         success
          HANTRO_NOK        end of stream or error in stream

------------------------------------------------------------------------------*/

pub unsafe fn h264bsdDecodeMacroblockLayer(
    pStrmData: &mut strmData_t,
    pMbLayer: &mut macroblockLayer_t,
    pMb: &mbStorage_t,
    sliceType: u32,
    numRefIdxActive: u32,
) -> u32 {
    /* Variables */

    let mut tmp: u32;
    let mut i: u32;
    let mut value: u32 = 0;
    let mut itmp: i32 = 0;
    let partMode: mbPartPredMode_e;

    /* Code */

    core::ptr::write_bytes(pMbLayer as *mut macroblockLayer_t, 0, 1);

    tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);

    if IS_I_SLICE(sliceType) {
        if (value + 6) > 31 || tmp != HANTRO_OK {
            return HANTRO_NOK;
        }
        pMbLayer.mbType = (value + 6) as mbType_e;
    } else {
        if (value + 1) > 31 || tmp != HANTRO_OK {
            return HANTRO_NOK;
        }
        pMbLayer.mbType = (value + 1) as mbType_e;
    }

    if pMbLayer.mbType == I_PCM {
        let mut level: *mut i32;
        while h264bsdIsByteAligned(pStrmData) == 0 {
            /* pcm_alignment_zero_bit */
            tmp = h264bsdGetBits(pStrmData, 1);
            if tmp != 0 {
                return HANTRO_NOK;
            }
        }

        level = pMbLayer.residual.level[0].as_mut_ptr();
        i = 0;
        while i < 384 {
            value = h264bsdGetBits(pStrmData, 8);
            if value == END_OF_STREAM {
                return HANTRO_NOK;
            }
            *level = value as i32;
            level = level.add(1);
            i += 1;
        }
    } else {
        partMode = h264bsdMbPartPredMode(pMbLayer.mbType);
        if partMode == PRED_MODE_INTER && h264bsdNumMbPart(pMbLayer.mbType) == 4 {
            tmp = DecodeSubMbPred(
                pStrmData,
                &mut pMbLayer.subMbPred,
                pMbLayer.mbType,
                numRefIdxActive,
            );
        } else {
            tmp = DecodeMbPred(
                pStrmData,
                &mut pMbLayer.mbPred,
                pMbLayer.mbType,
                numRefIdxActive,
            );
        }
        if tmp != HANTRO_OK {
            return tmp;
        }

        if partMode != PRED_MODE_INTRA16x16 {
            tmp = h264bsdDecodeExpGolombMapped(
                pStrmData,
                &mut value,
                (partMode == PRED_MODE_INTRA4x4) as u32,
            );
            if tmp != HANTRO_OK {
                return tmp;
            }
            pMbLayer.codedBlockPattern = value;
        } else {
            pMbLayer.codedBlockPattern = CbpIntra16x16(pMbLayer.mbType);
        }

        if pMbLayer.codedBlockPattern != 0 || partMode == PRED_MODE_INTRA16x16 {
            tmp = h264bsdDecodeExpGolombSigned(pStrmData, &mut itmp);
            if tmp != HANTRO_OK || itmp < -26 || itmp > 25 {
                return HANTRO_NOK;
            }
            pMbLayer.mbQpDelta = itmp;

            tmp = DecodeResidual(
                pStrmData,
                &mut pMbLayer.residual,
                pMb,
                pMbLayer.mbType,
                pMbLayer.codedBlockPattern,
            );

            pStrmData.strmBuffReadBits =
                (pStrmData.pStrmCurrPos.offset_from(pStrmData.pStrmBuffStart) as u32) * 8
                    + pStrmData.bitPosInWord;

            if tmp != HANTRO_OK {
                return tmp;
            }
        }
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: h264bsdMbPartPredMode

        Functional description:
          Returns the prediction mode of a macroblock type

------------------------------------------------------------------------------*/

pub fn h264bsdMbPartPredMode(mbType: mbType_e) -> mbPartPredMode_e {
    if mbType <= P_8x8ref0 {
        PRED_MODE_INTER
    } else if mbType == I_4x4 {
        PRED_MODE_INTRA4x4
    } else {
        PRED_MODE_INTRA16x16
    }
}

/*------------------------------------------------------------------------------

    Function: h264bsdNumMbPart

        Functional description:
          Returns the amount of macroblock partitions in a macroblock type

------------------------------------------------------------------------------*/

pub fn h264bsdNumMbPart(mbType: mbType_e) -> u32 {
    match mbType {
        P_L0_16x16 | P_Skip => 1,

        P_L0_L0_16x8 | P_L0_L0_8x16 => 2,

        /* P_8x8 or P_8x8ref0 */
        _ => 4,
    }
}

/*------------------------------------------------------------------------------

    Function: h264bsdNumSubMbPart

        Functional description:
          Returns the amount of sub-partitions in a sub-macroblock type

------------------------------------------------------------------------------*/

pub fn h264bsdNumSubMbPart(subMbType: subMbType_e) -> u32 {
    match subMbType {
        P_L0_8x8 => 1,

        P_L0_8x4 | P_L0_4x8 => 2,

        /* P_L0_4x4 */
        _ => 4,
    }
}

/*------------------------------------------------------------------------------

    Function: DecodeMbPred

        Functional description:
          Parse macroblock prediction information from bit stream and store
          in 'pMbPred'.

------------------------------------------------------------------------------*/

fn DecodeMbPred(
    pStrmData: &mut strmData_t,
    pMbPred: &mut mbPred_t,
    mbType: mbType_e,
    numRefIdxActive: u32,
) -> u32 {
    /* Variables */

    let mut tmp: u32;
    let mut i: u32;
    let mut j: u32;
    let mut value: u32 = 0;
    let mut itmp: i32 = 0;

    /* Code */

    let partMode = h264bsdMbPartPredMode(mbType);
    if partMode == PRED_MODE_INTER {
        /* PRED_MODE_INTER */
        if numRefIdxActive > 1 {
            i = h264bsdNumMbPart(mbType);
            j = 0;
            while i != 0 {
                i -= 1;
                tmp = h264bsdDecodeExpGolombTruncated(
                    pStrmData,
                    &mut value,
                    (numRefIdxActive > 2) as u32,
                );
                if tmp != HANTRO_OK || value >= numRefIdxActive {
                    return HANTRO_NOK;
                }

                pMbPred.refIdxL0[j as usize] = value;
                j += 1;
            }
        }

        i = h264bsdNumMbPart(mbType);
        j = 0;
        while i != 0 {
            i -= 1;
            tmp = h264bsdDecodeExpGolombSigned(pStrmData, &mut itmp);
            if tmp != HANTRO_OK {
                return tmp;
            }
            pMbPred.mvdL0[j as usize].hor = itmp as i16;

            tmp = h264bsdDecodeExpGolombSigned(pStrmData, &mut itmp);
            if tmp != HANTRO_OK {
                return tmp;
            }
            pMbPred.mvdL0[j as usize].ver = itmp as i16;
            j += 1;
        }
    } else {
        /* C switch falls through from PRED_MODE_INTRA4x4 into
         * PRED_MODE_INTRA16x16 */
        if partMode == PRED_MODE_INTRA4x4 {
            itmp = 0;
            i = 0;
            while itmp < 2 {
                value = h264bsdShowBits32(pStrmData);
                tmp = 0;
                j = 8;
                while j != 0 {
                    j -= 1;
                    pMbPred.prevIntra4x4PredModeFlag[i as usize] =
                        if value & 0x80000000 != 0 { HANTRO_TRUE } else { HANTRO_FALSE };
                    value <<= 1;
                    if pMbPred.prevIntra4x4PredModeFlag[i as usize] == 0 {
                        pMbPred.remIntra4x4PredMode[i as usize] = value >> 29;
                        value <<= 3;
                        tmp += 1;
                    }
                    i += 1;
                }
                if h264bsdFlushBits(pStrmData, 8 + 3 * tmp) == END_OF_STREAM {
                    return HANTRO_NOK;
                }
                itmp += 1;
            }
        }

        /* PRED_MODE_INTRA16x16 (and fall-through from PRED_MODE_INTRA4x4) */
        tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
        if tmp != HANTRO_OK || value > 3 {
            return HANTRO_NOK;
        }
        pMbPred.intraChromaPredMode = value;
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: DecodeSubMbPred

        Functional description:
          Parse sub-macroblock prediction information from bit stream and
          store in 'pMbPred'.

------------------------------------------------------------------------------*/

fn DecodeSubMbPred(
    pStrmData: &mut strmData_t,
    pSubMbPred: &mut subMbPred_t,
    mbType: mbType_e,
    numRefIdxActive: u32,
) -> u32 {
    /* Variables */

    let mut tmp: u32;
    let mut i: u32;
    let mut j: u32;
    let mut value: u32 = 0;
    let mut itmp: i32 = 0;

    /* Code */

    i = 0;
    while i < 4 {
        tmp = h264bsdDecodeExpGolombUnsigned(pStrmData, &mut value);
        if tmp != HANTRO_OK || value > 3 {
            return HANTRO_NOK;
        }
        pSubMbPred.subMbType[i as usize] = value as subMbType_e;
        i += 1;
    }

    if numRefIdxActive > 1 && mbType != P_8x8ref0 {
        i = 0;
        while i < 4 {
            tmp = h264bsdDecodeExpGolombTruncated(
                pStrmData,
                &mut value,
                (numRefIdxActive > 2) as u32,
            );
            if tmp != HANTRO_OK || value >= numRefIdxActive {
                return HANTRO_NOK;
            }
            pSubMbPred.refIdxL0[i as usize] = value;
            i += 1;
        }
    }

    i = 0;
    while i < 4 {
        j = 0;
        value = h264bsdNumSubMbPart(pSubMbPred.subMbType[i as usize]);
        while value != 0 {
            value -= 1;
            tmp = h264bsdDecodeExpGolombSigned(pStrmData, &mut itmp);
            if tmp != HANTRO_OK {
                return tmp;
            }
            pSubMbPred.mvdL0[i as usize][j as usize].hor = itmp as i16;

            tmp = h264bsdDecodeExpGolombSigned(pStrmData, &mut itmp);
            if tmp != HANTRO_OK {
                return tmp;
            }
            pSubMbPred.mvdL0[i as usize][j as usize].ver = itmp as i16;
            j += 1;
        }
        i += 1;
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: DecodeResidual

        Functional description:
          Parse residual information from bit stream and store in 'pResidual'.

------------------------------------------------------------------------------*/

unsafe fn DecodeResidual(
    pStrmData: &mut strmData_t,
    pResidual: &mut residual_t,
    pMb: &mbStorage_t,
    mbType: mbType_e,
    mut codedBlockPattern: u32,
) -> u32 {
    /* Variables */

    let mut i: u32;
    let mut j: u32;
    let mut tmp: u32;
    let mut nc: i32;
    let mut blockCoded: u32;
    let mut blockIndex: u32;
    let is16x16: u32;
    let level: *mut [i32; 16];

    /* Code */

    level = pResidual.level.as_mut_ptr();

    /* luma DC is at index 24 */
    if h264bsdMbPartPredMode(mbType) == PRED_MODE_INTRA16x16 {
        nc = DetermineNc(pMb, 0, pResidual.totalCoeff.as_ptr()) as i32;
        tmp = h264bsdDecodeResidualBlockCavlc(
            pStrmData,
            (*level.add(24)).as_mut_ptr(),
            nc,
            16,
        );
        if (tmp & 0xF) != HANTRO_OK {
            return tmp;
        }
        pResidual.totalCoeff[24] = ((tmp >> 4) & 0xFF) as i16;
        is16x16 = HANTRO_TRUE;
    } else {
        is16x16 = HANTRO_FALSE;
    }

    i = 4;
    blockIndex = 0;
    while i != 0 {
        i -= 1;
        /* luma cbp in bits 0-3 */
        blockCoded = codedBlockPattern & 0x1;
        codedBlockPattern >>= 1;
        if blockCoded != 0 {
            j = 4;
            while j != 0 {
                j -= 1;
                nc = DetermineNc(pMb, blockIndex, pResidual.totalCoeff.as_ptr()) as i32;
                if is16x16 != 0 {
                    tmp = h264bsdDecodeResidualBlockCavlc(
                        pStrmData,
                        (*level.add(blockIndex as usize)).as_mut_ptr().add(1),
                        nc,
                        15,
                    );
                    pResidual.coeffMap[blockIndex as usize] = tmp >> 15;
                } else {
                    tmp = h264bsdDecodeResidualBlockCavlc(
                        pStrmData,
                        (*level.add(blockIndex as usize)).as_mut_ptr(),
                        nc,
                        16,
                    );
                    pResidual.coeffMap[blockIndex as usize] = tmp >> 16;
                }
                if (tmp & 0xF) != HANTRO_OK {
                    return tmp;
                }
                pResidual.totalCoeff[blockIndex as usize] = ((tmp >> 4) & 0xFF) as i16;
                blockIndex += 1;
            }
        } else {
            blockIndex += 4;
        }
    }

    /* chroma DC block are at indices 25 and 26 */
    blockCoded = codedBlockPattern & 0x3;
    if blockCoded != 0 {
        tmp = h264bsdDecodeResidualBlockCavlc(
            pStrmData,
            (*level.add(25)).as_mut_ptr(),
            -1,
            4,
        );
        if (tmp & 0xF) != HANTRO_OK {
            return tmp;
        }
        pResidual.totalCoeff[25] = ((tmp >> 4) & 0xFF) as i16;
        tmp = h264bsdDecodeResidualBlockCavlc(
            pStrmData,
            (*level.add(25)).as_mut_ptr().add(4),
            -1,
            4,
        );
        if (tmp & 0xF) != HANTRO_OK {
            return tmp;
        }
        pResidual.totalCoeff[26] = ((tmp >> 4) & 0xFF) as i16;
    }

    /* chroma AC */
    blockCoded = codedBlockPattern & 0x2;
    if blockCoded != 0 {
        i = 8;
        while i != 0 {
            i -= 1;
            nc = DetermineNc(pMb, blockIndex, pResidual.totalCoeff.as_ptr()) as i32;
            tmp = h264bsdDecodeResidualBlockCavlc(
                pStrmData,
                (*level.add(blockIndex as usize)).as_mut_ptr().add(1),
                nc,
                15,
            );
            if (tmp & 0xF) != HANTRO_OK {
                return tmp;
            }
            pResidual.totalCoeff[blockIndex as usize] = ((tmp >> 4) & 0xFF) as i16;
            pResidual.coeffMap[blockIndex as usize] = tmp >> 15;
            blockIndex += 1;
        }
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: DetermineNc

        Functional description:
          Returns the nC of a block.

------------------------------------------------------------------------------*/

unsafe fn DetermineNc(pMb: &mbStorage_t, blockIndex: u32, pTotalCoeff: *const i16) -> u32 {
    /* Variables */

    let mut tmp: u32;
    let mut n: i32;

    /* Code */

    /* if neighbour block belongs to current macroblock totalCoeff array
     * mbStorage has not been set/updated yet -> use pTotalCoeff */
    let neighbourA = h264bsdNeighbour4x4BlockA(blockIndex);
    let neighbourB = h264bsdNeighbour4x4BlockB(blockIndex);
    let neighbourAindex: u8 = neighbourA.index;
    let neighbourBindex: u8 = neighbourB.index;
    if neighbourA.mb == MB_CURR && neighbourB.mb == MB_CURR {
        n = ((*pTotalCoeff.add(neighbourAindex as usize) as i32)
            + (*pTotalCoeff.add(neighbourBindex as usize) as i32)
            + 1)
            >> 1;
    } else if neighbourA.mb == MB_CURR {
        n = *pTotalCoeff.add(neighbourAindex as usize) as i32;
        if h264bsdIsNeighbourAvailable(pMb, pMb.mbB) != 0 {
            n = (n + (*pMb.mbB).totalCoeff[neighbourBindex as usize] as i32 + 1) >> 1;
        }
    } else if neighbourB.mb == MB_CURR {
        n = *pTotalCoeff.add(neighbourBindex as usize) as i32;
        if h264bsdIsNeighbourAvailable(pMb, pMb.mbA) != 0 {
            n = (n + (*pMb.mbA).totalCoeff[neighbourAindex as usize] as i32 + 1) >> 1;
        }
    } else {
        n = 0;
        tmp = 0;
        if h264bsdIsNeighbourAvailable(pMb, pMb.mbA) != 0 {
            n = (*pMb.mbA).totalCoeff[neighbourAindex as usize] as i32;
            tmp = 1;
        }
        if h264bsdIsNeighbourAvailable(pMb, pMb.mbB) != 0 {
            if tmp != 0 {
                n = (n + (*pMb.mbB).totalCoeff[neighbourBindex as usize] as i32 + 1) >> 1;
            } else {
                n = (*pMb.mbB).totalCoeff[neighbourBindex as usize] as i32;
            }
        }
    }
    n as u32
}

/*------------------------------------------------------------------------------

    Function: CbpIntra16x16

        Functional description:
          Returns the coded block pattern for intra 16x16 macroblock.

------------------------------------------------------------------------------*/

fn CbpIntra16x16(mbType: mbType_e) -> u32 {
    /* Variables */

    let mut cbp: u32;
    let mut tmp: u32;

    /* Code */

    if mbType >= I_16x16_0_0_1 {
        cbp = 15;
    } else {
        cbp = 0;
    }

    /* tmp is 0 for I_16x16_0_0_0 mb type */
    tmp = (mbType - I_16x16_0_0_0) >> 2;
    if tmp > 2 {
        tmp -= 3;
    }

    cbp += tmp << 4;

    cbp
}

/*------------------------------------------------------------------------------

    Function: h264bsdPredModeIntra16x16

        Functional description:
          Returns the prediction mode for intra 16x16 macroblock.

------------------------------------------------------------------------------*/

pub fn h264bsdPredModeIntra16x16(mbType: mbType_e) -> u32 {
    /* Variables */

    let tmp: u32;

    /* Code */

    /* tmp is 0 for I_16x16_0_0_0 mb type */
    tmp = mbType - I_16x16_0_0_0;

    tmp & 0x3
}

/*------------------------------------------------------------------------------

    Function: h264bsdClearMbLayer

        Functional description:
          Clear macroblock layer structure (size bytes).

------------------------------------------------------------------------------*/

// PORT NOTE: the C implementation of this header-declared function is NEON
// assembly (dead in the plain build; plain build uses memset instead).
// Ported as an equivalent byte clear so the manifest signature exists.
pub fn h264bsdClearMbLayer(pMbLayer: &mut macroblockLayer_t, size: u32) -> u32 {
    unsafe {
        core::ptr::write_bytes(pMbLayer as *mut macroblockLayer_t as *mut u8, 0, size as usize);
    }
    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: h264bsdDecodeMacroblock

        Functional description:
          Decode one macroblock and write into output image.

        Inputs:
          pMb           pointer to macroblock specific information
          mbLayer       pointer to current macroblock data from stream
          currImage     pointer to output image
          dpb           pointer to decoded picture buffer
          qpY           pointer to slice QP
          mbNum         current macroblock number
          constrainedIntraPred  flag specifying if neighbouring inter
                                macroblocks are used in intra prediction

        Outputs:
          pMb           structure is updated with current macroblock
          currImage     decoded macroblock is written into output image

        Returns:
          HANTRO_OK     success
          HANTRO_NOK    error in macroblock decoding

------------------------------------------------------------------------------*/

pub unsafe fn h264bsdDecodeMacroblock(
    pMb: &mut mbStorage_t,
    pMbLayer: &mut macroblockLayer_t,
    currImage: &mut image_t,
    dpb: &mut dpbStorage_t,
    qpY: &mut i32,
    mbNum: u32,
    constrainedIntraPredFlag: u32,
    data: *mut u8,
) -> u32 {
    /* Variables */

    let mut i: u32;
    let mut tmp: u32;
    let mbType: mbType_e;

    /* Code */

    mbType = pMbLayer.mbType;
    pMb.mbType = mbType;

    pMb.decoded += 1;

    h264bsdSetCurrImageMbPointers(currImage, mbNum);

    if mbType == I_PCM {
        let mut pData: *mut u8 = data;
        let mut tot: *mut i16 = pMb.totalCoeff.as_mut_ptr();
        let mut lev: *mut i32 = pMbLayer.residual.level[0].as_mut_ptr();

        pMb.qpY = 0;

        /* if decoded flag > 1 -> mb has already been successfully decoded and
         * written to output -> do not write again */
        if pMb.decoded > 1 {
            i = 24;
            while i != 0 {
                i -= 1;
                *tot = 16;
                tot = tot.add(1);
            }
            return HANTRO_OK;
        }

        i = 24;
        while i != 0 {
            i -= 1;
            *tot = 16;
            tot = tot.add(1);
            tmp = 16;
            while tmp != 0 {
                tmp -= 1;
                *pData = *lev as u8;
                pData = pData.add(1);
                lev = lev.add(1);
            }
        }
        h264bsdWriteMacroblock(currImage, data as *const u8);

        return HANTRO_OK;
    } else {
        if mbType != P_Skip {
            core::ptr::copy_nonoverlapping(
                pMbLayer.residual.totalCoeff.as_ptr(),
                pMb.totalCoeff.as_mut_ptr(),
                27,
            );

            /* update qpY */
            if pMbLayer.mbQpDelta != 0 {
                *qpY = *qpY + pMbLayer.mbQpDelta;
                if *qpY < 0 {
                    *qpY += 52;
                } else if *qpY >= 52 {
                    *qpY -= 52;
                }
            }
            pMb.qpY = *qpY as u32;

            tmp = ProcessResidual(
                pMb,
                pMbLayer.residual.level.as_mut_ptr(),
                pMbLayer.residual.coeffMap.as_mut_ptr(),
            );
            if tmp != HANTRO_OK {
                return tmp;
            }
        } else {
            core::ptr::write_bytes(pMb.totalCoeff.as_mut_ptr(), 0, 27);
            pMb.qpY = *qpY as u32;
        }

        if h264bsdMbPartPredMode(mbType) != PRED_MODE_INTER {
            tmp = h264bsdIntraPrediction(
                pMb,
                pMbLayer,
                currImage,
                mbNum,
                constrainedIntraPredFlag,
                data,
            );
            if tmp != HANTRO_OK {
                return tmp;
            }
        } else {
            tmp = h264bsdInterPrediction(pMb, pMbLayer, dpb, mbNum, currImage, data);
            if tmp != HANTRO_OK {
                return tmp;
            }
        }
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: ProcessResidual

        Functional description:
          Process the residual data of one macroblock with
          inverse quantization and inverse transform.

------------------------------------------------------------------------------*/

unsafe fn ProcessResidual(
    pMb: &mut mbStorage_t,
    residualLevel: *mut [i32; 16],
    mut coeffMap: *mut u32,
) -> u32 {
    /* Variables */

    let mut i: u32;
    let chromaQp: u32;
    let mut blockData: *mut [i32; 16];
    let blockDc: *mut [i32; 16];
    let mut totalCoeff: *const i16;
    let mut chromaDc: *mut i32;
    let mut dcCoeffIdx: *const u32;

    /* Code */

    /* set pointers to DC coefficient blocks */
    blockDc = residualLevel.add(24);

    blockData = residualLevel;
    totalCoeff = pMb.totalCoeff.as_ptr();
    if h264bsdMbPartPredMode(pMb.mbType) == PRED_MODE_INTRA16x16 {
        if *totalCoeff.add(24) != 0 {
            h264bsdProcessLumaDc((*blockDc).as_mut_ptr(), pMb.qpY);
        }
        dcCoeffIdx = dcCoeffIndex.as_ptr();

        i = 16;
        while i != 0 {
            i -= 1;
            /* set dc coefficient of luma block */
            (*blockData)[0] = (*blockDc)[*dcCoeffIdx as usize];
            dcCoeffIdx = dcCoeffIdx.add(1);
            if (*blockData)[0] != 0 || *totalCoeff != 0 {
                if h264bsdProcessBlock((*blockData).as_mut_ptr(), pMb.qpY, 1, *coeffMap)
                    != HANTRO_OK
                {
                    return HANTRO_NOK;
                }
            } else {
                MARK_RESIDUAL_EMPTY(&mut *blockData);
            }
            blockData = blockData.add(1);
            totalCoeff = totalCoeff.add(1);
            coeffMap = coeffMap.add(1);
        }
    } else {
        i = 16;
        while i != 0 {
            i -= 1;
            if *totalCoeff != 0 {
                if h264bsdProcessBlock((*blockData).as_mut_ptr(), pMb.qpY, 0, *coeffMap)
                    != HANTRO_OK
                {
                    return HANTRO_NOK;
                }
            } else {
                MARK_RESIDUAL_EMPTY(&mut *blockData);
            }
            blockData = blockData.add(1);
            totalCoeff = totalCoeff.add(1);
            coeffMap = coeffMap.add(1);
        }
    }

    /* chroma DC processing. First chroma dc block is block with index 25 */
    chromaQp =
        h264bsdQpC[CLIP3!(0, 51, pMb.qpY as i32 + pMb.chromaQpIndexOffset) as usize];
    if pMb.totalCoeff[25] != 0 || pMb.totalCoeff[26] != 0 {
        h264bsdProcessChromaDc((*residualLevel.add(25)).as_mut_ptr(), chromaQp);
    }
    chromaDc = (*residualLevel.add(25)).as_mut_ptr();
    i = 8;
    while i != 0 {
        i -= 1;
        /* set dc coefficient of chroma block */
        (*blockData)[0] = *chromaDc;
        chromaDc = chromaDc.add(1);
        if (*blockData)[0] != 0 || *totalCoeff != 0 {
            if h264bsdProcessBlock((*blockData).as_mut_ptr(), chromaQp, 1, *coeffMap)
                != HANTRO_OK
            {
                return HANTRO_NOK;
            }
        } else {
            MARK_RESIDUAL_EMPTY(&mut *blockData);
        }
        blockData = blockData.add(1);
        totalCoeff = totalCoeff.add(1);
        coeffMap = coeffMap.add(1);
    }

    HANTRO_OK
}

/*------------------------------------------------------------------------------

    Function: h264bsdSubMbPartMode

        Functional description:
          Returns the macroblock's sub-partition mode.

------------------------------------------------------------------------------*/

pub fn h264bsdSubMbPartMode(subMbType: subMbType_e) -> subMbPartMode_e {
    subMbType as subMbPartMode_e
}
