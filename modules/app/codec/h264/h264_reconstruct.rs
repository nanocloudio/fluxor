// Mechanical Rust port of h264bsd_reconstruct.c (plain path: H264DEC_OMXDL
// and H264DEC_NEON undefined) and h264bsd_image.c (h264bsdWriteMacroblock +
// h264bsdWriteOutputBlocks), per the port rules in PORT_RULES.md.
//
// This is the inter-prediction reconstruction core: 6-tap luma interpolation
// (half/quarter-pel positions a..s) and bilinear 1/8-pel chroma interpolation,
// plus edge overfilling (FillBlock/FillRow) and the macroblock image writers.
//
// `ref` is a Rust keyword; the C parameter/local `ref` is renamed `ref_`
// throughout (as noted in the manifest).
//
// SKIPPED (dead in our build):
// - h264bsd_reconstruct.c OMXDL variant of h264bsdPredictSamples
//   (H264DEC_OMXDL path).
// - h264bsd_image.c h264bsdConvertToRGBA/BGRA/YCbCrA converters (dead).
//
// Clipping table h264bsdClip and block coordinate tables h264bsdBlockX/
// h264bsdBlockY are defined in h264bsd_intra_prediction.c -> super::h264_intra.

#![allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code,
    unused_assignments,
    unused_mut,
    unused_variables,
    clippy::all
)]

use super::*;
use super::h264_intra::*;

/* Luma fractional-sample positions
 *
 *  G a b c H
 *  d e f g
 *  h i j k m
 *  n p q r
 *  M   s   N
 *
 *  G, H, M and N are integer sample positions
 *  a-s are fractional samples that need to be interpolated.
 */
static lumaFracPos: [[u32; 4]; 4] = [
    /* G  d  h  n    a  e  i  p    b  f  j   q     c   g   k   r */
    [0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15],
];

/*------------------------------------------------------------------------------

    Function: h264bsdInterpolateChromaHor

        Functional description:
          This function performs chroma interpolation in horizontal direction.
          Overfilling is done only if needed. Reference image (pRef) is
          read at correct position and the predicted part is written to
          macroblock's chrominance (predPartChroma)

------------------------------------------------------------------------------*/
pub unsafe fn h264bsdInterpolateChromaHor(
    pRef: *mut u8,
    predPartChroma: *mut u8,
    x0: i32,
    y0: i32,
    width: u32,
    height: u32,
    xFrac: u32,
    chromaPartWidth: u32,
    chromaPartHeight: u32,
) {
    /* Variables */

    let mut x: u32;
    let mut y: u32;
    let mut tmp1: u32;
    let mut tmp2: u32;
    let mut tmp3: u32;
    let mut tmp4: u32;
    let mut c: u32;
    let val: u32;
    let mut ptrA: *const u8;
    let mut cbr: *mut u8;
    let mut comp: u32;
    let mut block = [0u8; 9 * 8 * 2];

    let mut pRef: *const u8 = pRef;
    let mut x0 = x0;
    let mut y0 = y0;
    let mut width = width;
    let mut height = height;

    /* Code */

    if (x0 < 0)
        || ((x0 as u32).wrapping_add(chromaPartWidth).wrapping_add(1) > width)
        || (y0 < 0)
        || ((y0 as u32).wrapping_add(chromaPartHeight) > height)
    {
        h264bsdFillBlock(
            pRef,
            block.as_mut_ptr(),
            x0,
            y0,
            width,
            height,
            chromaPartWidth + 1,
            chromaPartHeight,
            chromaPartWidth + 1,
        );
        pRef = pRef.add((width * height) as usize);
        h264bsdFillBlock(
            pRef,
            block
                .as_mut_ptr()
                .add(((chromaPartWidth + 1) * chromaPartHeight) as usize),
            x0,
            y0,
            width,
            height,
            chromaPartWidth + 1,
            chromaPartHeight,
            chromaPartWidth + 1,
        );

        pRef = block.as_ptr();
        x0 = 0;
        y0 = 0;
        width = chromaPartWidth + 1;
        height = chromaPartHeight;
    }

    val = 8 - xFrac;

    comp = 0;
    while comp <= 1 {
        ptrA = pRef
            .add(((comp * height + y0 as u32) * width) as usize)
            .offset(x0 as isize);
        cbr = predPartChroma.add((comp * 8 * 8) as usize);

        /* 2x2 pels per iteration
         * bilinear horizontal interpolation */
        y = chromaPartHeight >> 1;
        while y != 0 {
            x = chromaPartWidth >> 1;
            while x != 0 {
                tmp1 = *ptrA.add(width as usize) as u32;
                tmp2 = *ptrA as u32;
                ptrA = ptrA.add(1);
                tmp3 = *ptrA.add(width as usize) as u32;
                tmp4 = *ptrA as u32;
                ptrA = ptrA.add(1);
                c = ((val * tmp1 + xFrac * tmp3) << 3) + 32;
                c >>= 6;
                *cbr.add(8) = c as u8;
                c = ((val * tmp2 + xFrac * tmp4) << 3) + 32;
                c >>= 6;
                *cbr = c as u8;
                cbr = cbr.add(1);
                tmp1 = *ptrA.add(width as usize) as u32;
                tmp2 = *ptrA as u32;
                c = ((val * tmp3 + xFrac * tmp1) << 3) + 32;
                c >>= 6;
                *cbr.add(8) = c as u8;
                c = ((val * tmp4 + xFrac * tmp2) << 3) + 32;
                c >>= 6;
                *cbr = c as u8;
                cbr = cbr.add(1);
                x -= 1;
            }
            cbr = cbr.add((2 * 8 - chromaPartWidth) as usize);
            ptrA = ptrA.add((2 * width - chromaPartWidth) as usize);
            y -= 1;
        }
        comp += 1;
    }
}

/*------------------------------------------------------------------------------

    Function: h264bsdInterpolateChromaVer

        Functional description:
          This function performs chroma interpolation in vertical direction.
          Overfilling is done only if needed. Reference image (pRef) is
          read at correct position and the predicted part is written to
          macroblock's chrominance (predPartChroma)

------------------------------------------------------------------------------*/
pub unsafe fn h264bsdInterpolateChromaVer(
    pRef: *mut u8,
    predPartChroma: *mut u8,
    x0: i32,
    y0: i32,
    width: u32,
    height: u32,
    yFrac: u32,
    chromaPartWidth: u32,
    chromaPartHeight: u32,
) {
    /* Variables */

    let mut x: u32;
    let mut y: u32;
    let mut tmp1: u32;
    let mut tmp2: u32;
    let mut tmp3: u32;
    let mut c: u32;
    let val: u32;
    let mut ptrA: *const u8;
    let mut cbr: *mut u8;
    let mut comp: u32;
    let mut block = [0u8; 9 * 8 * 2];

    let mut pRef: *const u8 = pRef;
    let mut x0 = x0;
    let mut y0 = y0;
    let mut width = width;
    let mut height = height;

    /* Code */

    if (x0 < 0)
        || ((x0 as u32).wrapping_add(chromaPartWidth) > width)
        || (y0 < 0)
        || ((y0 as u32).wrapping_add(chromaPartHeight).wrapping_add(1) > height)
    {
        h264bsdFillBlock(
            pRef,
            block.as_mut_ptr(),
            x0,
            y0,
            width,
            height,
            chromaPartWidth,
            chromaPartHeight + 1,
            chromaPartWidth,
        );
        pRef = pRef.add((width * height) as usize);
        h264bsdFillBlock(
            pRef,
            block
                .as_mut_ptr()
                .add((chromaPartWidth * (chromaPartHeight + 1)) as usize),
            x0,
            y0,
            width,
            height,
            chromaPartWidth,
            chromaPartHeight + 1,
            chromaPartWidth,
        );

        pRef = block.as_ptr();
        x0 = 0;
        y0 = 0;
        width = chromaPartWidth;
        height = chromaPartHeight + 1;
    }

    val = 8 - yFrac;

    comp = 0;
    while comp <= 1 {
        ptrA = pRef
            .add(((comp * height + y0 as u32) * width) as usize)
            .offset(x0 as isize);
        cbr = predPartChroma.add((comp * 8 * 8) as usize);

        /* 2x2 pels per iteration
         * bilinear vertical interpolation */
        y = chromaPartHeight >> 1;
        while y != 0 {
            x = chromaPartWidth >> 1;
            while x != 0 {
                tmp3 = *ptrA.add((width * 2) as usize) as u32;
                tmp2 = *ptrA.add(width as usize) as u32;
                tmp1 = *ptrA as u32;
                ptrA = ptrA.add(1);
                c = ((val * tmp2 + yFrac * tmp3) << 3) + 32;
                c >>= 6;
                *cbr.add(8) = c as u8;
                c = ((val * tmp1 + yFrac * tmp2) << 3) + 32;
                c >>= 6;
                *cbr = c as u8;
                cbr = cbr.add(1);
                tmp3 = *ptrA.add((width * 2) as usize) as u32;
                tmp2 = *ptrA.add(width as usize) as u32;
                tmp1 = *ptrA as u32;
                ptrA = ptrA.add(1);
                c = ((val * tmp2 + yFrac * tmp3) << 3) + 32;
                c >>= 6;
                *cbr.add(8) = c as u8;
                c = ((val * tmp1 + yFrac * tmp2) << 3) + 32;
                c >>= 6;
                *cbr = c as u8;
                cbr = cbr.add(1);
                x -= 1;
            }
            cbr = cbr.add((2 * 8 - chromaPartWidth) as usize);
            ptrA = ptrA.add((2 * width - chromaPartWidth) as usize);
            y -= 1;
        }
        comp += 1;
    }
}

/*------------------------------------------------------------------------------

    Function: h264bsdInterpolateChromaHorVer

        Functional description:
          This function performs chroma interpolation in horizontal and
          vertical direction. Overfilling is done only if needed. Reference
          image (ref) is read at correct position and the predicted part
          is written to macroblock's chrominance (predPartChroma)

------------------------------------------------------------------------------*/
pub unsafe fn h264bsdInterpolateChromaHorVer(
    ref_: *mut u8,
    predPartChroma: *mut u8,
    x0: i32,
    y0: i32,
    width: u32,
    height: u32,
    xFrac: u32,
    yFrac: u32,
    chromaPartWidth: u32,
    chromaPartHeight: u32,
) {
    let mut block = [0u8; 9 * 9 * 2];
    let mut x: u32;
    let mut y: u32;
    let mut tmp1: u32;
    let mut tmp2: u32;
    let mut tmp3: u32;
    let mut tmp4: u32;
    let mut tmp5: u32;
    let mut tmp6: u32;
    let valX: u32;
    let valY: u32;
    let plus32: u32 = 32;
    let mut comp: u32;
    let mut ptrA: *const u8;
    let mut cbr: *mut u8;

    let mut ref_: *const u8 = ref_;
    let mut x0 = x0;
    let mut y0 = y0;
    let mut width = width;
    let mut height = height;

    /* Code */

    if (x0 < 0)
        || ((x0 as u32).wrapping_add(chromaPartWidth).wrapping_add(1) > width)
        || (y0 < 0)
        || ((y0 as u32).wrapping_add(chromaPartHeight).wrapping_add(1) > height)
    {
        h264bsdFillBlock(
            ref_,
            block.as_mut_ptr(),
            x0,
            y0,
            width,
            height,
            chromaPartWidth + 1,
            chromaPartHeight + 1,
            chromaPartWidth + 1,
        );
        ref_ = ref_.add((width * height) as usize);
        h264bsdFillBlock(
            ref_,
            block
                .as_mut_ptr()
                .add(((chromaPartWidth + 1) * (chromaPartHeight + 1)) as usize),
            x0,
            y0,
            width,
            height,
            chromaPartWidth + 1,
            chromaPartHeight + 1,
            chromaPartWidth + 1,
        );

        ref_ = block.as_ptr();
        x0 = 0;
        y0 = 0;
        width = chromaPartWidth + 1;
        height = chromaPartHeight + 1;
    }

    valX = 8 - xFrac;
    valY = 8 - yFrac;

    comp = 0;
    while comp <= 1 {
        ptrA = ref_
            .add(((comp * height + y0 as u32) * width) as usize)
            .offset(x0 as isize);
        cbr = predPartChroma.add((comp * 8 * 8) as usize);

        /* 2x2 pels per iteration
         * bilinear vertical and horizontal interpolation */
        y = chromaPartHeight >> 1;
        while y != 0 {
            tmp1 = *ptrA as u32;
            tmp3 = *ptrA.add(width as usize) as u32;
            tmp5 = *ptrA.add((width * 2) as usize) as u32;
            tmp1 *= valY;
            tmp1 += tmp3 * yFrac;
            tmp3 *= valY;
            tmp3 += tmp5 * yFrac;
            x = chromaPartWidth >> 1;
            while x != 0 {
                ptrA = ptrA.add(1);
                tmp2 = *ptrA as u32;
                tmp4 = *ptrA.add(width as usize) as u32;
                tmp6 = *ptrA.add((width * 2) as usize) as u32;
                tmp2 *= valY;
                tmp2 += tmp4 * yFrac;
                tmp4 *= valY;
                tmp4 += tmp6 * yFrac;
                tmp1 = tmp1 * valX + plus32;
                tmp3 = tmp3 * valX + plus32;
                tmp1 += tmp2 * xFrac;
                tmp1 >>= 6;
                tmp3 += tmp4 * xFrac;
                tmp3 >>= 6;
                *cbr.add(8) = tmp3 as u8;
                *cbr = tmp1 as u8;
                cbr = cbr.add(1);

                ptrA = ptrA.add(1);
                tmp1 = *ptrA as u32;
                tmp3 = *ptrA.add(width as usize) as u32;
                tmp5 = *ptrA.add((width * 2) as usize) as u32;
                tmp1 *= valY;
                tmp1 += tmp3 * yFrac;
                tmp3 *= valY;
                tmp3 += tmp5 * yFrac;
                tmp2 = tmp2 * valX + plus32;
                tmp4 = tmp4 * valX + plus32;
                tmp2 += tmp1 * xFrac;
                tmp2 >>= 6;
                tmp4 += tmp3 * xFrac;
                tmp4 >>= 6;
                *cbr.add(8) = tmp4 as u8;
                *cbr = tmp2 as u8;
                cbr = cbr.add(1);
                x -= 1;
            }
            cbr = cbr.add((2 * 8 - chromaPartWidth) as usize);
            ptrA = ptrA.add((2 * width - chromaPartWidth) as usize);
            y -= 1;
        }
        comp += 1;
    }
}

/*------------------------------------------------------------------------------

    Function: PredictChroma

        Functional description:
          Top level chroma prediction function that calls the appropriate
          interpolation function. The output is written to macroblock array.

------------------------------------------------------------------------------*/
unsafe fn PredictChroma(
    mbPartChroma: *mut u8,
    xAL: u32,
    yAL: u32,
    partWidth: u32,
    partHeight: u32,
    mv: &mv_t,
    refPic: &image_t,
) {
    /* Variables */

    let xFrac: u32;
    let yFrac: u32;
    let width: u32;
    let height: u32;
    let chromaPartWidth: u32;
    let chromaPartHeight: u32;
    let xInt: i32;
    let yInt: i32;
    let mut ref_: *mut u8;

    /* Code */

    width = 8 * refPic.width;
    height = 8 * refPic.height;

    /* C: xInt = (xAL >> 1) + (mv->hor >> 3); unsigned add reinterpreted
     * as signed — identical to signed add in two's complement */
    xInt = ((xAL >> 1) as i32).wrapping_add((mv.hor as i32) >> 3);
    yInt = ((yAL >> 1) as i32).wrapping_add((mv.ver as i32) >> 3);
    xFrac = ((mv.hor as i32) & 0x7) as u32;
    yFrac = ((mv.ver as i32) & 0x7) as u32;

    chromaPartWidth = partWidth >> 1;
    chromaPartHeight = partHeight >> 1;
    ref_ = refPic
        .data
        .add((256 * refPic.width * refPic.height) as usize);

    if xFrac != 0 && yFrac != 0 {
        h264bsdInterpolateChromaHorVer(
            ref_,
            mbPartChroma,
            xInt,
            yInt,
            width,
            height,
            xFrac,
            yFrac,
            chromaPartWidth,
            chromaPartHeight,
        );
    } else if xFrac != 0 {
        h264bsdInterpolateChromaHor(
            ref_,
            mbPartChroma,
            xInt,
            yInt,
            width,
            height,
            xFrac,
            chromaPartWidth,
            chromaPartHeight,
        );
    } else if yFrac != 0 {
        h264bsdInterpolateChromaVer(
            ref_,
            mbPartChroma,
            xInt,
            yInt,
            width,
            height,
            yFrac,
            chromaPartWidth,
            chromaPartHeight,
        );
    } else {
        h264bsdFillBlock(
            ref_,
            mbPartChroma,
            xInt,
            yInt,
            width,
            height,
            chromaPartWidth,
            chromaPartHeight,
            8,
        );
        ref_ = ref_.add((width * height) as usize);
        h264bsdFillBlock(
            ref_,
            mbPartChroma.add(8 * 8),
            xInt,
            yInt,
            width,
            height,
            chromaPartWidth,
            chromaPartHeight,
            8,
        );
    }
}

/*------------------------------------------------------------------------------

    Function: h264bsdInterpolateVerHalf

        Functional description:
          Function to perform vertical interpolation of pixel position 'h'
          for a block. Overfilling is done only if needed. Reference
          image (ref) is read at correct position and the predicted part
          is written to macroblock array (mb)

------------------------------------------------------------------------------*/
pub unsafe fn h264bsdInterpolateVerHalf(
    ref_: *mut u8,
    mb: *mut u8,
    x0: i32,
    y0: i32,
    width: u32,
    height: u32,
    partWidth: u32,
    partHeight: u32,
) {
    let mut p1 = [0u32; 21 * 21 / 4 + 1];
    let mut i: u32;
    let mut j: u32;
    let mut tmp1: i32;
    let mut tmp2: i32;
    let mut tmp3: i32;
    let mut tmp4: i32;
    let mut tmp5: i32;
    let mut tmp6: i32;
    let mut tmp7: i32;
    let mut ptrC: *const u8;
    let mut ptrV: *const u8;
    let clp: *const u8 = h264bsdClip.as_ptr().add(512);

    let mut ref_: *const u8 = ref_;
    let mut mb = mb;
    let mut x0 = x0;
    let mut y0 = y0;
    let mut width = width;

    /* Code */

    if (x0 < 0)
        || ((x0 as u32).wrapping_add(partWidth) > width)
        || (y0 < 0)
        || ((y0 as u32).wrapping_add(partHeight).wrapping_add(5) > height)
    {
        h264bsdFillBlock(
            ref_,
            p1.as_mut_ptr() as *mut u8,
            x0,
            y0,
            width,
            height,
            partWidth,
            partHeight + 5,
            partWidth,
        );

        x0 = 0;
        y0 = 0;
        ref_ = p1.as_ptr() as *const u8;
        width = partWidth;
    }

    ref_ = ref_.add((y0 as u32 * width + x0 as u32) as usize);

    ptrC = ref_.add(width as usize);
    ptrV = ptrC.add((5 * width) as usize);

    /* 4 pixels per iteration, interpolate using 5 vertical samples */
    i = partHeight >> 2;
    while i != 0 {
        /* h1 = (16 + A + 16(G+M) + 4(G+M) - 4(C+R) - (C+R) + T) >> 5 */
        j = partWidth;
        while j != 0 {
            tmp4 = *ptrV.offset(-((width as i32) * 2) as isize) as i32;
            tmp5 = *ptrV.offset(-(width as i32) as isize) as i32;
            tmp1 = *ptrV.add(width as usize) as i32;
            tmp2 = *ptrV.add((width * 2) as usize) as i32;
            tmp6 = *ptrV as i32;
            ptrV = ptrV.add(1);

            tmp7 = tmp4 + tmp1;
            tmp2 -= tmp7 << 2;
            tmp2 -= tmp7;
            tmp2 += 16;
            tmp7 = tmp5 + tmp6;
            tmp3 = *ptrC.add((width * 2) as usize) as i32;
            tmp2 += tmp7 << 4;
            tmp2 += tmp7 << 2;
            tmp2 += tmp3;
            tmp2 = *clp.offset((tmp2 >> 5) as isize) as i32;
            tmp1 += 16;
            *mb.add(48) = tmp2 as u8;

            tmp7 = tmp3 + tmp6;
            tmp1 -= tmp7 << 2;
            tmp1 -= tmp7;
            tmp7 = tmp4 + tmp5;
            tmp2 = *ptrC.add(width as usize) as i32;
            tmp1 += tmp7 << 4;
            tmp1 += tmp7 << 2;
            tmp1 += tmp2;
            tmp1 = *clp.offset((tmp1 >> 5) as isize) as i32;
            tmp6 += 16;
            *mb.add(32) = tmp1 as u8;

            tmp7 = tmp2 + tmp5;
            tmp6 -= tmp7 << 2;
            tmp6 -= tmp7;
            tmp7 = tmp4 + tmp3;
            tmp1 = *ptrC as i32;
            tmp6 += tmp7 << 4;
            tmp6 += tmp7 << 2;
            tmp6 += tmp1;
            tmp6 = *clp.offset((tmp6 >> 5) as isize) as i32;
            tmp5 += 16;
            *mb.add(16) = tmp6 as u8;

            tmp1 += tmp4;
            tmp5 -= tmp1 << 2;
            tmp5 -= tmp1;
            tmp3 += tmp2;
            tmp6 = *ptrC.offset(-(width as i32) as isize) as i32;
            tmp5 += tmp3 << 4;
            tmp5 += tmp3 << 2;
            tmp5 += tmp6;
            tmp5 = *clp.offset((tmp5 >> 5) as isize) as i32;
            *mb = tmp5 as u8;
            mb = mb.add(1);
            ptrC = ptrC.add(1);
            j -= 1;
        }
        ptrC = ptrC.add((4 * width - partWidth) as usize);
        ptrV = ptrV.add((4 * width - partWidth) as usize);
        mb = mb.add((4 * 16 - partWidth) as usize);
        i -= 1;
    }
}

/*------------------------------------------------------------------------------

    Function: h264bsdInterpolateVerQuarter

        Functional description:
          Function to perform vertical interpolation of pixel position 'd'
          or 'n' for a block. Overfilling is done only if needed. Reference
          image (ref) is read at correct position and the predicted part
          is written to macroblock array (mb)

------------------------------------------------------------------------------*/
pub unsafe fn h264bsdInterpolateVerQuarter(
    ref_: *mut u8,
    mb: *mut u8,
    x0: i32,
    y0: i32,
    width: u32,
    height: u32,
    partWidth: u32,
    partHeight: u32,
    verOffset: u32, /* 0 for pixel d, 1 for pixel n */
) {
    let mut p1 = [0u32; 21 * 21 / 4 + 1];
    let mut i: u32;
    let mut j: u32;
    let mut tmp1: i32;
    let mut tmp2: i32;
    let mut tmp3: i32;
    let mut tmp4: i32;
    let mut tmp5: i32;
    let mut tmp6: i32;
    let mut tmp7: i32;
    let mut ptrC: *const u8;
    let mut ptrV: *const u8;
    let mut ptrInt: *const u8;
    let clp: *const u8 = h264bsdClip.as_ptr().add(512);

    let mut ref_: *const u8 = ref_;
    let mut mb = mb;
    let mut x0 = x0;
    let mut y0 = y0;
    let mut width = width;

    /* Code */

    if (x0 < 0)
        || ((x0 as u32).wrapping_add(partWidth) > width)
        || (y0 < 0)
        || ((y0 as u32).wrapping_add(partHeight).wrapping_add(5) > height)
    {
        h264bsdFillBlock(
            ref_,
            p1.as_mut_ptr() as *mut u8,
            x0,
            y0,
            width,
            height,
            partWidth,
            partHeight + 5,
            partWidth,
        );

        x0 = 0;
        y0 = 0;
        ref_ = p1.as_ptr() as *const u8;
        width = partWidth;
    }

    ref_ = ref_.add((y0 as u32 * width + x0 as u32) as usize);

    ptrC = ref_.add(width as usize);
    ptrV = ptrC.add((5 * width) as usize);

    /* Pointer to integer sample position, either M or R */
    ptrInt = ptrC.add(((2 + verOffset) * width) as usize);

    /* 4 pixels per iteration
     * interpolate using 5 vertical samples and average between
     * interpolated value and integer sample value */
    i = partHeight >> 2;
    while i != 0 {
        /* h1 = (16 + A + 16(G+M) + 4(G+M) - 4(C+R) - (C+R) + T) >> 5 */
        j = partWidth;
        while j != 0 {
            tmp4 = *ptrV.offset(-((width as i32) * 2) as isize) as i32;
            tmp5 = *ptrV.offset(-(width as i32) as isize) as i32;
            tmp1 = *ptrV.add(width as usize) as i32;
            tmp2 = *ptrV.add((width * 2) as usize) as i32;
            tmp6 = *ptrV as i32;
            ptrV = ptrV.add(1);

            tmp7 = tmp4 + tmp1;
            tmp2 -= tmp7 << 2;
            tmp2 -= tmp7;
            tmp2 += 16;
            tmp7 = tmp5 + tmp6;
            tmp3 = *ptrC.add((width * 2) as usize) as i32;
            tmp2 += tmp7 << 4;
            tmp2 += tmp7 << 2;
            tmp2 += tmp3;
            tmp2 = *clp.offset((tmp2 >> 5) as isize) as i32;
            tmp7 = *ptrInt.add((width * 2) as usize) as i32;
            tmp1 += 16;
            tmp2 += 1;
            *mb.add(48) = ((tmp2 + tmp7) >> 1) as u8;

            tmp7 = tmp3 + tmp6;
            tmp1 -= tmp7 << 2;
            tmp1 -= tmp7;
            tmp7 = tmp4 + tmp5;
            tmp2 = *ptrC.add(width as usize) as i32;
            tmp1 += tmp7 << 4;
            tmp1 += tmp7 << 2;
            tmp1 += tmp2;
            tmp1 = *clp.offset((tmp1 >> 5) as isize) as i32;
            tmp7 = *ptrInt.add(width as usize) as i32;
            tmp6 += 16;
            tmp1 += 1;
            *mb.add(32) = ((tmp1 + tmp7) >> 1) as u8;

            tmp7 = tmp2 + tmp5;
            tmp6 -= tmp7 << 2;
            tmp6 -= tmp7;
            tmp7 = tmp4 + tmp3;
            tmp1 = *ptrC as i32;
            tmp6 += tmp7 << 4;
            tmp6 += tmp7 << 2;
            tmp6 += tmp1;
            tmp6 = *clp.offset((tmp6 >> 5) as isize) as i32;
            tmp7 = *ptrInt as i32;
            tmp5 += 16;
            tmp6 += 1;
            *mb.add(16) = ((tmp6 + tmp7) >> 1) as u8;

            tmp1 += tmp4;
            tmp5 -= tmp1 << 2;
            tmp5 -= tmp1;
            tmp3 += tmp2;
            tmp6 = *ptrC.offset(-(width as i32) as isize) as i32;
            tmp5 += tmp3 << 4;
            tmp5 += tmp3 << 2;
            tmp5 += tmp6;
            tmp5 = *clp.offset((tmp5 >> 5) as isize) as i32;
            tmp7 = *ptrInt.offset(-(width as i32) as isize) as i32;
            tmp5 += 1;
            *mb = ((tmp5 + tmp7) >> 1) as u8;
            mb = mb.add(1);
            ptrC = ptrC.add(1);
            ptrInt = ptrInt.add(1);
            j -= 1;
        }
        ptrC = ptrC.add((4 * width - partWidth) as usize);
        ptrV = ptrV.add((4 * width - partWidth) as usize);
        ptrInt = ptrInt.add((4 * width - partWidth) as usize);
        mb = mb.add((4 * 16 - partWidth) as usize);
        i -= 1;
    }
}

/*------------------------------------------------------------------------------

    Function: h264bsdInterpolateHorHalf

        Functional description:
          Function to perform horizontal interpolation of pixel position 'b'
          for a block. Overfilling is done only if needed. Reference
          image (ref) is read at correct position and the predicted part
          is written to macroblock array (mb)

------------------------------------------------------------------------------*/
pub unsafe fn h264bsdInterpolateHorHalf(
    ref_: *mut u8,
    mb: *mut u8,
    x0: i32,
    y0: i32,
    width: u32,
    height: u32,
    partWidth: u32,
    partHeight: u32,
) {
    let mut p1 = [0u32; 21 * 21 / 4 + 1];
    let mut ptrJ: *const u8;
    let mut x: u32;
    let mut y: u32;
    let mut tmp1: i32;
    let mut tmp2: i32;
    let mut tmp3: i32;
    let mut tmp4: i32;
    let mut tmp5: i32;
    let mut tmp6: i32;
    let mut tmp7: i32;
    let clp: *const u8 = h264bsdClip.as_ptr().add(512);

    let mut ref_: *const u8 = ref_;
    let mut mb = mb;
    let mut x0 = x0;
    let mut y0 = y0;
    let mut width = width;

    /* Code */

    if (x0 < 0)
        || ((x0 as u32).wrapping_add(partWidth).wrapping_add(5) > width)
        || (y0 < 0)
        || ((y0 as u32).wrapping_add(partHeight) > height)
    {
        h264bsdFillBlock(
            ref_,
            p1.as_mut_ptr() as *mut u8,
            x0,
            y0,
            width,
            height,
            partWidth + 5,
            partHeight,
            partWidth + 5,
        );

        x0 = 0;
        y0 = 0;
        ref_ = p1.as_ptr() as *const u8;
        width = partWidth + 5;
    }

    ref_ = ref_.add((y0 as u32 * width + x0 as u32) as usize);

    ptrJ = ref_.add(5);

    y = partHeight;
    while y != 0 {
        tmp6 = *ptrJ.offset(-5) as i32;
        tmp5 = *ptrJ.offset(-4) as i32;
        tmp4 = *ptrJ.offset(-3) as i32;
        tmp3 = *ptrJ.offset(-2) as i32;
        tmp2 = *ptrJ.offset(-1) as i32;

        /* calculate 4 pels per iteration */
        x = partWidth >> 2;
        while x != 0 {
            /* First pixel */
            tmp6 += 16;
            tmp7 = tmp3 + tmp4;
            tmp6 += tmp7 << 4;
            tmp6 += tmp7 << 2;
            tmp7 = tmp2 + tmp5;
            tmp1 = *ptrJ as i32;
            ptrJ = ptrJ.add(1);
            tmp6 -= tmp7 << 2;
            tmp6 -= tmp7;
            tmp6 += tmp1;
            tmp6 = *clp.offset((tmp6 >> 5) as isize) as i32;
            /* Second pixel */
            tmp5 += 16;
            tmp7 = tmp2 + tmp3;
            *mb = tmp6 as u8;
            mb = mb.add(1);
            tmp5 += tmp7 << 4;
            tmp5 += tmp7 << 2;
            tmp7 = tmp1 + tmp4;
            tmp6 = *ptrJ as i32;
            ptrJ = ptrJ.add(1);
            tmp5 -= tmp7 << 2;
            tmp5 -= tmp7;
            tmp5 += tmp6;
            tmp5 = *clp.offset((tmp5 >> 5) as isize) as i32;
            /* Third pixel */
            tmp4 += 16;
            tmp7 = tmp1 + tmp2;
            *mb = tmp5 as u8;
            mb = mb.add(1);
            tmp4 += tmp7 << 4;
            tmp4 += tmp7 << 2;
            tmp7 = tmp6 + tmp3;
            tmp5 = *ptrJ as i32;
            ptrJ = ptrJ.add(1);
            tmp4 -= tmp7 << 2;
            tmp4 -= tmp7;
            tmp4 += tmp5;
            tmp4 = *clp.offset((tmp4 >> 5) as isize) as i32;
            /* Fourth pixel */
            tmp3 += 16;
            tmp7 = tmp6 + tmp1;
            *mb = tmp4 as u8;
            mb = mb.add(1);
            tmp3 += tmp7 << 4;
            tmp3 += tmp7 << 2;
            tmp7 = tmp5 + tmp2;
            tmp4 = *ptrJ as i32;
            ptrJ = ptrJ.add(1);
            tmp3 -= tmp7 << 2;
            tmp3 -= tmp7;
            tmp3 += tmp4;
            tmp3 = *clp.offset((tmp3 >> 5) as isize) as i32;
            tmp7 = tmp4;
            tmp4 = tmp6;
            tmp6 = tmp2;
            tmp2 = tmp7;
            *mb = tmp3 as u8;
            mb = mb.add(1);
            tmp3 = tmp5;
            tmp5 = tmp1;
            x -= 1;
        }
        ptrJ = ptrJ.add((width - partWidth) as usize);
        mb = mb.add((16 - partWidth) as usize);
        y -= 1;
    }
}

/*------------------------------------------------------------------------------

    Function: h264bsdInterpolateHorQuarter

        Functional description:
          Function to perform horizontal interpolation of pixel position 'a'
          or 'c' for a block. Overfilling is done only if needed. Reference
          image (ref) is read at correct position and the predicted part
          is written to macroblock array (mb)

------------------------------------------------------------------------------*/
pub unsafe fn h264bsdInterpolateHorQuarter(
    ref_: *mut u8,
    mb: *mut u8,
    x0: i32,
    y0: i32,
    width: u32,
    height: u32,
    partWidth: u32,
    partHeight: u32,
    horOffset: u32, /* 0 for pixel a, 1 for pixel c */
) {
    let mut p1 = [0u32; 21 * 21 / 4 + 1];
    let mut ptrJ: *const u8;
    let mut x: u32;
    let mut y: u32;
    let mut tmp1: i32;
    let mut tmp2: i32;
    let mut tmp3: i32;
    let mut tmp4: i32;
    let mut tmp5: i32;
    let mut tmp6: i32;
    let mut tmp7: i32;
    let clp: *const u8 = h264bsdClip.as_ptr().add(512);

    let mut ref_: *const u8 = ref_;
    let mut mb = mb;
    let mut x0 = x0;
    let mut y0 = y0;
    let mut width = width;

    /* Code */

    if (x0 < 0)
        || ((x0 as u32).wrapping_add(partWidth).wrapping_add(5) > width)
        || (y0 < 0)
        || ((y0 as u32).wrapping_add(partHeight) > height)
    {
        h264bsdFillBlock(
            ref_,
            p1.as_mut_ptr() as *mut u8,
            x0,
            y0,
            width,
            height,
            partWidth + 5,
            partHeight,
            partWidth + 5,
        );

        x0 = 0;
        y0 = 0;
        ref_ = p1.as_ptr() as *const u8;
        width = partWidth + 5;
    }

    ref_ = ref_.add((y0 as u32 * width + x0 as u32) as usize);

    ptrJ = ref_.add(5);

    y = partHeight;
    while y != 0 {
        tmp6 = *ptrJ.offset(-5) as i32;
        tmp5 = *ptrJ.offset(-4) as i32;
        tmp4 = *ptrJ.offset(-3) as i32;
        tmp3 = *ptrJ.offset(-2) as i32;
        tmp2 = *ptrJ.offset(-1) as i32;

        /* calculate 4 pels per iteration */
        x = partWidth >> 2;
        while x != 0 {
            /* First pixel */
            tmp6 += 16;
            tmp7 = tmp3 + tmp4;
            tmp6 += tmp7 << 4;
            tmp6 += tmp7 << 2;
            tmp7 = tmp2 + tmp5;
            tmp1 = *ptrJ as i32;
            ptrJ = ptrJ.add(1);
            tmp6 -= tmp7 << 2;
            tmp6 -= tmp7;
            tmp6 += tmp1;
            tmp6 = *clp.offset((tmp6 >> 5) as isize) as i32;
            tmp5 += 16;
            if horOffset == 0 {
                tmp6 += tmp4;
            } else {
                tmp6 += tmp3;
            }
            *mb = ((tmp6 + 1) >> 1) as u8;
            mb = mb.add(1);
            /* Second pixel */
            tmp7 = tmp2 + tmp3;
            tmp5 += tmp7 << 4;
            tmp5 += tmp7 << 2;
            tmp7 = tmp1 + tmp4;
            tmp6 = *ptrJ as i32;
            ptrJ = ptrJ.add(1);
            tmp5 -= tmp7 << 2;
            tmp5 -= tmp7;
            tmp5 += tmp6;
            tmp5 = *clp.offset((tmp5 >> 5) as isize) as i32;
            tmp4 += 16;
            if horOffset == 0 {
                tmp5 += tmp3;
            } else {
                tmp5 += tmp2;
            }
            *mb = ((tmp5 + 1) >> 1) as u8;
            mb = mb.add(1);
            /* Third pixel */
            tmp7 = tmp1 + tmp2;
            tmp4 += tmp7 << 4;
            tmp4 += tmp7 << 2;
            tmp7 = tmp6 + tmp3;
            tmp5 = *ptrJ as i32;
            ptrJ = ptrJ.add(1);
            tmp4 -= tmp7 << 2;
            tmp4 -= tmp7;
            tmp4 += tmp5;
            tmp4 = *clp.offset((tmp4 >> 5) as isize) as i32;
            tmp3 += 16;
            if horOffset == 0 {
                tmp4 += tmp2;
            } else {
                tmp4 += tmp1;
            }
            *mb = ((tmp4 + 1) >> 1) as u8;
            mb = mb.add(1);
            /* Fourth pixel */
            tmp7 = tmp6 + tmp1;
            tmp3 += tmp7 << 4;
            tmp3 += tmp7 << 2;
            tmp7 = tmp5 + tmp2;
            tmp4 = *ptrJ as i32;
            ptrJ = ptrJ.add(1);
            tmp3 -= tmp7 << 2;
            tmp3 -= tmp7;
            tmp3 += tmp4;
            tmp3 = *clp.offset((tmp3 >> 5) as isize) as i32;
            if horOffset == 0 {
                tmp3 += tmp1;
            } else {
                tmp3 += tmp6;
            }
            *mb = ((tmp3 + 1) >> 1) as u8;
            mb = mb.add(1);
            tmp3 = tmp5;
            tmp5 = tmp1;
            tmp7 = tmp4;
            tmp4 = tmp6;
            tmp6 = tmp2;
            tmp2 = tmp7;
            x -= 1;
        }
        ptrJ = ptrJ.add((width - partWidth) as usize);
        mb = mb.add((16 - partWidth) as usize);
        y -= 1;
    }
}

/*------------------------------------------------------------------------------

    Function: h264bsdInterpolateHorVerQuarter

        Functional description:
          Function to perform horizontal and vertical interpolation of pixel
          position 'e', 'g', 'p' or 'r' for a block. Overfilling is done only
          if needed. Reference image (ref) is read at correct position and
          the predicted part is written to macroblock array (mb)

------------------------------------------------------------------------------*/
pub unsafe fn h264bsdInterpolateHorVerQuarter(
    ref_: *mut u8,
    mb: *mut u8,
    x0: i32,
    y0: i32,
    width: u32,
    height: u32,
    partWidth: u32,
    partHeight: u32,
    horVerOffset: u32, /* 0 for pixel e, 1 for pixel g,
                          2 for pixel p, 3 for pixel r */
) {
    let mut p1 = [0u32; 21 * 21 / 4 + 1];
    let mut ptrC: *const u8;
    let mut ptrJ: *const u8;
    let mut ptrV: *const u8;
    let mut x: u32;
    let mut y: u32;
    let mut tmp1: i32;
    let mut tmp2: i32;
    let mut tmp3: i32;
    let mut tmp4: i32;
    let mut tmp5: i32;
    let mut tmp6: i32;
    let mut tmp7: i32;
    let clp: *const u8 = h264bsdClip.as_ptr().add(512);

    let mut ref_: *const u8 = ref_;
    let mut mb = mb;
    let mut x0 = x0;
    let mut y0 = y0;
    let mut width = width;

    /* Code */

    if (x0 < 0)
        || ((x0 as u32).wrapping_add(partWidth).wrapping_add(5) > width)
        || (y0 < 0)
        || ((y0 as u32).wrapping_add(partHeight).wrapping_add(5) > height)
    {
        h264bsdFillBlock(
            ref_,
            p1.as_mut_ptr() as *mut u8,
            x0,
            y0,
            width,
            height,
            partWidth + 5,
            partHeight + 5,
            partWidth + 5,
        );

        x0 = 0;
        y0 = 0;
        ref_ = p1.as_ptr() as *const u8;
        width = partWidth + 5;
    }

    /* Ref points to G + (-2, -2) */
    ref_ = ref_.add((y0 as u32 * width + x0 as u32) as usize);

    /* ptrJ points to either J or Q, depending on vertical offset */
    ptrJ = ref_.add(((((horVerOffset & 0x2) >> 1) + 2) * width + 5) as usize);

    /* ptrC points to either C or D, depending on horizontal offset */
    ptrC = ref_.add((width + 2 + (horVerOffset & 0x1)) as usize);

    y = partHeight;
    while y != 0 {
        tmp6 = *ptrJ.offset(-5) as i32;
        tmp5 = *ptrJ.offset(-4) as i32;
        tmp4 = *ptrJ.offset(-3) as i32;
        tmp3 = *ptrJ.offset(-2) as i32;
        tmp2 = *ptrJ.offset(-1) as i32;

        /* Horizontal interpolation, calculate 4 pels per iteration */
        x = partWidth >> 2;
        while x != 0 {
            /* First pixel */
            tmp6 += 16;
            tmp7 = tmp3 + tmp4;
            tmp6 += tmp7 << 4;
            tmp6 += tmp7 << 2;
            tmp7 = tmp2 + tmp5;
            tmp1 = *ptrJ as i32;
            ptrJ = ptrJ.add(1);
            tmp6 -= tmp7 << 2;
            tmp6 -= tmp7;
            tmp6 += tmp1;
            tmp6 = *clp.offset((tmp6 >> 5) as isize) as i32;
            /* Second pixel */
            tmp5 += 16;
            tmp7 = tmp2 + tmp3;
            *mb = tmp6 as u8;
            mb = mb.add(1);
            tmp5 += tmp7 << 4;
            tmp5 += tmp7 << 2;
            tmp7 = tmp1 + tmp4;
            tmp6 = *ptrJ as i32;
            ptrJ = ptrJ.add(1);
            tmp5 -= tmp7 << 2;
            tmp5 -= tmp7;
            tmp5 += tmp6;
            tmp5 = *clp.offset((tmp5 >> 5) as isize) as i32;
            /* Third pixel */
            tmp4 += 16;
            tmp7 = tmp1 + tmp2;
            *mb = tmp5 as u8;
            mb = mb.add(1);
            tmp4 += tmp7 << 4;
            tmp4 += tmp7 << 2;
            tmp7 = tmp6 + tmp3;
            tmp5 = *ptrJ as i32;
            ptrJ = ptrJ.add(1);
            tmp4 -= tmp7 << 2;
            tmp4 -= tmp7;
            tmp4 += tmp5;
            tmp4 = *clp.offset((tmp4 >> 5) as isize) as i32;
            /* Fourth pixel */
            tmp3 += 16;
            tmp7 = tmp6 + tmp1;
            *mb = tmp4 as u8;
            mb = mb.add(1);
            tmp3 += tmp7 << 4;
            tmp3 += tmp7 << 2;
            tmp7 = tmp5 + tmp2;
            tmp4 = *ptrJ as i32;
            ptrJ = ptrJ.add(1);
            tmp3 -= tmp7 << 2;
            tmp3 -= tmp7;
            tmp3 += tmp4;
            tmp3 = *clp.offset((tmp3 >> 5) as isize) as i32;
            tmp7 = tmp4;
            tmp4 = tmp6;
            tmp6 = tmp2;
            tmp2 = tmp7;
            *mb = tmp3 as u8;
            mb = mb.add(1);
            tmp3 = tmp5;
            tmp5 = tmp1;
            x -= 1;
        }
        ptrJ = ptrJ.add((width - partWidth) as usize);
        mb = mb.add((16 - partWidth) as usize);
        y -= 1;
    }

    mb = mb.offset(-((16 * partHeight) as isize));
    ptrV = ptrC.add((5 * width) as usize);

    y = partHeight >> 2;
    while y != 0 {
        /* Vertical interpolation and averaging, 4 pels per iteration */
        x = partWidth;
        while x != 0 {
            tmp4 = *ptrV.offset(-((width as i32) * 2) as isize) as i32;
            tmp5 = *ptrV.offset(-(width as i32) as isize) as i32;
            tmp1 = *ptrV.add(width as usize) as i32;
            tmp2 = *ptrV.add((width * 2) as usize) as i32;
            tmp6 = *ptrV as i32;
            ptrV = ptrV.add(1);

            tmp7 = tmp4 + tmp1;
            tmp2 -= tmp7 << 2;
            tmp2 -= tmp7;
            tmp2 += 16;
            tmp7 = tmp5 + tmp6;
            tmp3 = *ptrC.add((width * 2) as usize) as i32;
            tmp2 += tmp7 << 4;
            tmp2 += tmp7 << 2;
            tmp2 += tmp3;
            tmp7 = *clp.offset((tmp2 >> 5) as isize) as i32;
            tmp2 = *mb.add(48) as i32;
            tmp1 += 16;
            tmp7 += 1;
            *mb.add(48) = ((tmp2 + tmp7) >> 1) as u8;

            tmp7 = tmp3 + tmp6;
            tmp1 -= tmp7 << 2;
            tmp1 -= tmp7;
            tmp7 = tmp4 + tmp5;
            tmp2 = *ptrC.add(width as usize) as i32;
            tmp1 += tmp7 << 4;
            tmp1 += tmp7 << 2;
            tmp1 += tmp2;
            tmp7 = *clp.offset((tmp1 >> 5) as isize) as i32;
            tmp1 = *mb.add(32) as i32;
            tmp6 += 16;
            tmp7 += 1;
            *mb.add(32) = ((tmp1 + tmp7) >> 1) as u8;

            tmp1 = *ptrC as i32;
            tmp7 = tmp2 + tmp5;
            tmp6 -= tmp7 << 2;
            tmp6 -= tmp7;
            tmp7 = tmp4 + tmp3;
            tmp6 += tmp7 << 4;
            tmp6 += tmp7 << 2;
            tmp6 += tmp1;
            tmp7 = *clp.offset((tmp6 >> 5) as isize) as i32;
            tmp6 = *mb.add(16) as i32;
            tmp5 += 16;
            tmp7 += 1;
            *mb.add(16) = ((tmp6 + tmp7) >> 1) as u8;

            tmp6 = *ptrC.offset(-(width as i32) as isize) as i32;
            tmp1 += tmp4;
            tmp5 -= tmp1 << 2;
            tmp5 -= tmp1;
            tmp3 += tmp2;
            tmp5 += tmp3 << 4;
            tmp5 += tmp3 << 2;
            tmp5 += tmp6;
            tmp7 = *clp.offset((tmp5 >> 5) as isize) as i32;
            tmp5 = *mb as i32;
            tmp7 += 1;
            *mb = ((tmp5 + tmp7) >> 1) as u8;
            mb = mb.add(1);
            ptrC = ptrC.add(1);
            x -= 1;
        }
        ptrC = ptrC.add((4 * width - partWidth) as usize);
        ptrV = ptrV.add((4 * width - partWidth) as usize);
        mb = mb.add((4 * 16 - partWidth) as usize);
        y -= 1;
    }
}

/*------------------------------------------------------------------------------

    Function: h264bsdInterpolateMidHalf

        Functional description:
          Function to perform horizontal and vertical interpolation of pixel
          position 'j' for a block. Overfilling is done only if needed.
          Reference image (ref) is read at correct position and the predicted
          part is written to macroblock array (mb)

------------------------------------------------------------------------------*/
pub unsafe fn h264bsdInterpolateMidHalf(
    ref_: *mut u8,
    mb: *mut u8,
    x0: i32,
    y0: i32,
    width: u32,
    height: u32,
    partWidth: u32,
    partHeight: u32,
) {
    let mut p1 = [0u32; 21 * 21 / 4 + 1];
    let mut x: u32;
    let mut y: u32;
    let mut tmp1: i32;
    let mut tmp2: i32;
    let mut tmp3: i32;
    let mut tmp4: i32;
    let mut tmp5: i32;
    let mut tmp6: i32;
    let mut tmp7: i32;
    let mut ptrC: *const i32;
    let mut ptrV: *const i32;
    let mut b1: *mut i32;
    let mut ptrJ: *const u8;
    let mut table = [0i32; 21 * 16];
    let clp: *const u8 = h264bsdClip.as_ptr().add(512);

    let mut ref_: *const u8 = ref_;
    let mut mb = mb;
    let mut x0 = x0;
    let mut y0 = y0;
    let mut width = width;

    /* Code */

    if (x0 < 0)
        || ((x0 as u32).wrapping_add(partWidth).wrapping_add(5) > width)
        || (y0 < 0)
        || ((y0 as u32).wrapping_add(partHeight).wrapping_add(5) > height)
    {
        h264bsdFillBlock(
            ref_,
            p1.as_mut_ptr() as *mut u8,
            x0,
            y0,
            width,
            height,
            partWidth + 5,
            partHeight + 5,
            partWidth + 5,
        );

        x0 = 0;
        y0 = 0;
        ref_ = p1.as_ptr() as *const u8;
        width = partWidth + 5;
    }

    ref_ = ref_.add((y0 as u32 * width + x0 as u32) as usize);

    b1 = table.as_mut_ptr();
    ptrJ = ref_.add(5);

    /* First step: calculate intermediate values for
     * horizontal interpolation */
    y = partHeight + 5;
    while y != 0 {
        tmp6 = *ptrJ.offset(-5) as i32;
        tmp5 = *ptrJ.offset(-4) as i32;
        tmp4 = *ptrJ.offset(-3) as i32;
        tmp3 = *ptrJ.offset(-2) as i32;
        tmp2 = *ptrJ.offset(-1) as i32;

        /* 4 pels per iteration */
        x = partWidth >> 2;
        while x != 0 {
            /* First pixel */
            tmp7 = tmp3 + tmp4;
            tmp6 += tmp7 << 4;
            tmp6 += tmp7 << 2;
            tmp7 = tmp2 + tmp5;
            tmp1 = *ptrJ as i32;
            ptrJ = ptrJ.add(1);
            tmp6 -= tmp7 << 2;
            tmp6 -= tmp7;
            tmp6 += tmp1;
            *b1 = tmp6;
            b1 = b1.add(1);
            /* Second pixel */
            tmp7 = tmp2 + tmp3;
            tmp5 += tmp7 << 4;
            tmp5 += tmp7 << 2;
            tmp7 = tmp1 + tmp4;
            tmp6 = *ptrJ as i32;
            ptrJ = ptrJ.add(1);
            tmp5 -= tmp7 << 2;
            tmp5 -= tmp7;
            tmp5 += tmp6;
            *b1 = tmp5;
            b1 = b1.add(1);
            /* Third pixel */
            tmp7 = tmp1 + tmp2;
            tmp4 += tmp7 << 4;
            tmp4 += tmp7 << 2;
            tmp7 = tmp6 + tmp3;
            tmp5 = *ptrJ as i32;
            ptrJ = ptrJ.add(1);
            tmp4 -= tmp7 << 2;
            tmp4 -= tmp7;
            tmp4 += tmp5;
            *b1 = tmp4;
            b1 = b1.add(1);
            /* Fourth pixel */
            tmp7 = tmp6 + tmp1;
            tmp3 += tmp7 << 4;
            tmp3 += tmp7 << 2;
            tmp7 = tmp5 + tmp2;
            tmp4 = *ptrJ as i32;
            ptrJ = ptrJ.add(1);
            tmp3 -= tmp7 << 2;
            tmp3 -= tmp7;
            tmp3 += tmp4;
            *b1 = tmp3;
            b1 = b1.add(1);
            tmp7 = tmp4;
            tmp4 = tmp6;
            tmp6 = tmp2;
            tmp2 = tmp7;
            tmp3 = tmp5;
            tmp5 = tmp1;
            x -= 1;
        }
        ptrJ = ptrJ.add((width - partWidth) as usize);
        y -= 1;
    }

    /* Second step: calculate vertical interpolation */
    ptrC = table.as_ptr().add(partWidth as usize);
    ptrV = ptrC.add((5 * partWidth) as usize);
    y = partHeight >> 2;
    while y != 0 {
        /* 4 pels per iteration */
        x = partWidth;
        while x != 0 {
            tmp4 = *ptrV.offset(-((partWidth as i32) * 2) as isize);
            tmp5 = *ptrV.offset(-(partWidth as i32) as isize);
            tmp1 = *ptrV.add(partWidth as usize);
            tmp2 = *ptrV.add((partWidth * 2) as usize);
            tmp6 = *ptrV;
            ptrV = ptrV.add(1);

            tmp7 = tmp4 + tmp1;
            tmp2 -= tmp7 << 2;
            tmp2 -= tmp7;
            tmp2 += 512;
            tmp7 = tmp5 + tmp6;
            tmp3 = *ptrC.add((partWidth * 2) as usize);
            tmp2 += tmp7 << 4;
            tmp2 += tmp7 << 2;
            tmp2 += tmp3;
            tmp7 = *clp.offset((tmp2 >> 10) as isize) as i32;
            tmp1 += 512;
            *mb.add(48) = tmp7 as u8;

            tmp7 = tmp3 + tmp6;
            tmp1 -= tmp7 << 2;
            tmp1 -= tmp7;
            tmp7 = tmp4 + tmp5;
            tmp2 = *ptrC.add(partWidth as usize);
            tmp1 += tmp7 << 4;
            tmp1 += tmp7 << 2;
            tmp1 += tmp2;
            tmp7 = *clp.offset((tmp1 >> 10) as isize) as i32;
            tmp6 += 512;
            *mb.add(32) = tmp7 as u8;

            tmp1 = *ptrC;
            tmp7 = tmp2 + tmp5;
            tmp6 -= tmp7 << 2;
            tmp6 -= tmp7;
            tmp7 = tmp4 + tmp3;
            tmp6 += tmp7 << 4;
            tmp6 += tmp7 << 2;
            tmp6 += tmp1;
            tmp7 = *clp.offset((tmp6 >> 10) as isize) as i32;
            tmp5 += 512;
            *mb.add(16) = tmp7 as u8;

            tmp6 = *ptrC.offset(-(partWidth as i32) as isize);
            tmp1 += tmp4;
            tmp5 -= tmp1 << 2;
            tmp5 -= tmp1;
            tmp3 += tmp2;
            tmp5 += tmp3 << 4;
            tmp5 += tmp3 << 2;
            tmp5 += tmp6;
            tmp7 = *clp.offset((tmp5 >> 10) as isize) as i32;
            *mb = tmp7 as u8;
            mb = mb.add(1);
            ptrC = ptrC.add(1);
            x -= 1;
        }
        mb = mb.add((4 * 16 - partWidth) as usize);
        ptrC = ptrC.add((3 * partWidth) as usize);
        ptrV = ptrV.add((3 * partWidth) as usize);
        y -= 1;
    }
}

/*------------------------------------------------------------------------------

    Function: h264bsdInterpolateMidVerQuarter

        Functional description:
          Function to perform horizontal and vertical interpolation of pixel
          position 'f' or 'q' for a block. Overfilling is done only if needed.
          Reference image (ref) is read at correct position and the predicted
          part is written to macroblock array (mb)

------------------------------------------------------------------------------*/
pub unsafe fn h264bsdInterpolateMidVerQuarter(
    ref_: *mut u8,
    mb: *mut u8,
    x0: i32,
    y0: i32,
    width: u32,
    height: u32,
    partWidth: u32,
    partHeight: u32,
    verOffset: u32, /* 0 for pixel f, 1 for pixel q */
) {
    let mut p1 = [0u32; 21 * 21 / 4 + 1];
    let mut x: u32;
    let mut y: u32;
    let mut tmp1: i32;
    let mut tmp2: i32;
    let mut tmp3: i32;
    let mut tmp4: i32;
    let mut tmp5: i32;
    let mut tmp6: i32;
    let mut tmp7: i32;
    let mut ptrC: *const i32;
    let mut ptrV: *const i32;
    let mut ptrInt: *const i32;
    let mut b1: *mut i32;
    let mut ptrJ: *const u8;
    let mut table = [0i32; 21 * 16];
    let clp: *const u8 = h264bsdClip.as_ptr().add(512);

    let mut ref_: *const u8 = ref_;
    let mut mb = mb;
    let mut x0 = x0;
    let mut y0 = y0;
    let mut width = width;

    /* Code */

    if (x0 < 0)
        || ((x0 as u32).wrapping_add(partWidth).wrapping_add(5) > width)
        || (y0 < 0)
        || ((y0 as u32).wrapping_add(partHeight).wrapping_add(5) > height)
    {
        h264bsdFillBlock(
            ref_,
            p1.as_mut_ptr() as *mut u8,
            x0,
            y0,
            width,
            height,
            partWidth + 5,
            partHeight + 5,
            partWidth + 5,
        );

        x0 = 0;
        y0 = 0;
        ref_ = p1.as_ptr() as *const u8;
        width = partWidth + 5;
    }

    ref_ = ref_.add((y0 as u32 * width + x0 as u32) as usize);

    b1 = table.as_mut_ptr();
    ptrJ = ref_.add(5);

    /* First step: calculate intermediate values for
     * horizontal interpolation */
    y = partHeight + 5;
    while y != 0 {
        tmp6 = *ptrJ.offset(-5) as i32;
        tmp5 = *ptrJ.offset(-4) as i32;
        tmp4 = *ptrJ.offset(-3) as i32;
        tmp3 = *ptrJ.offset(-2) as i32;
        tmp2 = *ptrJ.offset(-1) as i32;
        x = partWidth >> 2;
        while x != 0 {
            /* First pixel */
            tmp7 = tmp3 + tmp4;
            tmp6 += tmp7 << 4;
            tmp6 += tmp7 << 2;
            tmp7 = tmp2 + tmp5;
            tmp1 = *ptrJ as i32;
            ptrJ = ptrJ.add(1);
            tmp6 -= tmp7 << 2;
            tmp6 -= tmp7;
            tmp6 += tmp1;
            *b1 = tmp6;
            b1 = b1.add(1);
            /* Second pixel */
            tmp7 = tmp2 + tmp3;
            tmp5 += tmp7 << 4;
            tmp5 += tmp7 << 2;
            tmp7 = tmp1 + tmp4;
            tmp6 = *ptrJ as i32;
            ptrJ = ptrJ.add(1);
            tmp5 -= tmp7 << 2;
            tmp5 -= tmp7;
            tmp5 += tmp6;
            *b1 = tmp5;
            b1 = b1.add(1);
            /* Third pixel */
            tmp7 = tmp1 + tmp2;
            tmp4 += tmp7 << 4;
            tmp4 += tmp7 << 2;
            tmp7 = tmp6 + tmp3;
            tmp5 = *ptrJ as i32;
            ptrJ = ptrJ.add(1);
            tmp4 -= tmp7 << 2;
            tmp4 -= tmp7;
            tmp4 += tmp5;
            *b1 = tmp4;
            b1 = b1.add(1);
            /* Fourth pixel */
            tmp7 = tmp6 + tmp1;
            tmp3 += tmp7 << 4;
            tmp3 += tmp7 << 2;
            tmp7 = tmp5 + tmp2;
            tmp4 = *ptrJ as i32;
            ptrJ = ptrJ.add(1);
            tmp3 -= tmp7 << 2;
            tmp3 -= tmp7;
            tmp3 += tmp4;
            *b1 = tmp3;
            b1 = b1.add(1);
            tmp7 = tmp4;
            tmp4 = tmp6;
            tmp6 = tmp2;
            tmp2 = tmp7;
            tmp3 = tmp5;
            tmp5 = tmp1;
            x -= 1;
        }
        ptrJ = ptrJ.add((width - partWidth) as usize);
        y -= 1;
    }

    /* Second step: calculate vertical interpolation and average */
    ptrC = table.as_ptr().add(partWidth as usize);
    ptrV = ptrC.add((5 * partWidth) as usize);
    /* Pointer to integer sample position, either M or R */
    ptrInt = ptrC.add(((2 + verOffset) * partWidth) as usize);
    y = partHeight >> 2;
    while y != 0 {
        x = partWidth;
        while x != 0 {
            tmp4 = *ptrV.offset(-((partWidth as i32) * 2) as isize);
            tmp5 = *ptrV.offset(-(partWidth as i32) as isize);
            tmp1 = *ptrV.add(partWidth as usize);
            tmp2 = *ptrV.add((partWidth * 2) as usize);
            tmp6 = *ptrV;
            ptrV = ptrV.add(1);

            tmp7 = tmp4 + tmp1;
            tmp2 -= tmp7 << 2;
            tmp2 -= tmp7;
            tmp2 += 512;
            tmp7 = tmp5 + tmp6;
            tmp3 = *ptrC.add((partWidth * 2) as usize);
            tmp2 += tmp7 << 4;
            tmp2 += tmp7 << 2;
            tmp7 = *ptrInt.add((partWidth * 2) as usize);
            tmp2 += tmp3;
            tmp2 = *clp.offset((tmp2 >> 10) as isize) as i32;
            tmp7 += 16;
            tmp7 = *clp.offset((tmp7 >> 5) as isize) as i32;
            tmp1 += 512;
            tmp2 += 1;
            *mb.add(48) = ((tmp7 + tmp2) >> 1) as u8;

            tmp7 = tmp3 + tmp6;
            tmp1 -= tmp7 << 2;
            tmp1 -= tmp7;
            tmp7 = tmp4 + tmp5;
            tmp2 = *ptrC.add(partWidth as usize);
            tmp1 += tmp7 << 4;
            tmp1 += tmp7 << 2;
            tmp7 = *ptrInt.add(partWidth as usize);
            tmp1 += tmp2;
            tmp1 = *clp.offset((tmp1 >> 10) as isize) as i32;
            tmp7 += 16;
            tmp7 = *clp.offset((tmp7 >> 5) as isize) as i32;
            tmp6 += 512;
            tmp1 += 1;
            *mb.add(32) = ((tmp7 + tmp1) >> 1) as u8;

            tmp1 = *ptrC;
            tmp7 = tmp2 + tmp5;
            tmp6 -= tmp7 << 2;
            tmp6 -= tmp7;
            tmp7 = tmp4 + tmp3;
            tmp6 += tmp7 << 4;
            tmp6 += tmp7 << 2;
            tmp7 = *ptrInt;
            tmp6 += tmp1;
            tmp6 = *clp.offset((tmp6 >> 10) as isize) as i32;
            tmp7 += 16;
            tmp7 = *clp.offset((tmp7 >> 5) as isize) as i32;
            tmp5 += 512;
            tmp6 += 1;
            *mb.add(16) = ((tmp7 + tmp6) >> 1) as u8;

            tmp6 = *ptrC.offset(-(partWidth as i32) as isize);
            tmp1 += tmp4;
            tmp5 -= tmp1 << 2;
            tmp5 -= tmp1;
            tmp3 += tmp2;
            tmp5 += tmp3 << 4;
            tmp5 += tmp3 << 2;
            tmp7 = *ptrInt.offset(-(partWidth as i32) as isize);
            tmp5 += tmp6;
            tmp5 = *clp.offset((tmp5 >> 10) as isize) as i32;
            tmp7 += 16;
            tmp7 = *clp.offset((tmp7 >> 5) as isize) as i32;
            tmp5 += 1;
            *mb = ((tmp7 + tmp5) >> 1) as u8;
            mb = mb.add(1);
            ptrC = ptrC.add(1);
            ptrInt = ptrInt.add(1);
            x -= 1;
        }
        mb = mb.add((4 * 16 - partWidth) as usize);
        ptrC = ptrC.add((3 * partWidth) as usize);
        ptrV = ptrV.add((3 * partWidth) as usize);
        ptrInt = ptrInt.add((3 * partWidth) as usize);
        y -= 1;
    }
}

/*------------------------------------------------------------------------------

    Function: h264bsdInterpolateMidHorQuarter

        Functional description:
          Function to perform horizontal and vertical interpolation of pixel
          position 'i' or 'k' for a block. Overfilling is done only if needed.
          Reference image (ref) is read at correct position and the predicted
          part is written to macroblock array (mb)

------------------------------------------------------------------------------*/
pub unsafe fn h264bsdInterpolateMidHorQuarter(
    ref_: *mut u8,
    mb: *mut u8,
    x0: i32,
    y0: i32,
    width: u32,
    height: u32,
    partWidth: u32,
    partHeight: u32,
    horOffset: u32, /* 0 for pixel i, 1 for pixel k */
) {
    let mut p1 = [0u32; 21 * 21 / 4 + 1];
    let mut x: u32;
    let mut y: u32;
    let mut tmp1: i32;
    let mut tmp2: i32;
    let mut tmp3: i32;
    let mut tmp4: i32;
    let mut tmp5: i32;
    let mut tmp6: i32;
    let mut tmp7: i32;
    let mut ptrJ: *const i32;
    let mut ptrInt: *const i32;
    let mut h1: *mut i32;
    let mut ptrC: *const u8;
    let mut ptrV: *const u8;
    let mut table = [0i32; 21 * 16];
    let tableWidth: i32 = partWidth as i32 + 5;
    let clp: *const u8 = h264bsdClip.as_ptr().add(512);

    let mut ref_: *const u8 = ref_;
    let mut mb = mb;
    let mut x0 = x0;
    let mut y0 = y0;
    let mut width = width;

    /* Code */

    if (x0 < 0)
        || ((x0 as u32).wrapping_add(partWidth).wrapping_add(5) > width)
        || (y0 < 0)
        || ((y0 as u32).wrapping_add(partHeight).wrapping_add(5) > height)
    {
        h264bsdFillBlock(
            ref_,
            p1.as_mut_ptr() as *mut u8,
            x0,
            y0,
            width,
            height,
            partWidth + 5,
            partHeight + 5,
            partWidth + 5,
        );

        x0 = 0;
        y0 = 0;
        ref_ = p1.as_ptr() as *const u8;
        width = partWidth + 5;
    }

    ref_ = ref_.add((y0 as u32 * width + x0 as u32) as usize);

    h1 = table.as_mut_ptr().offset(tableWidth as isize);
    ptrC = ref_.add(width as usize);
    ptrV = ptrC.add((5 * width) as usize);

    /* First step: calculate intermediate values for
     * vertical interpolation */
    y = partHeight >> 2;
    while y != 0 {
        x = tableWidth as u32;
        while x != 0 {
            tmp4 = *ptrV.offset(-((width as i32) * 2) as isize) as i32;
            tmp5 = *ptrV.offset(-(width as i32) as isize) as i32;
            tmp1 = *ptrV.add(width as usize) as i32;
            tmp2 = *ptrV.add((width * 2) as usize) as i32;
            tmp6 = *ptrV as i32;
            ptrV = ptrV.add(1);

            tmp7 = tmp4 + tmp1;
            tmp2 -= tmp7 << 2;
            tmp2 -= tmp7;
            tmp7 = tmp5 + tmp6;
            tmp3 = *ptrC.add((width * 2) as usize) as i32;
            tmp2 += tmp7 << 4;
            tmp2 += tmp7 << 2;
            tmp2 += tmp3;
            *h1.offset((tableWidth * 2) as isize) = tmp2;

            tmp7 = tmp3 + tmp6;
            tmp1 -= tmp7 << 2;
            tmp1 -= tmp7;
            tmp7 = tmp4 + tmp5;
            tmp2 = *ptrC.add(width as usize) as i32;
            tmp1 += tmp7 << 4;
            tmp1 += tmp7 << 2;
            tmp1 += tmp2;
            *h1.offset(tableWidth as isize) = tmp1;

            tmp1 = *ptrC as i32;
            tmp7 = tmp2 + tmp5;
            tmp6 -= tmp7 << 2;
            tmp6 -= tmp7;
            tmp7 = tmp4 + tmp3;
            tmp6 += tmp7 << 4;
            tmp6 += tmp7 << 2;
            tmp6 += tmp1;
            *h1 = tmp6;

            tmp6 = *ptrC.offset(-(width as i32) as isize) as i32;
            tmp1 += tmp4;
            tmp5 -= tmp1 << 2;
            tmp5 -= tmp1;
            tmp3 += tmp2;
            tmp5 += tmp3 << 4;
            tmp5 += tmp3 << 2;
            tmp5 += tmp6;
            *h1.offset(-(tableWidth as isize)) = tmp5;
            h1 = h1.add(1);
            ptrC = ptrC.add(1);
            x -= 1;
        }
        ptrC = ptrC.add((4 * width - partWidth - 5) as usize);
        ptrV = ptrV.add((4 * width - partWidth - 5) as usize);
        h1 = h1.offset((3 * tableWidth) as isize);
        y -= 1;
    }

    /* Second step: calculate horizontal interpolation and average */
    ptrJ = table.as_ptr().add(5);
    /* Pointer to integer sample position, either G or H */
    ptrInt = table.as_ptr().add((2 + horOffset) as usize);
    y = partHeight;
    while y != 0 {
        tmp6 = *ptrJ.offset(-5);
        tmp5 = *ptrJ.offset(-4);
        tmp4 = *ptrJ.offset(-3);
        tmp3 = *ptrJ.offset(-2);
        tmp2 = *ptrJ.offset(-1);
        x = partWidth >> 2;
        while x != 0 {
            /* First pixel */
            tmp6 += 512;
            tmp7 = tmp3 + tmp4;
            tmp6 += tmp7 << 4;
            tmp6 += tmp7 << 2;
            tmp7 = tmp2 + tmp5;
            tmp1 = *ptrJ;
            ptrJ = ptrJ.add(1);
            tmp6 -= tmp7 << 2;
            tmp6 -= tmp7;
            tmp7 = *ptrInt;
            ptrInt = ptrInt.add(1);
            tmp6 += tmp1;
            tmp6 = *clp.offset((tmp6 >> 10) as isize) as i32;
            tmp7 += 16;
            tmp7 = *clp.offset((tmp7 >> 5) as isize) as i32;
            tmp5 += 512;
            tmp6 += 1;
            *mb = ((tmp6 + tmp7) >> 1) as u8;
            mb = mb.add(1);
            /* Second pixel */
            tmp7 = tmp2 + tmp3;
            tmp5 += tmp7 << 4;
            tmp5 += tmp7 << 2;
            tmp7 = tmp1 + tmp4;
            tmp6 = *ptrJ;
            ptrJ = ptrJ.add(1);
            tmp5 -= tmp7 << 2;
            tmp5 -= tmp7;
            tmp7 = *ptrInt;
            ptrInt = ptrInt.add(1);
            tmp5 += tmp6;
            tmp5 = *clp.offset((tmp5 >> 10) as isize) as i32;
            tmp7 += 16;
            tmp7 = *clp.offset((tmp7 >> 5) as isize) as i32;
            tmp4 += 512;
            tmp5 += 1;
            *mb = ((tmp5 + tmp7) >> 1) as u8;
            mb = mb.add(1);
            /* Third pixel */
            tmp7 = tmp1 + tmp2;
            tmp4 += tmp7 << 4;
            tmp4 += tmp7 << 2;
            tmp7 = tmp6 + tmp3;
            tmp5 = *ptrJ;
            ptrJ = ptrJ.add(1);
            tmp4 -= tmp7 << 2;
            tmp4 -= tmp7;
            tmp7 = *ptrInt;
            ptrInt = ptrInt.add(1);
            tmp4 += tmp5;
            tmp4 = *clp.offset((tmp4 >> 10) as isize) as i32;
            tmp7 += 16;
            tmp7 = *clp.offset((tmp7 >> 5) as isize) as i32;
            tmp3 += 512;
            tmp4 += 1;
            *mb = ((tmp4 + tmp7) >> 1) as u8;
            mb = mb.add(1);
            /* Fourth pixel */
            tmp7 = tmp6 + tmp1;
            tmp3 += tmp7 << 4;
            tmp3 += tmp7 << 2;
            tmp7 = tmp5 + tmp2;
            tmp4 = *ptrJ;
            ptrJ = ptrJ.add(1);
            tmp3 -= tmp7 << 2;
            tmp3 -= tmp7;
            tmp7 = *ptrInt;
            ptrInt = ptrInt.add(1);
            tmp3 += tmp4;
            tmp3 = *clp.offset((tmp3 >> 10) as isize) as i32;
            tmp7 += 16;
            tmp7 = *clp.offset((tmp7 >> 5) as isize) as i32;
            tmp3 += 1;
            *mb = ((tmp3 + tmp7) >> 1) as u8;
            mb = mb.add(1);
            tmp3 = tmp5;
            tmp5 = tmp1;
            tmp7 = tmp4;
            tmp4 = tmp6;
            tmp6 = tmp2;
            tmp2 = tmp7;
            x -= 1;
        }
        ptrJ = ptrJ.add(5);
        ptrInt = ptrInt.add(5);
        mb = mb.add((16 - partWidth) as usize);
        y -= 1;
    }
}

/*------------------------------------------------------------------------------

    Function: h264bsdPredictSamples

        Functional description:
          This function reconstructs a prediction for a macroblock partition.
          The prediction is either copied or interpolated using the reference
          frame and the motion vector. Both luminance and chrominance parts are
          predicted. The prediction is stored in given macroblock array (data).
        Inputs:
          data          pointer to macroblock array (384 bytes) for output
          mv            pointer to motion vector used for prediction
          refPic        pointer to reference picture structure
          xA            x-coordinate for current macroblock
          yA            y-coordinate for current macroblock
          partX         x-offset for partition in macroblock
          partY         y-offset for partition in macroblock
          partWidth     width of partition
          partHeight    height of partition
        Outputs:
          data          macroblock array (16x16+8x8+8x8) where predicted
                        partition is stored at correct position

------------------------------------------------------------------------------*/
pub unsafe fn h264bsdPredictSamples(
    data: *mut u8,
    mv: &mv_t,
    refPic: &image_t,
    xA: u32,
    yA: u32,
    partX: u32,
    partY: u32,
    partWidth: u32,
    partHeight: u32,
) {
    /* Variables */

    let xFrac: u32;
    let yFrac: u32;
    let width: u32;
    let height: u32;
    let xInt: i32;
    let yInt: i32;
    let lumaPartData: *mut u8;

    /* Code */

    /* luma */
    lumaPartData = data.add((16 * partY + partX) as usize);

    xFrac = ((mv.hor as i32) & 0x3) as u32;
    yFrac = ((mv.ver as i32) & 0x3) as u32;

    width = 16 * refPic.width;
    height = 16 * refPic.height;

    xInt = (xA as i32) + (partX as i32) + ((mv.hor as i32) >> 2);
    yInt = (yA as i32) + (partY as i32) + ((mv.ver as i32) >> 2);

    match lumaFracPos[xFrac as usize][yFrac as usize] {
        0 => {
            /* G */
            h264bsdFillBlock(
                refPic.data,
                lumaPartData,
                xInt,
                yInt,
                width,
                height,
                partWidth,
                partHeight,
                16,
            );
        }
        1 => {
            /* d */
            h264bsdInterpolateVerQuarter(
                refPic.data,
                lumaPartData,
                xInt,
                yInt - 2,
                width,
                height,
                partWidth,
                partHeight,
                0,
            );
        }
        2 => {
            /* h */
            h264bsdInterpolateVerHalf(
                refPic.data,
                lumaPartData,
                xInt,
                yInt - 2,
                width,
                height,
                partWidth,
                partHeight,
            );
        }
        3 => {
            /* n */
            h264bsdInterpolateVerQuarter(
                refPic.data,
                lumaPartData,
                xInt,
                yInt - 2,
                width,
                height,
                partWidth,
                partHeight,
                1,
            );
        }
        4 => {
            /* a */
            h264bsdInterpolateHorQuarter(
                refPic.data,
                lumaPartData,
                xInt - 2,
                yInt,
                width,
                height,
                partWidth,
                partHeight,
                0,
            );
        }
        5 => {
            /* e */
            h264bsdInterpolateHorVerQuarter(
                refPic.data,
                lumaPartData,
                xInt - 2,
                yInt - 2,
                width,
                height,
                partWidth,
                partHeight,
                0,
            );
        }
        6 => {
            /* i */
            h264bsdInterpolateMidHorQuarter(
                refPic.data,
                lumaPartData,
                xInt - 2,
                yInt - 2,
                width,
                height,
                partWidth,
                partHeight,
                0,
            );
        }
        7 => {
            /* p */
            h264bsdInterpolateHorVerQuarter(
                refPic.data,
                lumaPartData,
                xInt - 2,
                yInt - 2,
                width,
                height,
                partWidth,
                partHeight,
                2,
            );
        }
        8 => {
            /* b */
            h264bsdInterpolateHorHalf(
                refPic.data,
                lumaPartData,
                xInt - 2,
                yInt,
                width,
                height,
                partWidth,
                partHeight,
            );
        }
        9 => {
            /* f */
            h264bsdInterpolateMidVerQuarter(
                refPic.data,
                lumaPartData,
                xInt - 2,
                yInt - 2,
                width,
                height,
                partWidth,
                partHeight,
                0,
            );
        }
        10 => {
            /* j */
            h264bsdInterpolateMidHalf(
                refPic.data,
                lumaPartData,
                xInt - 2,
                yInt - 2,
                width,
                height,
                partWidth,
                partHeight,
            );
        }
        11 => {
            /* q */
            h264bsdInterpolateMidVerQuarter(
                refPic.data,
                lumaPartData,
                xInt - 2,
                yInt - 2,
                width,
                height,
                partWidth,
                partHeight,
                1,
            );
        }
        12 => {
            /* c */
            h264bsdInterpolateHorQuarter(
                refPic.data,
                lumaPartData,
                xInt - 2,
                yInt,
                width,
                height,
                partWidth,
                partHeight,
                1,
            );
        }
        13 => {
            /* g */
            h264bsdInterpolateHorVerQuarter(
                refPic.data,
                lumaPartData,
                xInt - 2,
                yInt - 2,
                width,
                height,
                partWidth,
                partHeight,
                1,
            );
        }
        14 => {
            /* k */
            h264bsdInterpolateMidHorQuarter(
                refPic.data,
                lumaPartData,
                xInt - 2,
                yInt - 2,
                width,
                height,
                partWidth,
                partHeight,
                1,
            );
        }
        _ => {
            /* case 15, r */
            h264bsdInterpolateHorVerQuarter(
                refPic.data,
                lumaPartData,
                xInt - 2,
                yInt - 2,
                width,
                height,
                partWidth,
                partHeight,
                3,
            );
        }
    }

    /* chroma */
    PredictChroma(
        data.add((16 * 16 + (partY >> 1) * 8 + (partX >> 1)) as usize),
        xA + partX,
        yA + partY,
        partWidth,
        partHeight,
        mv,
        refPic,
    );
}

/*------------------------------------------------------------------------------

    Function: FillRow1

        Functional description:
          This function gets a row of reference pels in a 'normal' case when no
          overfilling is necessary.

------------------------------------------------------------------------------*/
unsafe fn FillRow1(ref_: *const u8, fill: *mut u8, left: i32, center: i32, right: i32) {
    /* non-FLASCC path: memcpy(fill, ref, center) */
    core::ptr::copy_nonoverlapping(ref_, fill, center as usize);
}

/*------------------------------------------------------------------------------

    Function: h264bsdFillRow7

        Functional description:
          This function gets a row of reference pels when horizontal coordinate
          is partly negative or partly greater than reference picture width
          (overfilling some pels on left and/or right edge).
        Inputs:
          ref       pointer to reference samples
          left      amount of pixels to overfill on left-edge
          center    amount of pixels to copy
          right     amount of pixels to overfill on right-edge
        Outputs:
          fill      pointer where samples are stored

------------------------------------------------------------------------------*/
pub unsafe fn h264bsdFillRow7(
    ref_: *const u8,
    fill: *mut u8,
    left: i32,
    center: i32,
    right: i32,
) {
    let mut ref_ = ref_;
    let mut fill = fill;
    let mut left = left;
    let mut center = center;
    let mut right = right;
    let mut tmp: u8 = 0;

    if left != 0 {
        tmp = *ref_;
    }

    while left != 0 {
        *fill = tmp;
        fill = fill.add(1);
        left -= 1;
    }

    while center != 0 {
        *fill = *ref_;
        fill = fill.add(1);
        ref_ = ref_.add(1);
        center -= 1;
    }

    if right != 0 {
        tmp = *ref_.offset(-1);
    }

    while right != 0 {
        *fill = tmp;
        fill = fill.add(1);
        right -= 1;
    }
}

/*------------------------------------------------------------------------------

    Function: h264bsdFillBlock

        Functional description:
          This function gets a block of reference pels. It determines whether
          overfilling is needed or not and repeatedly calls an appropriate
          function that fills one row of the block.
        Inputs:
          ref               pointer to reference frame
          x0                x-coordinate for block
          y0                y-coordinate for block
          width             width of reference frame
          height            height of reference frame
          blockWidth        width of block
          blockHeight       height of block
          fillScanLength    length of a line in output array (pixels)
        Outputs:
          fill              pointer to array where output block is written

------------------------------------------------------------------------------*/
pub unsafe fn h264bsdFillBlock(
    ref_: *const u8,
    fill: *mut u8,
    x0: i32,
    y0: i32,
    width: u32,
    height: u32,
    blockWidth: u32,
    blockHeight: u32,
    fillScanLength: u32,
) {
    /* Variables */

    let mut xstop: i32;
    let mut ystop: i32;
    let left: i32;
    let x: i32;
    let right: i32;
    let mut top: i32;
    let mut y: i32;
    let mut bottom: i32;

    let mut ref_ = ref_;
    let mut fill = fill;
    let mut x0 = x0;
    let mut y0 = y0;

    /* Code */

    xstop = x0 + blockWidth as i32;
    ystop = y0 + blockHeight as i32;

    /* PORT NOTE: the C picks a row-fill function pointer (`fp`) here
     * (FillRow1 vs h264bsdFillRow7) but the call through it is commented
     * out; the selection condition is duplicated inline below, as in C. */

    if ystop < 0 {
        y0 = -(blockHeight as i32);
    }

    if xstop < 0 {
        x0 = -(blockWidth as i32);
    }

    if y0 > height as i32 {
        y0 = height as i32;
    }

    if x0 > width as i32 {
        x0 = width as i32;
    }

    xstop = x0 + blockWidth as i32;
    ystop = y0 + blockHeight as i32;

    if x0 > 0 {
        ref_ = ref_.add(x0 as usize);
    }

    if y0 > 0 {
        ref_ = ref_.add((y0 * width as i32) as usize);
    }

    left = if x0 < 0 { -x0 } else { 0 };
    right = if xstop > width as i32 { xstop - width as i32 } else { 0 };
    x = blockWidth as i32 - left - right;

    top = if y0 < 0 { -y0 } else { 0 };
    bottom = if ystop > height as i32 { ystop - height as i32 } else { 0 };
    y = blockHeight as i32 - top - bottom;

    if x0 >= 0 && xstop <= width as i32 {
        /* Top-overfilling */
        while top != 0 {
            FillRow1(ref_, fill, left, x, right);
            fill = fill.add(fillScanLength as usize);
            top -= 1;
        }
        /* PORT NOTE: dead duplicate top-loop in the C source (top is
         * already 0 here); kept for fidelity, never executes. */
        while top != 0 {
            FillRow1(ref_, fill, left, x, right);
            top -= 1;
        }
        /* Lines inside reference image */
        while y != 0 {
            FillRow1(ref_, fill, left, x, right);
            ref_ = ref_.add(width as usize);
            fill = fill.add(fillScanLength as usize);
            y -= 1;
        }
    } else {
        /* Top-overfilling */
        while top != 0 {
            h264bsdFillRow7(ref_, fill, left, x, right);
            fill = fill.add(fillScanLength as usize);
            top -= 1;
        }
        /* PORT NOTE: dead duplicate top-loop, see above. */
        while top != 0 {
            h264bsdFillRow7(ref_, fill, left, x, right);
            top -= 1;
        }
        /* Lines inside reference image */
        while y != 0 {
            h264bsdFillRow7(ref_, fill, left, x, right);
            ref_ = ref_.add(width as usize);
            fill = fill.add(fillScanLength as usize);
            y -= 1;
        }
    }

    /* wrapping_sub: C does `ref -= width` unconditionally; when there is
     * no bottom-overfill the resulting pointer is unused */
    ref_ = ref_.wrapping_sub(width as usize);

    /* Bottom-overfilling */
    while bottom != 0 {
        if x0 >= 0 && xstop <= width as i32 {
            FillRow1(ref_, fill, left, x, right);
        } else {
            h264bsdFillRow7(ref_, fill, left, x, right);
        }
        fill = fill.add(fillScanLength as usize);
        bottom -= 1;
    }
}

// ============================================================================
// h264bsd_image.c
// ============================================================================

/*------------------------------------------------------------------------------

    Function: h264bsdWriteMacroblock

        Functional description:
            Write one macroblock into the image. Both luma and chroma
            components will be written at the same time.

        Inputs:
            data    pointer to macroblock data to be written, 256 values for
                    luma followed by 64 values for both chroma components

        Outputs:
            image   pointer to the image where the macroblock will be written

------------------------------------------------------------------------------*/
pub unsafe fn h264bsdWriteMacroblock(image: &mut image_t, data: *const u8) {
    /* Variables */

    let mut i: u32;
    let mut width: u32;
    let mut lum: *mut u32;
    let mut cb: *mut u32;
    let mut cr: *mut u32;
    let mut ptr: *const u32;
    let mut tmp1: u32;
    let mut tmp2: u32;

    /* Code */

    width = image.width;

    /* lum, cb and cr used to copy 4 bytes at a time; the C asserts these
     * pointers (and data) are 4-byte aligned, so plain derefs match. */
    lum = image.luma as *mut u32;
    cb = image.cb as *mut u32;
    cr = image.cr as *mut u32;

    ptr = data as *const u32;

    width *= 4;
    i = 16;
    while i != 0 {
        tmp1 = *ptr;
        ptr = ptr.add(1);
        tmp2 = *ptr;
        ptr = ptr.add(1);
        *lum = tmp1;
        lum = lum.add(1);
        *lum = tmp2;
        lum = lum.add(1);
        tmp1 = *ptr;
        ptr = ptr.add(1);
        tmp2 = *ptr;
        ptr = ptr.add(1);
        *lum = tmp1;
        lum = lum.add(1);
        *lum = tmp2;
        lum = lum.add(1);
        lum = lum.add((width - 4) as usize);
        i -= 1;
    }

    width >>= 1;
    i = 8;
    while i != 0 {
        tmp1 = *ptr;
        ptr = ptr.add(1);
        tmp2 = *ptr;
        ptr = ptr.add(1);
        *cb = tmp1;
        cb = cb.add(1);
        *cb = tmp2;
        cb = cb.add(1);
        cb = cb.add((width - 2) as usize);
        i -= 1;
    }

    i = 8;
    while i != 0 {
        tmp1 = *ptr;
        ptr = ptr.add(1);
        tmp2 = *ptr;
        ptr = ptr.add(1);
        *cr = tmp1;
        cr = cr.add(1);
        *cr = tmp2;
        cr = cr.add(1);
        cr = cr.add((width - 2) as usize);
        i -= 1;
    }
}

/*------------------------------------------------------------------------------

    Function: h264bsdWriteOutputBlocks

        Functional description:
            Write one macroblock into the image. Prediction for the macroblock
            and the residual are given separately and will be combined while
            writing the data to the image

        Inputs:
            data        pointer to macroblock prediction data, 256 values for
                        luma followed by 64 values for both chroma components
            mbNum       number of the macroblock
            residual    pointer to residual data, 16 16-element arrays for luma
                        followed by 4 16-element arrays for both chroma
                        components

        Outputs:
            image       pointer to the image where the data will be written

------------------------------------------------------------------------------*/
pub unsafe fn h264bsdWriteOutputBlocks(
    image: &mut image_t,
    mbNum: u32,
    data: *const u8,
    residual: *mut [i32; 16],
) {
    /* Variables */

    let mut i: u32;
    let mut picWidth: u32;
    let picSize: u32;
    let lum: *mut u8;
    let cb: *mut u8;
    let cr: *mut u8;
    let mut imageBlock: *mut u8;
    let mut tmp: *const u8;
    let row: u32;
    let col: u32;
    let mut block: u32;
    let mut x: u32;
    let mut y: u32;
    let mut pRes: *mut i32;
    let mut tmp1: i32;
    let mut tmp2: i32;
    let mut tmp3: i32;
    let mut tmp4: i32;
    let clp: *const u8 = h264bsdClip.as_ptr().add(512);

    /* Code */

    /* Image size in macroblocks */
    picWidth = image.width;
    picSize = picWidth * image.height;
    row = udiv(mbNum, picWidth);
    col = urem(mbNum, picWidth);

    /* Output macroblock position in output picture */
    lum = image.data.add((row * picWidth * 256 + col * 16) as usize);
    cb = image
        .data
        .add((picSize * 256 + row * picWidth * 64 + col * 8) as usize);
    cr = cb.add((picSize * 64) as usize);

    picWidth *= 16;

    block = 0;
    while block < 16 {
        x = h264bsdBlockX[block as usize];
        y = h264bsdBlockY[block as usize];

        pRes = (*residual.add(block as usize)).as_mut_ptr();

        tmp = data.add((y * 16 + x) as usize);
        imageBlock = lum.add((y * picWidth + x) as usize);

        if IS_RESIDUAL_EMPTY(&*residual.add(block as usize)) {
            /* aligned per C asserts: plain 32-bit copies */
            let mut in32 = tmp as *const i32;
            let mut out32 = imageBlock as *mut i32;

            /* Residual is zero => copy prediction block to output */
            tmp1 = *in32;
            in32 = in32.add(4);
            tmp2 = *in32;
            in32 = in32.add(4);
            *out32 = tmp1;
            out32 = out32.add((picWidth / 4) as usize);
            *out32 = tmp2;
            out32 = out32.add((picWidth / 4) as usize);
            tmp1 = *in32;
            in32 = in32.add(4);
            tmp2 = *in32;
            *out32 = tmp1;
            out32 = out32.add((picWidth / 4) as usize);
            *out32 = tmp2;
        } else {
            /* Calculate image = prediction + residual
             * Process four pixels in a loop */
            i = 4;
            while i != 0 {
                tmp1 = *tmp.add(0) as i32;
                tmp2 = *pRes;
                pRes = pRes.add(1);
                tmp3 = *tmp.add(1) as i32;
                tmp1 = *clp.offset((tmp1 + tmp2) as isize) as i32;
                tmp4 = *pRes;
                pRes = pRes.add(1);
                *imageBlock.add(0) = tmp1 as u8;
                tmp3 = *clp.offset((tmp3 + tmp4) as isize) as i32;
                tmp1 = *tmp.add(2) as i32;
                tmp2 = *pRes;
                pRes = pRes.add(1);
                *imageBlock.add(1) = tmp3 as u8;
                tmp1 = *clp.offset((tmp1 + tmp2) as isize) as i32;
                tmp3 = *tmp.add(3) as i32;
                tmp4 = *pRes;
                pRes = pRes.add(1);
                *imageBlock.add(2) = tmp1 as u8;
                tmp3 = *clp.offset((tmp3 + tmp4) as isize) as i32;
                tmp = tmp.add(16);
                *imageBlock.add(3) = tmp3 as u8;
                imageBlock = imageBlock.add(picWidth as usize);
                i -= 1;
            }
        }

        block += 1;
    }

    picWidth /= 2;

    block = 16;
    while block <= 23 {
        x = h264bsdBlockX[(block & 0x3) as usize];
        y = h264bsdBlockY[(block & 0x3) as usize];

        pRes = (*residual.add(block as usize)).as_mut_ptr();

        tmp = data.add(256);
        imageBlock = cb;

        if block >= 20 {
            imageBlock = cr;
            tmp = tmp.add(64);
        }

        tmp = tmp.add((y * 8 + x) as usize);
        imageBlock = imageBlock.add((y * picWidth + x) as usize);

        if IS_RESIDUAL_EMPTY(&*residual.add(block as usize)) {
            /* aligned per C asserts: plain 32-bit copies */
            let mut in32 = tmp as *const i32;
            let mut out32 = imageBlock as *mut i32;

            /* Residual is zero => copy prediction block to output */
            tmp1 = *in32;
            in32 = in32.add(2);
            tmp2 = *in32;
            in32 = in32.add(2);
            *out32 = tmp1;
            out32 = out32.add((picWidth / 4) as usize);
            *out32 = tmp2;
            out32 = out32.add((picWidth / 4) as usize);
            tmp1 = *in32;
            in32 = in32.add(2);
            tmp2 = *in32;
            *out32 = tmp1;
            out32 = out32.add((picWidth / 4) as usize);
            *out32 = tmp2;
        } else {
            i = 4;
            while i != 0 {
                tmp1 = *tmp.add(0) as i32;
                tmp2 = *pRes;
                pRes = pRes.add(1);
                tmp3 = *tmp.add(1) as i32;
                tmp1 = *clp.offset((tmp1 + tmp2) as isize) as i32;
                tmp4 = *pRes;
                pRes = pRes.add(1);
                *imageBlock.add(0) = tmp1 as u8;
                tmp3 = *clp.offset((tmp3 + tmp4) as isize) as i32;
                tmp1 = *tmp.add(2) as i32;
                tmp2 = *pRes;
                pRes = pRes.add(1);
                *imageBlock.add(1) = tmp3 as u8;
                tmp1 = *clp.offset((tmp1 + tmp2) as isize) as i32;
                tmp3 = *tmp.add(3) as i32;
                tmp4 = *pRes;
                pRes = pRes.add(1);
                *imageBlock.add(2) = tmp1 as u8;
                tmp3 = *clp.offset((tmp3 + tmp4) as isize) as i32;
                tmp = tmp.add(8);
                *imageBlock.add(3) = tmp3 as u8;
                imageBlock = imageBlock.add(picWidth as usize);
                i -= 1;
            }
        }

        block += 1;
    }
}
