// JPEG decoder for the unified image codec.
//
// Pipeline: segment walk → quantization tables (DQT) → Huffman
// tables (DHT) → SOF0 baseline OR SOF2 progressive frame → SOS
// scans (one for baseline, multiple for progressive) → per-MCU
// Huffman decode → coefficient accumulation → final dequant + IDCT
// → upsample chroma → YCbCr→RGB → nearest-neighbour scale →
// RGB565 in s.pending.
//
// Supported subset:
//   * Baseline sequential (SOF0 / FF C0). Single scan, full DC + AC
//     per block.
//   * Progressive (SOF2 / FF C2). Multiple SOS segments, each
//     refining a coefficient range. Spectral selection (Ss/Se),
//     successive approximation (Ah/Al), EOBRUN, ZRL, refinement —
//     full RFC 1950 / T.81 §G.1.
//   * Extended sequential and lossless (SOF1, SOF3, SOF9..) are
//     rejected.
//   * 8-bit precision, 1 (grayscale) or 3 (YCbCr) components.
//   * Restart markers tolerated (DC predictors + EOBRUN reset).
//   * Common chroma subsamplings (4:4:4, 4:2:2, 4:2:0, 4:4:0).
//
// Memory: Huffman tables + quant tables stay in-stack; the
// per-component coefficient grids and the YCbCr planes are
// heap-allocated and freed before return.

use super::image_codec::{ensure_pending, log, log_dims, store_rgb565, ImageState};

const MAX_COMPONENTS: usize = 4;
const ZIGZAG: [u8; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

#[derive(Clone, Copy)]
struct Component {
    id: u8,
    h_samp: u8,
    v_samp: u8,
    quant_id: u8,
    dc_id: u8,
    ac_id: u8,
    dc_pred: i32,
    /// Width in 8x8 blocks at frame resolution. Computed after SOF.
    blocks_w: u16,
    /// Height in 8x8 blocks at frame resolution.
    blocks_h: u16,
}

impl Component {
    const fn new() -> Self {
        Self {
            id: 0,
            h_samp: 0,
            v_samp: 0,
            quant_id: 0,
            dc_id: 0,
            ac_id: 0,
            dc_pred: 0,
            blocks_w: 0,
            blocks_h: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct HuffTable {
    bits: [u8; 17],
    huffval: [u8; 256],
    n_symbols: u16,
}

impl HuffTable {
    const fn new() -> Self {
        Self {
            bits: [0; 17],
            huffval: [0; 256],
            n_symbols: 0,
        }
    }

    fn decode(&self, br: &mut JpegBitReader) -> Option<u8> {
        let mut code: i32 = 0;
        let mut idx: usize = 0;
        for len in 1..=16 {
            let bit = br.read_bits(1)? as i32;
            code = (code << 1) | bit;
            let count = self.bits[len] as i32;
            if code < count {
                let sym_idx = idx + code as usize;
                if sym_idx < self.n_symbols as usize {
                    return Some(self.huffval[sym_idx]);
                }
                return None;
            }
            idx += count as usize;
            code -= count;
        }
        None
    }
}

/// MSB-first bit reader for JPEG entropy-coded data. Honours byte
/// stuffing (FF 00 → FF), restart markers (FF D0..D7), and any
/// other marker (FF xx where xx is not 00 / D0..D7) terminates the
/// scan.
struct JpegBitReader<'a> {
    src: &'a [u8],
    pos: usize,
    buf: u32,
    n: u32,
    /// Sticky flag — set when a non-restart, non-stuffing marker
    /// is encountered. The caller checks this between blocks /
    /// MCUs to break out of the scan.
    end_of_scan: bool,
}

impl<'a> JpegBitReader<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            pos: 0,
            buf: 0,
            n: 0,
            end_of_scan: false,
        }
    }

    fn read_bits(&mut self, count: u32) -> Option<u32> {
        while self.n < count {
            if self.pos >= self.src.len() {
                self.end_of_scan = true;
                return None;
            }
            let b = self.src[self.pos];
            self.pos += 1;
            let real_byte = if b == 0xFF {
                if self.pos >= self.src.len() {
                    self.end_of_scan = true;
                    return None;
                }
                let nb = self.src[self.pos];
                if nb == 0x00 {
                    self.pos += 1;
                    0xFF
                } else if (0xD0..=0xD7).contains(&nb) {
                    self.pos += 1;
                    // Restart marker is consumed but the bit stream
                    // continues with the next byte. The caller is
                    // expected to detect MCU-mod boundary and reset
                    // DC predictors + EOBRUN separately; we just
                    // skip the marker.
                    continue;
                } else {
                    // Some other marker (EOI / next SOS / DHT / …).
                    // Un-consume the FF and signal end-of-scan.
                    self.pos -= 1;
                    self.end_of_scan = true;
                    return None;
                }
            } else {
                b
            };
            self.buf = (self.buf << 8) | (real_byte as u32);
            self.n += 8;
        }
        let v = (self.buf >> (self.n - count)) & ((1u32 << count) - 1);
        self.n -= count;
        Some(v)
    }

    /// Align to byte boundary (drop residual bits in `buf`).
    fn align_to_byte(&mut self) {
        let drop = self.n & 7;
        if drop > 0 {
            self.buf >>= drop;
            self.n -= drop;
        }
    }

    fn extend(v: u32, len: u32) -> i32 {
        if len == 0 {
            return 0;
        }
        let mask = 1u32 << (len - 1);
        if v & mask != 0 {
            v as i32
        } else {
            (v as i32) - ((1i32 << len) - 1)
        }
    }
}

// ── Top-level decode ────────────────────────────────────────────────────

pub unsafe fn jpeg_decode(s: &mut ImageState) -> bool {
    let buf = core::slice::from_raw_parts(s.encoded, s.encoded_used as usize);
    if buf.len() < 4 || buf[0] != 0xFF || buf[1] != 0xD8 {
        log(s, b"[img] jpeg: bad SOI");
        return false;
    }

    let mut qt = [[0i16; 64]; 4];
    let mut huff_dc = [HuffTable::new(); 4];
    let mut huff_ac = [HuffTable::new(); 4];
    let mut comps = [Component::new(); MAX_COMPONENTS];
    let mut n_comps: usize = 0;
    let mut src_w: usize = 0;
    let mut src_h: usize = 0;
    let mut restart_interval: u16 = 0;
    let mut progressive = false;

    // Coefficient grids: heap-allocated once SOF lands. coeffs[c]
    // is per-component, indexed by (block_y * blocks_w + block_x),
    // each block 64 × i16.
    let mut coeffs_buf: [*mut i16; MAX_COMPONENTS] = [core::ptr::null_mut(); MAX_COMPONENTS];
    let mut blocks_per_comp = [0usize; MAX_COMPONENTS];
    let mut h_max: u8 = 1;
    let mut v_max: u8 = 1;
    let mut frame_inited = false;

    // Helper closure-free pattern: define a goto-style label via
    // `'walk`. We'll need to return cleanup via heap_free of
    // coeffs_buf on any error.
    let mut cur = 2usize;
    let ok = 'walk: loop {
        if cur + 1 >= buf.len() {
            log(s, b"[img] jpeg: truncated");
            break false;
        }
        if buf[cur] != 0xFF {
            log(s, b"[img] jpeg: lost sync");
            break false;
        }
        let mut p = cur + 1;
        while p < buf.len() && buf[p] == 0xFF {
            p += 1;
        }
        if p >= buf.len() {
            break false;
        }
        let marker = buf[p];
        cur = p + 1;

        if marker == 0xD9 {
            // EOI — done.
            break frame_inited;
        }
        if matches!(marker, 0xD0..=0xD7) || marker == 0x01 {
            continue;
        }

        if cur + 2 > buf.len() {
            break false;
        }
        let seg_len = u16::from_be_bytes([buf[cur], buf[cur + 1]]) as usize;
        if seg_len < 2 || cur + seg_len > buf.len() {
            log(s, b"[img] jpeg: bad seg len");
            break false;
        }
        let seg = &buf[cur + 2..cur + seg_len];
        let next = cur + seg_len;

        match marker {
            // SOF0 baseline, SOF2 progressive.
            0xC0 | 0xC2 => {
                progressive = marker == 0xC2;
                if seg.len() < 6 {
                    break false;
                }
                if seg[0] != 8 {
                    log(s, b"[img] jpeg: bit depth!=8");
                    break false;
                }
                src_h = u16::from_be_bytes([seg[1], seg[2]]) as usize;
                src_w = u16::from_be_bytes([seg[3], seg[4]]) as usize;
                if src_w == 0 || src_h == 0 || src_w > 4096 || src_h > 4096 {
                    log(s, b"[img] jpeg: bad dims");
                    break false;
                }
                n_comps = seg[5] as usize;
                if n_comps != 1 && n_comps != 3 {
                    log(s, b"[img] jpeg: ncomps !=1,3");
                    break false;
                }
                if seg.len() < 6 + 3 * n_comps {
                    break false;
                }
                for i in 0..n_comps {
                    let p = 6 + i * 3;
                    comps[i].id = seg[p];
                    comps[i].h_samp = seg[p + 1] >> 4;
                    comps[i].v_samp = seg[p + 1] & 0x0F;
                    comps[i].quant_id = seg[p + 2];
                    if comps[i].h_samp == 0
                        || comps[i].v_samp == 0
                        || comps[i].h_samp > 4
                        || comps[i].v_samp > 4
                        || comps[i].quant_id >= 4
                    {
                        break 'walk false;
                    }
                    if comps[i].h_samp > h_max {
                        h_max = comps[i].h_samp;
                    }
                    if comps[i].v_samp > v_max {
                        v_max = comps[i].v_samp;
                    }
                }
                // Per-component block grid: width_in_blocks at frame
                // resolution scaled by sampling ratio. MCU-aligned.
                let mcu_w_px = (h_max as usize) * 8;
                let mcu_h_px = (v_max as usize) * 8;
                let mcus_x = (src_w + mcu_w_px - 1) / mcu_w_px;
                let mcus_y = (src_h + mcu_h_px - 1) / mcu_h_px;
                for i in 0..n_comps {
                    comps[i].blocks_w = (mcus_x as u16) * (comps[i].h_samp as u16);
                    comps[i].blocks_h = (mcus_y as u16) * (comps[i].v_samp as u16);
                    let n = (comps[i].blocks_w as usize) * (comps[i].blocks_h as usize);
                    blocks_per_comp[i] = n;
                    let bytes = n * 64 * core::mem::size_of::<i16>();
                    coeffs_buf[i] = ((*s.syscalls).heap_alloc)(bytes as u32) as *mut i16;
                    if coeffs_buf[i].is_null() {
                        log(s, b"[img] jpeg: coef alloc fail");
                        break 'walk false;
                    }
                    // Zero-init the coefficients (progressive scans
                    // OR refine into pre-existing zeros).
                    let slice = core::slice::from_raw_parts_mut(coeffs_buf[i], n * 64);
                    for k in slice.iter_mut() {
                        *k = 0;
                    }
                }
                frame_inited = true;
            }
            0xC1 | 0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF => {
                log(s, b"[img] jpeg: SOF variant unsupported");
                break false;
            }
            0xDB => {
                let mut p = 0;
                while p < seg.len() {
                    let pq_tq = seg[p];
                    let pq = pq_tq >> 4;
                    let tq = (pq_tq & 0x0F) as usize;
                    p += 1;
                    if tq >= 4 {
                        break 'walk false;
                    }
                    if pq == 0 {
                        if p + 64 > seg.len() {
                            break 'walk false;
                        }
                        for k in 0..64 {
                            qt[tq][k] = seg[p + k] as i16;
                        }
                        p += 64;
                    } else if pq == 1 {
                        if p + 128 > seg.len() {
                            break 'walk false;
                        }
                        for k in 0..64 {
                            qt[tq][k] = u16::from_be_bytes([seg[p + 2 * k], seg[p + 2 * k + 1]]) as i16;
                        }
                        p += 128;
                    } else {
                        break 'walk false;
                    }
                }
            }
            0xC4 => {
                let mut p = 0;
                while p < seg.len() {
                    let tc_th = seg[p];
                    let tc = tc_th >> 4;
                    let th = (tc_th & 0x0F) as usize;
                    p += 1;
                    if th >= 4 || p + 16 > seg.len() {
                        break 'walk false;
                    }
                    let mut bits = [0u8; 17];
                    let mut total = 0usize;
                    for k in 0..16 {
                        bits[k + 1] = seg[p + k];
                        total += seg[p + k] as usize;
                    }
                    p += 16;
                    if total > 256 || p + total > seg.len() {
                        break 'walk false;
                    }
                    let dst = if tc == 0 {
                        &mut huff_dc[th]
                    } else if tc == 1 {
                        &mut huff_ac[th]
                    } else {
                        break 'walk false;
                    };
                    dst.bits = bits;
                    for k in 0..total {
                        dst.huffval[k] = seg[p + k];
                    }
                    dst.n_symbols = total as u16;
                    p += total;
                }
            }
            0xDD => {
                if seg.len() != 2 {
                    break 'walk false;
                }
                restart_interval = u16::from_be_bytes([seg[0], seg[1]]);
            }
            0xDA => {
                if !frame_inited {
                    log(s, b"[img] jpeg: SOS before SOF");
                    break 'walk false;
                }
                let scan_n = seg[0] as usize;
                if scan_n == 0 || scan_n > n_comps || seg.len() < 1 + 2 * scan_n + 3 {
                    break 'walk false;
                }
                let mut scan_idx = [0usize; MAX_COMPONENTS];
                for i in 0..scan_n {
                    let cid = seg[1 + 2 * i];
                    let td_ta = seg[1 + 2 * i + 1];
                    let mut found = false;
                    for (j, c) in comps.iter_mut().take(n_comps).enumerate() {
                        if c.id == cid {
                            c.dc_id = td_ta >> 4;
                            c.ac_id = td_ta & 0x0F;
                            c.dc_pred = 0;
                            scan_idx[i] = j;
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        break 'walk false;
                    }
                }
                let ss = seg[1 + 2 * scan_n];
                let se = seg[2 + 2 * scan_n];
                let ah_al = seg[3 + 2 * scan_n];
                let ah = ah_al >> 4;
                let al = ah_al & 0x0F;

                let ecs = &buf[next..];
                let consumed = if progressive {
                    decode_progressive_scan(
                        ecs,
                        &huff_dc,
                        &huff_ac,
                        &mut comps,
                        n_comps,
                        &scan_idx[..scan_n],
                        scan_n,
                        ss,
                        se,
                        ah,
                        al,
                        coeffs_buf,
                        restart_interval,
                    )
                } else {
                    decode_baseline_scan(
                        ecs,
                        &huff_dc,
                        &huff_ac,
                        &mut comps,
                        n_comps,
                        &scan_idx[..scan_n],
                        scan_n,
                        coeffs_buf,
                        restart_interval,
                    )
                };
                let consumed = match consumed {
                    Some(v) => v,
                    None => {
                        log(s, b"[img] jpeg: scan decode fail");
                        break 'walk false;
                    }
                };
                cur = next + consumed;
                continue;
            }
            _ => {}
        }
        cur = next;
    };

    if !ok || !frame_inited {
        for i in 0..MAX_COMPONENTS {
            if !coeffs_buf[i].is_null() {
                ((*s.syscalls).heap_free)(coeffs_buf[i] as *mut u8);
            }
        }
        return false;
    }

    // ── Dequant + IDCT per block → planar YCbCr ────────────────────────
    let mcu_w_px = (h_max as usize) * 8;
    let mcu_h_px = (v_max as usize) * 8;
    let mcus_x = (src_w + mcu_w_px - 1) / mcu_w_px;
    let mcus_y = (src_h + mcu_h_px - 1) / mcu_h_px;
    let plane_w = mcus_x * mcu_w_px;
    let plane_h = mcus_y * mcu_h_px;

    let mut planes: [*mut u8; MAX_COMPONENTS] = [core::ptr::null_mut(); MAX_COMPONENTS];
    for i in 0..n_comps {
        planes[i] = ((*s.syscalls).heap_alloc)((plane_w * plane_h) as u32);
        if planes[i].is_null() {
            for j in 0..i {
                ((*s.syscalls).heap_free)(planes[j]);
            }
            for j in 0..MAX_COMPONENTS {
                if !coeffs_buf[j].is_null() {
                    ((*s.syscalls).heap_free)(coeffs_buf[j] as *mut u8);
                }
            }
            log(s, b"[img] jpeg: plane alloc fail");
            return false;
        }
    }

    let mut block = [0i32; 64];
    for ci in 0..n_comps {
        let bw = comps[ci].blocks_w as usize;
        let bh = comps[ci].blocks_h as usize;
        let q = &qt[comps[ci].quant_id as usize];
        let coeffs = core::slice::from_raw_parts(coeffs_buf[ci], blocks_per_comp[ci] * 64);
        for by in 0..bh {
            for bx in 0..bw {
                let base = (by * bw + bx) * 64;
                for k in 0..64 {
                    block[k] = (coeffs[base + k] as i32) * (q[k] as i32);
                }
                let px = bx * 8;
                let py = by * 8;
                write_block(planes[ci], plane_w, px, py, &block);
            }
        }
    }
    for j in 0..MAX_COMPONENTS {
        if !coeffs_buf[j].is_null() {
            ((*s.syscalls).heap_free)(coeffs_buf[j] as *mut u8);
        }
    }

    let render_ok = render_jpeg(
        s,
        &planes[..n_comps],
        n_comps,
        plane_w,
        plane_h,
        src_w,
        src_h,
        h_max as usize,
        v_max as usize,
        &comps[..n_comps],
    );
    for i in 0..n_comps {
        ((*s.syscalls).heap_free)(planes[i]);
    }
    if !render_ok {
        return false;
    }
    log_dims(
        s,
        b"[img] decoded ",
        src_w as u32,
        src_h as u32,
        s.dst_w as u32,
        s.dst_h as u32,
    );
    true
}

// ── Baseline scan decoder ───────────────────────────────────────────────

unsafe fn decode_baseline_scan(
    ecs: &[u8],
    huff_dc: &[HuffTable; 4],
    huff_ac: &[HuffTable; 4],
    comps: &mut [Component; MAX_COMPONENTS],
    n_comps: usize,
    scan_idx: &[usize],
    _scan_n: usize,
    coeffs: [*mut i16; MAX_COMPONENTS],
    restart_interval: u16,
) -> Option<usize> {
    let mut h_max: u8 = 1;
    let mut v_max: u8 = 1;
    for c in comps.iter().take(n_comps) {
        if c.h_samp > h_max { h_max = c.h_samp; }
        if c.v_samp > v_max { v_max = c.v_samp; }
    }
    let h0 = comps[0].h_samp as usize;
    let v0 = comps[0].v_samp as usize;
    if h0 == 0 || v0 == 0 { return None; }
    let mcus_x = (comps[0].blocks_w as usize) / h0;
    let mcus_y = (comps[0].blocks_h as usize) / v0;

    let mut br = JpegBitReader::new(ecs);
    let mut mcu_count: u32 = 0;
    let mut block = [0i16; 64];

    for my in 0..mcus_y {
        for mx in 0..mcus_x {
            for &ci in scan_idx.iter() {
                let h = comps[ci].h_samp as usize;
                let v = comps[ci].v_samp as usize;
                for by in 0..v {
                    for bx in 0..h {
                        for k in 0..64 { block[k] = 0; }
                        if !decode_baseline_block(
                            &mut br,
                            &huff_dc[comps[ci].dc_id as usize],
                            &huff_ac[comps[ci].ac_id as usize],
                            &mut block,
                            &mut comps[ci].dc_pred,
                        ) {
                            return None;
                        }
                        let block_x = mx * h + bx;
                        let block_y = my * v + by;
                        let base = (block_y * comps[ci].blocks_w as usize + block_x) * 64;
                        let dst = core::slice::from_raw_parts_mut(coeffs[ci].add(base), 64);
                        for k in 0..64 {
                            dst[k] = block[k];
                        }
                    }
                }
            }
            mcu_count += 1;
            if restart_interval > 0 && (mcu_count as u16) == restart_interval {
                mcu_count = 0;
                for c in comps.iter_mut().take(n_comps) {
                    c.dc_pred = 0;
                }
                br.align_to_byte();
                br.buf = 0;
                br.n = 0;
            }
        }
    }
    let _ = (h_max, v_max);
    Some(br.pos)
}

fn decode_baseline_block(
    br: &mut JpegBitReader,
    dc_tbl: &HuffTable,
    ac_tbl: &HuffTable,
    block: &mut [i16; 64],
    dc_pred: &mut i32,
) -> bool {
    let t = match dc_tbl.decode(br) {
        Some(v) => v,
        None => return false,
    };
    let dc_diff = if t == 0 {
        0
    } else {
        let bits = match br.read_bits(t as u32) {
            Some(v) => v,
            None => return false,
        };
        JpegBitReader::extend(bits, t as u32)
    };
    *dc_pred += dc_diff;
    block[0] = *dc_pred as i16;

    let mut k = 1;
    while k < 64 {
        let rs = match ac_tbl.decode(br) {
            Some(v) => v,
            None => return false,
        };
        let run = (rs >> 4) as usize;
        let size = (rs & 0x0F) as u32;
        if size == 0 {
            if run == 15 {
                k += 16;
                continue;
            }
            break; // EOB
        }
        k += run;
        if k >= 64 {
            return false;
        }
        let bits = match br.read_bits(size) {
            Some(v) => v,
            None => return false,
        };
        let value = JpegBitReader::extend(bits, size);
        let zz = ZIGZAG[k] as usize;
        block[zz] = value as i16;
        k += 1;
    }
    true
}

// ── Progressive scan decoder ────────────────────────────────────────────
//
// Four cases: (DC vs AC) × (initial vs refinement).
//
// DC initial (Ss==0, Ah==0): per block, read t = decode_dc(HT), then
//   t bits for the diff, apply to DC pred, store `(dc_pred) << Al`.
// DC refinement (Ss==0, Ah!=0): per block, read 1 bit, OR into
//   block[0] at position Al.
// AC initial (Ss>0, Ah==0): per block, read AC pairs. EOBRUN counts
//   blocks to skip entirely.
// AC refinement (Ss>0, Ah!=0): per block, refine existing non-zero
//   coefficients with 1-bit corrections; encoded zero runs may also
//   spawn new ±1 coefficients.

unsafe fn decode_progressive_scan(
    ecs: &[u8],
    huff_dc: &[HuffTable; 4],
    huff_ac: &[HuffTable; 4],
    comps: &mut [Component; MAX_COMPONENTS],
    n_comps: usize,
    scan_idx: &[usize],
    scan_n: usize,
    ss: u8,
    se: u8,
    ah: u8,
    al: u8,
    coeffs: [*mut i16; MAX_COMPONENTS],
    restart_interval: u16,
) -> Option<usize> {
    let dc_scan = ss == 0;
    if dc_scan {
        if se != 0 {
            return None;
        }
    } else if ss == 0 || se < ss || se >= 64 {
        return None;
    }
    // For AC scans, scan_n must be 1.
    if !dc_scan && scan_n != 1 {
        return None;
    }

    // Determine iteration shape. For DC scans with interleaved
    // components, walk MCUs (h*v blocks per component). For
    // single-component AC scans, walk that component's full block
    // grid directly.
    let mut br = JpegBitReader::new(ecs);
    let mut mcu_count: u32 = 0;
    let mut eob_run: u32 = 0;

    if dc_scan && scan_n > 1 {
        let mut h_max: u8 = 1;
        let mut v_max: u8 = 1;
        for c in comps.iter().take(n_comps) {
            if c.h_samp > h_max { h_max = c.h_samp; }
            if c.v_samp > v_max { v_max = c.v_samp; }
        }
        let h0 = comps[0].h_samp as usize;
        let v0 = comps[0].v_samp as usize;
        if h0 == 0 || v0 == 0 { return None; }
        let mcus_x = (comps[0].blocks_w as usize) / h0;
        let mcus_y = (comps[0].blocks_h as usize) / v0;
        for my in 0..mcus_y {
            for mx in 0..mcus_x {
                for &ci in scan_idx.iter() {
                    let h = comps[ci].h_samp as usize;
                    let v = comps[ci].v_samp as usize;
                    for by in 0..v {
                        for bx in 0..h {
                            let block_x = mx * h + bx;
                            let block_y = my * v + by;
                            let base = (block_y * comps[ci].blocks_w as usize + block_x) * 64;
                            let dst = core::slice::from_raw_parts_mut(coeffs[ci].add(base), 64);
                            if ah == 0 {
                                let t = huff_dc[comps[ci].dc_id as usize].decode(&mut br)?;
                                let diff = if t == 0 {
                                    0
                                } else {
                                    let bits = br.read_bits(t as u32)?;
                                    JpegBitReader::extend(bits, t as u32)
                                };
                                comps[ci].dc_pred += diff;
                                dst[0] = ((comps[ci].dc_pred) << al) as i16;
                            } else {
                                let bit = br.read_bits(1)?;
                                if bit != 0 {
                                    dst[0] |= (1i16) << al;
                                }
                            }
                        }
                    }
                }
                mcu_count += 1;
                if restart_interval > 0 && (mcu_count as u16) == restart_interval {
                    mcu_count = 0;
                    for c in comps.iter_mut().take(n_comps) {
                        c.dc_pred = 0;
                    }
                    // Multi-component branch never reads `eob_run`, so
                    // the restart-interval reset isn't needed here
                    // (the single-component branch below resets its
                    // own counter at its restart point).
                    br.align_to_byte();
                    br.buf = 0;
                    br.n = 0;
                }
            }
        }
    } else {
        // Single-component scan (DC or AC). Walk the component's
        // own block grid.
        let ci = scan_idx[0];
        let bw = comps[ci].blocks_w as usize;
        let bh = comps[ci].blocks_h as usize;
        for by in 0..bh {
            for bx in 0..bw {
                let base = (by * bw + bx) * 64;
                let dst = core::slice::from_raw_parts_mut(coeffs[ci].add(base), 64);

                if dc_scan {
                    if ah == 0 {
                        let t = huff_dc[comps[ci].dc_id as usize].decode(&mut br)?;
                        let diff = if t == 0 {
                            0
                        } else {
                            let bits = br.read_bits(t as u32)?;
                            JpegBitReader::extend(bits, t as u32)
                        };
                        comps[ci].dc_pred += diff;
                        dst[0] = ((comps[ci].dc_pred) << al) as i16;
                    } else {
                        let bit = br.read_bits(1)?;
                        if bit != 0 {
                            dst[0] |= (1i16) << al;
                        }
                    }
                } else if ah == 0 {
                    // AC initial.
                    if eob_run > 0 {
                        eob_run -= 1;
                        // Skip this block (all AC remain 0 in this scan).
                    } else {
                        let mut k = ss as usize;
                        let ac_tbl = &huff_ac[comps[ci].ac_id as usize];
                        loop {
                            let rs = ac_tbl.decode(&mut br)?;
                            let run = (rs >> 4) as usize;
                            let size = (rs & 0x0F) as u32;
                            if size == 0 {
                                if run < 15 {
                                    // EOBn: skip (1<<run) - 1 more blocks plus this one.
                                    eob_run = (1u32 << run) - 1;
                                    if run > 0 {
                                        eob_run += br.read_bits(run as u32)?;
                                    }
                                    break;
                                }
                                // ZRL — skip 16 zero coefficients.
                                k += 16;
                                if k > se as usize {
                                    return None;
                                }
                                continue;
                            }
                            k += run;
                            if k > se as usize {
                                return None;
                            }
                            let bits = br.read_bits(size)?;
                            let value = JpegBitReader::extend(bits, size);
                            let zz = ZIGZAG[k] as usize;
                            dst[zz] = (value << al) as i16;
                            k += 1;
                            if k > se as usize {
                                break;
                            }
                        }
                    }
                } else {
                    // AC refinement scan.
                    let plus = (1i16) << al;
                    let minus = -((1i16) << al);
                    let ac_tbl = &huff_ac[comps[ci].ac_id as usize];
                    let mut k = ss as usize;
                    if eob_run > 0 {
                        // Refine any non-zero AC coefficients in this
                        // block in [ss..=se], using 1 bit each.
                        while k <= se as usize {
                            let zz = ZIGZAG[k] as usize;
                            if dst[zz] != 0 {
                                let bit = br.read_bits(1)?;
                                if bit != 0 {
                                    if dst[zz] > 0 {
                                        dst[zz] += plus;
                                    } else {
                                        dst[zz] += minus;
                                    }
                                }
                            }
                            k += 1;
                        }
                        eob_run -= 1;
                    } else {
                        // Process newly-coded coefficients.
                        loop {
                            let rs = ac_tbl.decode(&mut br)?;
                            let mut run = (rs >> 4) as usize;
                            let size = (rs & 0x0F) as u32;
                            let value: i16;
                            if size == 0 {
                                if run < 15 {
                                    eob_run = (1u32 << run).saturating_sub(1);
                                    if run > 0 {
                                        eob_run += br.read_bits(run as u32)?;
                                    }
                                    // After consuming the run header,
                                    // refine remaining nonzero coeffs
                                    // and exit the inner loop.
                                    while k <= se as usize {
                                        let zz = ZIGZAG[k] as usize;
                                        if dst[zz] != 0 {
                                            let bit = br.read_bits(1)?;
                                            if bit != 0 {
                                                if dst[zz] > 0 {
                                                    dst[zz] += plus;
                                                } else {
                                                    dst[zz] += minus;
                                                }
                                            }
                                        }
                                        k += 1;
                                    }
                                    break;
                                }
                                // ZRL: 16 zero "new" coefficients.
                                value = 0;
                            } else if size == 1 {
                                let bit = br.read_bits(1)?;
                                value = if bit != 0 { plus } else { minus };
                            } else {
                                return None; // size must be 0 or 1 in refinement scans
                            }
                            // Skip `run` zero (non-coded) positions,
                            // refining each non-zero we pass on the way.
                            loop {
                                if k > se as usize {
                                    return None;
                                }
                                let zz = ZIGZAG[k] as usize;
                                if dst[zz] != 0 {
                                    let bit = br.read_bits(1)?;
                                    if bit != 0 {
                                        if dst[zz] > 0 {
                                            dst[zz] += plus;
                                        } else {
                                            dst[zz] += minus;
                                        }
                                    }
                                    k += 1;
                                } else {
                                    if run == 0 {
                                        break;
                                    }
                                    run -= 1;
                                    k += 1;
                                }
                            }
                            if value != 0 {
                                if k > se as usize {
                                    return None;
                                }
                                let zz = ZIGZAG[k] as usize;
                                dst[zz] = value;
                                k += 1;
                            }
                            if k > se as usize {
                                break;
                            }
                        }
                    }
                }

                mcu_count += 1;
                if restart_interval > 0 && (mcu_count as u16) == restart_interval {
                    mcu_count = 0;
                    for c in comps.iter_mut().take(n_comps) {
                        c.dc_pred = 0;
                    }
                    eob_run = 0;
                    br.align_to_byte();
                    br.buf = 0;
                    br.n = 0;
                }
            }
        }
    }

    Some(br.pos)
}

// ── IDCT (integer, fast) — same as before ───────────────────────────────

unsafe fn write_block(plane: *mut u8, plane_w: usize, px: usize, py: usize, block: &[i32; 64]) {
    let mut work = [0i32; 64];
    for r in 0..8 {
        let row_off = r * 8;
        idct_row(&block[row_off..row_off + 8], &mut work[row_off..row_off + 8]);
    }
    let mut col = [0i32; 8];
    let mut out = [0i32; 8];
    for c in 0..8 {
        for r in 0..8 {
            col[r] = work[r * 8 + c];
        }
        idct_col(&col, &mut out);
        for r in 0..8 {
            let v = (out[r] + 128).clamp(0, 255) as u8;
            *plane.add((py + r) * plane_w + (px + c)) = v;
        }
    }
}

fn idct_row(in_: &[i32], out: &mut [i32]) {
    const C1: i32 = 5681;
    const C2: i32 = 5352;
    const C3: i32 = 4816;
    const C4: i32 = 4096;
    const C5: i32 = 3218;
    const C6: i32 = 2217;
    const C7: i32 = 1130;

    let s0 = in_[0];
    let s1 = in_[1];
    let s2 = in_[2];
    let s3 = in_[3];
    let s4 = in_[4];
    let s5 = in_[5];
    let s6 = in_[6];
    let s7 = in_[7];

    let z11 = C4 * (s0 + s4);
    let z12 = C4 * (s0 - s4);
    let z13 = s2 * C2 + s6 * C6;
    let z14 = s2 * C6 - s6 * C2;
    let t0 = z11 + z13;
    let t3 = z11 - z13;
    let t1 = z12 + z14;
    let t2 = z12 - z14;
    let p0 = s1 * C1 + s3 * C3 + s5 * C5 + s7 * C7;
    let p1 = s1 * C3 - s3 * C7 - s5 * C1 - s7 * C5;
    let p2 = s1 * C5 - s3 * C1 + s5 * C7 + s7 * C3;
    let p3 = s1 * C7 - s3 * C5 + s5 * C3 - s7 * C1;

    out[0] = (t0 + p0) >> 13;
    out[1] = (t1 + p1) >> 13;
    out[2] = (t2 + p2) >> 13;
    out[3] = (t3 + p3) >> 13;
    out[4] = (t3 - p3) >> 13;
    out[5] = (t2 - p2) >> 13;
    out[6] = (t1 - p1) >> 13;
    out[7] = (t0 - p0) >> 13;
}

fn idct_col(in_: &[i32], out: &mut [i32]) {
    idct_row(in_, out);
}

// ── Render: upsample + YCbCr→RGB + scale → s.pending ────────────────────

unsafe fn render_jpeg(
    s: &mut ImageState,
    planes: &[*mut u8],
    n_comps: usize,
    plane_w: usize,
    _plane_h: usize,
    src_w: usize,
    src_h: usize,
    h_max: usize,
    v_max: usize,
    comps: &[Component],
) -> bool {
    let dst_w = s.dst_w as usize;
    let dst_h = s.dst_h as usize;
    if !ensure_pending(s, dst_w, dst_h) {
        return false;
    }

    let xmap_bytes = dst_w * core::mem::size_of::<u32>();
    let xmap_raw = ((*s.syscalls).heap_alloc)(xmap_bytes as u32) as *mut u32;
    if xmap_raw.is_null() {
        log(s, b"[img] jpeg: xmap alloc fail");
        return false;
    }
    let xmap = core::slice::from_raw_parts_mut(xmap_raw, dst_w);
    for dx in 0..dst_w {
        xmap[dx] = (((dx as u32) * 2 + 1) * src_w as u32) / (dst_w as u32 * 2);
    }

    let mut h_ratio = [1usize; MAX_COMPONENTS];
    let mut v_ratio = [1usize; MAX_COMPONENTS];
    for i in 0..n_comps {
        h_ratio[i] = (comps[i].h_samp as usize).max(1);
        v_ratio[i] = (comps[i].v_samp as usize).max(1);
    }

    for dy in 0..dst_h {
        let sy_luma = ((((dy as u32) * 2 + 1) * src_h as u32) / (dst_h as u32 * 2)) as usize;
        let dst_row_off = dy * dst_w * 2;
        for dx in 0..dst_w {
            let sx_luma = xmap[dx] as usize;
            if n_comps == 1 {
                let v = *planes[0].add(sy_luma * plane_w + sx_luma);
                store_rgb565(s.pending, dst_row_off + dx * 2, v, v, v);
            } else {
                let y = *planes[0].add(sy_luma * plane_w + sx_luma) as i32;
                let cb_x = sx_luma * h_ratio[1] / h_max;
                let cb_y = sy_luma * v_ratio[1] / v_max;
                let cr_x = sx_luma * h_ratio[2] / h_max;
                let cr_y = sy_luma * v_ratio[2] / v_max;
                let cb = *planes[1].add(cb_y * plane_w + cb_x) as i32;
                let cr = *planes[2].add(cr_y * plane_w + cr_x) as i32;
                let (r, g, b) = ycbcr_to_rgb(y, cb, cr);
                store_rgb565(s.pending, dst_row_off + dx * 2, r, g, b);
            }
        }
    }

    ((*s.syscalls).heap_free)(xmap_raw as *mut u8);
    true
}

fn ycbcr_to_rgb(y: i32, cb: i32, cr: i32) -> (u8, u8, u8) {
    let cb = cb - 128;
    let cr = cr - 128;
    let r = y + ((359 * cr) >> 8);
    let g = y - ((88 * cb + 183 * cr) >> 8);
    let b = y + ((454 * cb) >> 8);
    (r.clamp(0, 255) as u8, g.clamp(0, 255) as u8, b.clamp(0, 255) as u8)
}
