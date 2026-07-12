# codec Module

Unified essence decoder. Dispatches at runtime between audio-essence
sub-codecs (`wav_codec`, `mp3_codec`, `aac_codec`), image-essence
(`image_codec`), and video-essence (`mkv_h264` — Matroska container +
H.264 Constrained Baseline) by sniffing the encoded payload's
container/magic.

## Surface contract

The output ports follow the canonical AV surface family:

- `audio` — `AudioSample` (decoded sample-domain audio)
- `pixels` — `VideoRaster` (decoded pixel-domain frames)

The input port is `OctetStream` because format detection happens inside
the module; per-essence wrapper splits are an implementation detail of
the runtime dispatcher in `mod.rs`. A graph that only needs one output
side simply leaves the other unwired.

## Files

- `manifest.toml`
- `mod.rs` — entry, format sniff, sub-codec dispatch
- `aac_codec.rs` — AudioSample producer (AAC)
- `mp3_codec.rs` — AudioSample producer (MP3)
- `wav_codec.rs` — AudioSample producer (WAV / PCM)
- `image_codec.rs` — VideoRaster producer (BMP / GIF / PNG / JPEG)
- `mkv_h264.rs` — VideoRaster producer (MKV/H.264 video); glues the
  demuxer to the decoder and owns the RGB565 emit path
- `mkv_demux.rs` — clean-room Matroska/EBML incremental demuxer
- `h264/` — H.264 Constrained-Baseline decoder, mechanical Rust port
  of h264bsd (AOSP/Hantro, Apache-2.0). Bit-exact against ffmpeg on
  the verification corpus; see `.context/h264_mkv_codec_plan.md`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "encoded"
direction = "input"
content_type = "OctetStream"
required = true

[[ports]]
name = "audio"
direction = "output"
content_type = "AudioSample"

[[ports]]
name = "pixels"
direction = "output"
content_type = "VideoRaster"
```

## Parameters

- No TLV parameter tags detected in module source.

## Porting / validating a new sub-codec

When extending this module with a new essence decoder (or rewriting an
existing one — `mp3_codec.rs` was rewritten as an f32 port of
`lieff/minimp3` in May 2026), follow the workflow in
[`docs/guides/codec_porting.md`](../../../docs/guides/codec_porting.md).
The short version:

1. Get a byte-exact upstream reference (e.g. `minimp3` for MP3,
   `faad2` for AAC) building locally with intermediate-spectrum dumps.
2. Build a standalone Rust replica of this module's DSP under `/tmp/`
   that drives `decode_frame()` from a `std` `main()` — same code,
   no Fluxor runtime.
3. Diff per-layer probes (post-huffman, post-stereo, post-IMDCT,
   overlap state) against the C reference until correlation = 1.0000.
4. Only then run the WS-streaming harness; bring up the end-to-end
   pipeline against `ffmpeg` reference PCM.

The guide also documents the `SEND_BUF_SIZE` / `ws_stream` cap / codec
output `buffer_size` tunings the harness expects.

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-05-11
