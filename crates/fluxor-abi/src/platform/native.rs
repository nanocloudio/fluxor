//! Native modules' name hashes, params tags and port bindings, generated
//! by `fluxor abi-regen` from `modules/platform/<platform>/*/manifest.toml`.
//! Do not edit: change the manifest and regenerate.

pub mod linux {
    pub mod cli_in {
        pub const NAME_HASH: u32 = 0x39eb09ad;
        pub const PORT_ARGS_OUT: (u8, u8) = (1, 0);
        pub const PORT_STDIN_OUT: (u8, u8) = (1, 1);
    }
    pub mod cli_out {
        pub const NAME_HASH: u32 = 0xd0d89096;
        pub const PORT_BYTES_IN: (u8, u8) = (0, 0);
        pub const PORT_ERR_IN: (u8, u8) = (0, 1);
        pub const PORT_EXIT_IN: (u8, u8) = (0, 2);
    }
    pub mod host_asset_index {
        pub const NAME_HASH: u32 = 0xfb4428b3;
        pub const TAG_PATHS: u8 = 10;
        pub const PORT_STREAM: (u8, u8) = (1, 0);
    }
    pub mod host_asset_source {
        pub const NAME_HASH: u32 = 0x504eeef0;
        pub const TAG_PATH: u8 = 10;
        pub const PORT_STREAM: (u8, u8) = (1, 0);
    }
    pub mod host_image_codec {
        pub const NAME_HASH: u32 = 0xf09d5d98;
        pub const TAG_WIDTH: u8 = 10;
        pub const TAG_HEIGHT: u8 = 11;
        pub const TAG_SCALE_MODE: u8 = 12;
        pub const TAG_MAX_BYTES: u8 = 13;
        pub const PORT_ENCODED: (u8, u8) = (0, 0);
        pub const PORT_PIXELS: (u8, u8) = (1, 0);
    }
    pub mod hsm_key_vault {
        pub const NAME_HASH: u32 = 0x17cd1360;
    }
    pub mod linux_alsa_midi {
        pub const NAME_HASH: u32 = 0xc38e5605;
        pub const TAG_MODE: u8 = 10;
        pub const TAG_PORT_FILTER: u8 = 11;
        pub const TAG_CLIENT_NAME: u8 = 12;
        pub const PORT_EVENTS_OUT: (u8, u8) = (1, 0);
        pub const PORT_EVENTS_IN: (u8, u8) = (0, 0);
    }
    pub mod linux_audio {
        pub const NAME_HASH: u32 = 0xf62ea500;
        pub const TAG_MODE: u8 = 10;
        pub const TAG_PATH: u8 = 11;
        pub const TAG_SAMPLE_RATE: u8 = 12;
        pub const TAG_CHANNELS: u8 = 13;
        pub const PORT_AUDIO: (u8, u8) = (0, 0);
    }
    pub mod linux_display {
        pub const NAME_HASH: u32 = 0xee7453f4;
        pub const TAG_MODE: u8 = 10;
        pub const TAG_PATH: u8 = 11;
        pub const TAG_WIDTH: u8 = 12;
        pub const TAG_HEIGHT: u8 = 13;
        pub const TAG_SCALE: u8 = 14;
        pub const TAG_HEADER: u8 = 15;
        pub const PORT_PIXELS: (u8, u8) = (0, 0);
    }
    pub mod linux_eth {
        pub const NAME_HASH: u32 = 0xf682a08d;
        pub const TAG_IFNAME: u8 = 10;
        pub const TAG_MAC: u8 = 11;
        pub const TAG_MODE: u8 = 12;
        pub const PORT_FRAMES_RX: (u8, u8) = (1, 0);
        pub const PORT_FRAMES_TX: (u8, u8) = (0, 0);
    }
    pub mod linux_gpu {
        pub const NAME_HASH: u32 = 0x0c4964c4;
        pub const TAG_RESIDENT_MB: u8 = 10;
        pub const TAG_STAGING_KB: u8 = 11;
        pub const PORT_COMMANDS: (u8, u8) = (0, 0);
        pub const PORT_OUTCOMES: (u8, u8) = (1, 0);
    }
    pub mod linux_net {
        pub const NAME_HASH: u32 = 0xfbcc7dc9;
        pub const TAG_MAX_CONNS: u8 = 10;
        pub const TAG_WRITE_BUF_KIB: u8 = 11;
        pub const TAG_LISTEN_BACKLOG: u8 = 12;
        pub const PORT_NET_OUT: (u8, u8) = (1, 0);
        pub const PORT_NET_IN: (u8, u8) = (0, 0);
    }
    pub mod linux_pointer {
        pub const NAME_HASH: u32 = 0xeea312ef;
        pub const TAG_PATH: u8 = 10;
        pub const TAG_WIDTH: u8 = 11;
        pub const TAG_HEIGHT: u8 = 12;
        pub const TAG_X_MAX: u8 = 13;
        pub const TAG_Y_MAX: u8 = 14;
        pub const PORT_EVENTS: (u8, u8) = (1, 0);
    }
    pub mod linux_surface_traits {
        pub const NAME_HASH: u32 = 0x9772c0f3;
        pub const TAG_WIDTH: u8 = 10;
        pub const TAG_HEIGHT: u8 = 11;
        pub const PORT_EVENTS: (u8, u8) = (1, 0);
    }
    pub mod linux_surface_traits_probe {
        pub const NAME_HASH: u32 = 0xfadf1ac6;
        pub const PORT_EVENTS: (u8, u8) = (0, 0);
    }
}
pub mod wasm {
    pub mod host_browser_fetch {
        pub const NAME_HASH: u32 = 0x4e8f8303;
        pub const TAG_URL: u8 = 10;
        pub const PORT_BYTES: (u8, u8) = (1, 0);
    }
    pub mod wasm_browser_action {
        pub const NAME_HASH: u32 = 0x288b3015;
        pub const PORT_COMMANDS: (u8, u8) = (1, 0);
    }
    pub mod wasm_browser_audio {
        pub const NAME_HASH: u32 = 0xbb565f2b;
        pub const TAG_SAMPLE_RATE: u8 = 10;
        pub const TAG_CHANNELS: u8 = 11;
        pub const TAG_LEAD_MS: u8 = 12;
        pub const PORT_AUDIO: (u8, u8) = (0, 0);
    }
    pub mod wasm_browser_button {
        pub const NAME_HASH: u32 = 0x7c00007f;
        pub const PORT_RAW: (u8, u8) = (1, 0);
    }
    pub mod wasm_browser_camera {
        pub const NAME_HASH: u32 = 0x66106060;
        pub const PORT_FRAMES: (u8, u8) = (1, 0);
    }
    pub mod wasm_browser_canvas {
        pub const NAME_HASH: u32 = 0xbc02dadb;
        pub const TAG_WIDTH: u8 = 10;
        pub const TAG_HEIGHT: u8 = 11;
        pub const TAG_HEADER: u8 = 12;
        pub const PORT_PIXELS: (u8, u8) = (0, 0);
    }
    pub mod wasm_browser_compute {
        pub const NAME_HASH: u32 = 0x32704f28;
        pub const PORT_COMMANDS: (u8, u8) = (0, 0);
        pub const PORT_OUTCOMES: (u8, u8) = (1, 0);
    }
    pub mod wasm_browser_display_capture {
        pub const NAME_HASH: u32 = 0xf1ef8a8a;
        pub const TAG_WIDTH: u8 = 10;
        pub const TAG_HEIGHT: u8 = 11;
        pub const TAG_HEADER: u8 = 12;
        pub const PORT_PIXELS: (u8, u8) = (1, 0);
    }
    pub mod wasm_browser_dom_input {
        pub const NAME_HASH: u32 = 0x05261f62;
        pub const PORT_EVENTS: (u8, u8) = (1, 0);
    }
    pub mod wasm_browser_gamepad {
        pub const NAME_HASH: u32 = 0x339e4daa;
        pub const PORT_EVENTS: (u8, u8) = (1, 0);
    }
    pub mod wasm_browser_gpu {
        pub const NAME_HASH: u32 = 0x79efd837;
        pub const TAG_WIDTH: u8 = 10;
        pub const TAG_HEIGHT: u8 = 11;
        pub const PORT_COMMANDS: (u8, u8) = (0, 0);
    }
    pub mod wasm_browser_http {
        pub const NAME_HASH: u32 = 0x65b0731f;
        pub const TAG_ORIGIN: u8 = 10;
        pub const PORT_REQUEST_IN: (u8, u8) = (0, 0);
        pub const PORT_RESPONSE_OUT: (u8, u8) = (1, 0);
    }
    pub mod wasm_browser_image_codec {
        pub const NAME_HASH: u32 = 0x0aff8341;
        pub const TAG_WIDTH: u8 = 10;
        pub const TAG_HEIGHT: u8 = 11;
        pub const TAG_MAX_BYTES: u8 = 12;
        pub const PORT_ENCODED: (u8, u8) = (0, 0);
        pub const PORT_PIXELS: (u8, u8) = (1, 0);
    }
    pub mod wasm_browser_keyboard {
        pub const NAME_HASH: u32 = 0x9d66d64e;
        pub const PORT_EVENTS: (u8, u8) = (1, 0);
    }
    pub mod wasm_browser_midi_in {
        pub const NAME_HASH: u32 = 0x592a5858;
        pub const TAG_PORT_FILTER: u8 = 10;
        pub const TAG_SYSEX: u8 = 11;
        pub const PORT_EVENTS: (u8, u8) = (1, 0);
    }
    pub mod wasm_browser_midi_out {
        pub const NAME_HASH: u32 = 0x68f340dd;
        pub const TAG_PORT_FILTER: u8 = 10;
        pub const PORT_EVENTS: (u8, u8) = (0, 0);
    }
    pub mod wasm_browser_pointer {
        pub const NAME_HASH: u32 = 0xf7877a3c;
        pub const PORT_EVENTS: (u8, u8) = (1, 0);
    }
    pub mod wasm_browser_scan_out {
        pub const NAME_HASH: u32 = 0x3f027c3d;
        pub const PORT_RESULT: (u8, u8) = (0, 0);
    }
    pub mod wasm_browser_surface_traits {
        pub const NAME_HASH: u32 = 0xbdfa62d2;
        pub const PORT_EVENTS: (u8, u8) = (1, 0);
    }
    pub mod wasm_browser_surface_traits_probe {
        pub const NAME_HASH: u32 = 0xdb4c3473;
        pub const PORT_EVENTS: (u8, u8) = (0, 0);
    }
    pub mod wasm_browser_terminal {
        pub const NAME_HASH: u32 = 0x64482903;
    }
    pub mod wasm_browser_touch_gamepad_overlay {
        pub const NAME_HASH: u32 = 0x8db77f81;
        pub const PORT_EVENTS_IN: (u8, u8) = (0, 0);
        pub const PORT_EVENTS_OUT: (u8, u8) = (1, 0);
    }
    pub mod wasm_browser_video_codec {
        pub const NAME_HASH: u32 = 0x896689af;
        pub const TAG_WIDTH: u8 = 10;
        pub const TAG_HEIGHT: u8 = 11;
        pub const TAG_MAX_FRAME_BYTES: u8 = 12;
        pub const PORT_ENCODED: (u8, u8) = (0, 0);
    }
    pub mod wasm_browser_websocket {
        pub const NAME_HASH: u32 = 0xa29f5986;
        pub const TAG_URL: u8 = 10;
        pub const PORT_TX: (u8, u8) = (0, 0);
        pub const PORT_RX: (u8, u8) = (1, 0);
    }
    pub mod wasm_browser_ws {
        pub const NAME_HASH: u32 = 0xb1519961;
        pub const TAG_ORIGIN: u8 = 10;
        pub const PORT_OPEN_IN: (u8, u8) = (0, 0);
        pub const PORT_WS_IN: (u8, u8) = (0, 1);
        pub const PORT_WS_OUT: (u8, u8) = (1, 0);
        pub const PORT_EVENT_OUT: (u8, u8) = (1, 1);
    }
    pub mod wasm_browser_ws_source {
        pub const NAME_HASH: u32 = 0x776f8a27;
        pub const TAG_URL: u8 = 10;
        pub const PORT_BYTES: (u8, u8) = (1, 0);
    }
}
