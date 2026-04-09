// Self-describing parameter macro for PIC modules.
//
// Generates from a single definition:
//   - dispatch_param(): TLV tag dispatcher (match on tag → apply closure)
//   - set_defaults(): applies default values in declaration order
//   - PARAM_SCHEMA: serialized schema bytes for .fmod embedding
//
// The config tool reads PARAM_SCHEMA from the .fmod to learn param names,
// types, defaults, and enum mappings — no module-specific code needed.
//
// Usage:
//
//   define_params! {
//       MyState;
//
//       1, sample_rate, u32, 8000
//           => |s, d, len| { s.sample_rate = p_u32(d, len, 0, 8000); };
//
//       2, waveform, u8, 1, enum { sine=0, saw=1 }
//           => |s, d, len| { s.waveform = p_u8(d, len, 0, 1); };
//   }
//
// Params MUST be ordered so that dependencies come first (e.g., sample_rate
// before envelope rates that depend on it), because set_defaults applies
// them in declaration order.

/// Maximum schema buffer size. Trailing zeros are trimmed by the packer.
pub const SCHEMA_MAX: usize = 2048;

/// Schema binary magic: "SP" (Schema Params)
pub const SCHEMA_MAGIC: [u8; 2] = [0x53, 0x50];

/// Schema version
pub const SCHEMA_VERSION: u8 = 1;

/// TLV magic byte
pub const TLV_MAGIC: u8 = 0xFE;

/// TLV version byte
pub const TLV_VERSION: u8 = 0x01;

/// TLV end marker tag
pub const TLV_END: u8 = 0xFF;

// Type IDs used in the schema binary format.
// Must match the config tool's ParamType enum.
pub const PTYPE_U8: u8 = 0;
pub const PTYPE_U16: u8 = 1;
pub const PTYPE_U32: u8 = 2;
pub const PTYPE_STR: u8 = 3;
pub const PTYPE_U16_ARRAY: u8 = 4;
pub const PTYPE_BLOB: u8 = 5;

#[macro_export]
macro_rules! define_params {
    (
        $state_type:ty;
        $(
            $tag:literal, $name:ident, $ptype:ident, $default:expr
            $(, enum { $($ename:tt = $eval:literal),+ $(,)? })?
            => |$s:ident, $d:ident, $len:ident| $apply:block
        );* $(;)?
    ) => {
        // ================================================================
        // Dispatch: match on TLV tag, execute apply closure
        // ================================================================
        #[inline(always)]
        pub unsafe fn dispatch_param(
            s: &mut $state_type,
            tag: u8,
            d: *const u8,
            len: usize,
        ) {
            match tag {
                $(
                    $tag => {
                        let $s = s;
                        let $d = d;
                        let $len = len;
                        $apply
                    }
                )*
                _ => {}
            }
        }

        // ================================================================
        // Defaults: apply each default in declaration order via dispatch
        // ================================================================
        pub unsafe fn set_defaults(s: &mut $state_type) {
            $(
                {
                    let val = ($default as u32).to_le_bytes();
                    dispatch_param(
                        s,
                        $tag,
                        val.as_ptr(),
                        define_params!(@type_size $ptype),
                    );
                }
            )*
        }

        // ================================================================
        // Generic TLV parser: set defaults then dispatch each entry
        // ================================================================
        pub unsafe fn parse_tlv(s: &mut $state_type, p: *const u8, total_len: usize) {
            set_defaults(s);
            if total_len < 4 { return; }
            let payload_len = u16::from_le_bytes([*p.add(2), *p.add(3)]) as usize;
            let end = if 4 + payload_len < total_len { 4 + payload_len } else { total_len };
            let mut off = 4usize;
            while off + 2 <= end {
                let tag = *p.add(off);
                let elen = *p.add(off + 1) as usize;
                off += 2;
                if tag == 0xFF { break; }
                if off + elen <= total_len {
                    dispatch_param(s, tag, p.add(off), elen);
                }
                off += elen;
            }
        }

        // ================================================================
        // Schema bytes: serialized param metadata for .fmod embedding
        // ================================================================
        #[link_section = ".param_schema"]
        #[used]
        pub static PARAM_SCHEMA: [u8; SCHEMA_MAX] = {
            let mut buf = [0u8; SCHEMA_MAX];
            // Header
            buf[0] = 0x53; // 'S'
            buf[1] = 0x50; // 'P'
            buf[2] = 1;    // version
            // buf[3] = count (filled at end)
            let mut pos: usize = 4;
            let mut count: u8 = 0;

            $(
                // Tag
                buf[pos] = $tag;
                pos += 1;

                // Type
                buf[pos] = define_params!(@type_id $ptype);
                pos += 1;

                // Default (4 bytes LE, zero-extended)
                let db = ($default as u32).to_le_bytes();
                buf[pos] = db[0]; buf[pos+1] = db[1];
                buf[pos+2] = db[2]; buf[pos+3] = db[3];
                pos += 4;

                // Name
                let nb = stringify!($name).as_bytes();
                buf[pos] = nb.len() as u8;
                pos += 1;
                {
                    let mut _ni: usize = 0;
                    while _ni < nb.len() {
                        buf[pos] = nb[_ni];
                        pos += 1;
                        _ni += 1;
                    }
                }

                // Enums
                define_params!(@schema_enums buf, pos $(, $($ename, $eval),+)?);

                count += 1;
            )*

            buf[3] = count;
            buf
        };
    };

    // ====================================================================
    // Helper: type ID for schema binary
    // ====================================================================
    (@type_id u8) => { 0u8 };
    (@type_id u16) => { 1u8 };
    (@type_id u32) => { 2u8 };
    (@type_id str) => { 3u8 };
    (@type_id u16_array) => { 4u8 };
    (@type_id blob) => { 5u8 };

    // ====================================================================
    // Helper: type size for set_defaults buffer (0 = skip for var-length)
    // ====================================================================
    (@type_size u8) => { 1usize };
    (@type_size u16) => { 2usize };
    (@type_size u32) => { 4usize };
    (@type_size str) => { 0usize };
    (@type_size u16_array) => { 0usize };
    (@type_size blob) => { 0usize };

    // ====================================================================
    // Helper: serialize enum entries to schema buffer (no enums)
    // ====================================================================
    (@schema_enums $buf:ident, $pos:ident) => {
        $buf[$pos] = 0;
        $pos += 1;
    };

    // ====================================================================
    // Helper: serialize enum entries to schema buffer (with enums)
    // ====================================================================
    (@schema_enums $buf:ident, $pos:ident, $($ename:tt, $eval:literal),+) => {
        let _ecount_pos = $pos;
        $buf[$pos] = 0; // placeholder
        $pos += 1;
        let mut _ec: u8 = 0;
        $(
            // enum value
            $buf[$pos] = $eval;
            $pos += 1;
            // enum name
            let _eb = stringify!($ename).as_bytes();
            $buf[$pos] = _eb.len() as u8;
            $pos += 1;
            {
                let mut _ei: usize = 0;
                while _ei < _eb.len() {
                    $buf[$pos] = _eb[_ei];
                    $pos += 1;
                    _ei += 1;
                }
            }
            _ec += 1;
        )+
        $buf[_ecount_pos] = _ec;
    };
}
