// VideoCore property-mailbox MESSAGE format, separated from the MMIO that
// carries it.
//
// The BCM2712 keeps customer OTP behind the VideoCore property channel, and
// reading it is the last unimplemented piece of B1. The read divides into
// two very different halves:
//
//   - **The message.** Build a property buffer, name a tag, size a value
//     region, and read a response code back. This is pure data
//     manipulation, it is where the mistakes actually are — a wrong tag, a
//     length in words where the interface wants bytes, a response code
//     nobody checked — and it is fully testable on a host.
//   - **The transport.** Write a physical address into a register and poll
//     another until the firmware answers. Perhaps a dozen lines, and they
//     run nowhere but on a board.
//
// This file is the first half, so the untestable surface is the second half
// alone. That is the same split `seal_provenance.rs` already makes between
// "did the read succeed" and "may this key be believed".
//
// **Nothing here talks to hardware, and nothing here decides anything about
// a key.** It builds a buffer and reads one back.

/// Property tag: read customer OTP rows.
///
/// From the documented property interface. `GET_` rather than `SET_`
/// deliberately: provisioning is an irreversible, audited act and has no
/// business in a boot path or in this file.
pub const TAG_GET_CUSTOMER_OTP: u32 = 0x0003_0021;

/// The property buffer's request code — "process this request".
pub const REQUEST_PROCESS: u32 = 0x0000_0000;
/// Response code for a request the firmware processed successfully.
pub const RESPONSE_SUCCESS: u32 = 0x8000_0000;
/// Response code for a request the firmware rejected.
pub const RESPONSE_ERROR: u32 = 0x8000_0001;
/// A tag's response code carries this bit plus the value length in bytes.
pub const TAG_RESPONSE_BIT: u32 = 0x8000_0000;
/// Terminates the tag list.
pub const END_TAG: u32 = 0x0000_0000;

/// Index of the first customer-OTP row AS THE PROPERTY TAG COUNTS THEM.
///
/// The tag addresses rows RELATIVE to the customer block, starting at 0 —
/// the reference usage is `vcmailbox 0x00030021 8 8 0 8` to read all eight.
/// The block's ABSOLUTE OTP rows are 36-43, and the first draft of this
/// constant said 36, which would have asked the firmware for rows 36-43 OF
/// THE CUSTOMER BLOCK — rows that do not exist. The kind of off-by-a-frame
/// mistake this file exists to keep out of the MMIO layer.
pub const CUSTOMER_OTP_FIRST_ROW: u32 = 0;
/// How many rows of customer OTP there are.
pub const CUSTOMER_OTP_ROWS: u32 = 8;

/// How many BYTES of customer OTP exist: 8 rows of 32 bits.
pub const CUSTOMER_OTP_BYTES: usize = (CUSTOMER_OTP_ROWS as usize) * 4;

/// **The customer OTP is smaller than the seal-key blob wants.**
///
/// `provenance_from_hardware_key` requires `SEAL_KEY_MAGIC` (4 bytes) plus
/// at least 32 bytes of key — 36 bytes. Customer OTP is 32. The two do not
/// fit, and anyone implementing the transport half will hit that before
/// anything else.
///
/// It is stated here, as a constant a test asserts, rather than left for a
/// person with a board to discover: the resolution is a LAYOUT DECISION —
/// a shorter key, a magic that shares a row with key material, or a
/// different OTP region — and a layout decision made hastily at the point of
/// discovery is how a device key ends up 28 bytes because that was what was
/// left over.
/// **The BCM2712 device-seal-key layout — the answered question.**
///
/// The eight customer rows, as bytes (each row contributing
/// `row.to_le_bytes()`, ARM-native — provisioning writes
/// `row0 = u32::from_le_bytes(*b"KSK1")` = `0x314B_534B`):
///
/// ```text
///   row 0        SEAL_KEY_MAGIC ("KSK1")
///   rows 1..=7   28 bytes of provisioned entropy (224 bits)
/// ```
///
/// The magic stays in-band because it is the mis-addressed-read guard and
/// has no other home; what is left is the rule's [`MIN_DEVICE_KEY_BYTES`],
/// which carries its own rationale. The assert below pins that decision:
/// magic plus minimum key is exactly the customer block, so a change to any
/// of the three numbers stops the build at the moment this layout note
/// needs rewriting — rather than being settled by accident at 2am with a
/// board on the desk.
const _: () = assert!(
    SEAL_KEY_MAGIC.len() + MIN_DEVICE_KEY_BYTES == CUSTOMER_OTP_BYTES,
    "the device-seal-key layout no longer tiles customer OTP exactly — \
     rewrite the layout note above and the provisioning docs together"
);

/// Words a `GET_CUSTOMER_OTP` property buffer needs for `rows` rows.
///
/// `[size][request][tag][value_size][value_code][start][count][rows…][end]`
#[must_use]
pub const fn get_customer_otp_words(rows: u32) -> usize {
    8 + rows as usize
}

/// Build a `GET_CUSTOMER_OTP` property buffer into `buf`.
///
/// Returns the number of WORDS written. `None` when `buf` is too small or
/// `rows` is zero — a request for no rows is not a smaller request, it is a
/// request that cannot be answered, and the firmware's reply to one is not
/// something to find out on a board.
pub fn build_get_customer_otp(buf: &mut [u32], first_row: u32, rows: u32) -> Option<usize> {
    if rows == 0 {
        return None;
    }
    let words = get_customer_otp_words(rows);
    if buf.len() < words {
        return None;
    }
    // The value region holds the two request words AND the rows the reply
    // will land in — the same buffer serves both directions, which is the
    // detail most easily got wrong: sizing it to the request alone leaves
    // the firmware nowhere to put the answer.
    let value_bytes = (2 + rows as usize) * 4;
    buf[0] = (words * 4) as u32;
    buf[1] = REQUEST_PROCESS;
    buf[2] = TAG_GET_CUSTOMER_OTP;
    buf[3] = value_bytes as u32;
    // On a request this is the length of the data being SENT, in bytes:
    // the two words naming which rows are wanted.
    buf[4] = 8;
    buf[5] = first_row;
    buf[6] = rows;
    for slot in buf.iter_mut().take(words - 1).skip(7) {
        *slot = 0;
    }
    buf[words - 1] = END_TAG;
    Some(words)
}

/// Read the rows back out of a processed buffer.
///
/// Every check here is one whose absence yields plausible-looking garbage
/// rather than a failure:
///
/// - the buffer-level response code must be SUCCESS, not merely "not zero";
/// - the tag's response code must carry [`TAG_RESPONSE_BIT`], which is what
///   distinguishes a reply from a request the firmware never touched — an
///   untouched buffer still holds the row numbers that were asked for and
///   zeroes after them, which reads exactly like unprogrammed OTP;
/// - the length the tag reports must match the rows requested, so a short
///   answer is refused instead of being padded with the zeroes already
///   sitting in the buffer.
pub fn parse_get_customer_otp(buf: &[u32], rows: u32) -> Option<&[u32]> {
    if rows == 0 {
        return None;
    }
    let words = get_customer_otp_words(rows);
    if buf.len() < words {
        return None;
    }
    if buf[1] != RESPONSE_SUCCESS {
        return None;
    }
    if buf[2] != TAG_GET_CUSTOMER_OTP {
        return None;
    }
    let code = buf[4];
    if code & TAG_RESPONSE_BIT == 0 {
        return None;
    }
    let value_bytes = (code & !TAG_RESPONSE_BIT) as usize;
    if value_bytes != (2 + rows as usize) * 4 {
        return None;
    }
    if buf[6] != rows {
        return None;
    }
    Some(&buf[7..7 + rows as usize])
}
