// QUIC stream multiplexing skeleton (RFC 9000 §2 + §3 + §19.8).
//
// Stream IDs encode direction + initiator in their two low bits:
//   0x00  client-initiated bidirectional
//   0x01  server-initiated bidirectional
//   0x02  client-initiated unidirectional
//   0x03  server-initiated unidirectional
//
// Each stream has a send half and a receive half (unidirectional
// streams omit one of the two). Each half tracks: a current offset,
// a peer-imposed window (`MAX_STREAM_DATA`), and a final-size hint
// (set on receipt of FIN or RESET_STREAM).
//
// Mirrors the h2 server's `StreamSlot` shape so the HTTP/3
// dispatcher reuses the slot count, emission cursor, and per-slot
// rendering state on a QUIC transport.

pub const MAX_STREAMS: usize = 4;
pub const STREAM_RECV_BUF: usize = 4096;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StreamSendState {
    Ready,      // No data sent.
    Send,       // Data flight in progress.
    DataSent,   // FIN sent, awaiting ACK.
    DataRecvd,  // FIN ACKed.
    ResetSent,
    ResetRecvd,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StreamRecvState {
    Recv,
    SizeKnown,   // Final size known (peer FIN seen).
    DataRecvd,   // All data received.
    DataRead,    // Application drained the stream.
    ResetRecvd,
    ResetRead,
}

pub struct StreamSlot {
    pub stream_id: u64,
    pub send_state: StreamSendState,
    pub recv_state: StreamRecvState,
    /// Bytes acked + bytes locally produced (offset in send direction).
    pub send_offset: u64,
    /// Peer-imposed window: highest offset we may write through.
    pub send_max_data: u64,
    /// Highest offset we've consumed from peer (recv direction).
    pub recv_offset: u64,
    /// Window we've granted the peer.
    pub recv_max_data: u64,
    pub recv_buf: [u8; STREAM_RECV_BUF],
    pub recv_buf_len: usize,
    pub fin_seen: bool,
    pub fin_sent: bool,
    pub allocated: bool,
}

impl StreamSlot {
    pub const fn empty() -> Self {
        Self {
            stream_id: 0,
            send_state: StreamSendState::Ready,
            recv_state: StreamRecvState::Recv,
            send_offset: 0,
            send_max_data: 65535, // Default initial flow-control window.
            recv_offset: 0,
            recv_max_data: 65535,
            recv_buf: [0; STREAM_RECV_BUF],
            recv_buf_len: 0,
            fin_seen: false,
            fin_sent: false,
            allocated: false,
        }
    }
}

pub fn is_client_initiated(stream_id: u64) -> bool {
    stream_id & 0x01 == 0
}

pub fn is_unidirectional(stream_id: u64) -> bool {
    stream_id & 0x02 != 0
}
