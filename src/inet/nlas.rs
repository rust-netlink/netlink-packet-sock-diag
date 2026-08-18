// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{
    emit_u32, parse_string, parse_u32, parse_u8, DecodeError, DefaultNla,
    Emitable, ErrorContext, NlaBuffer, Parseable,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::constants::*;

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C, packed)]
pub struct LegacyMemInfoBuffer {
    receive_queue: u32,
    bottom_send_queue: u32,
    cache: u32,
    send_queue: u32,
}

/// In recent Linux kernels, this NLA is not used anymore to report
/// AF_INET and AF_INET6 sockets memory information. See [`MemInfo`]
/// instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyMemInfo {
    /// Amount of data in the receive queue.
    pub receive_queue: u32,
    /// Amount of data that is queued by TCP but not yet sent.
    pub bottom_send_queue: u32,
    /// Amount of memory scheduled for future use (TCP only).
    pub cache: u32,
    /// Amount of data in the send queue.
    pub send_queue: u32,
}

impl LegacyMemInfo {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            LegacyMemInfoBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<LegacyMemInfoBuffer>(),
                )
            })?;
        Ok(Self {
            receive_queue: raw.receive_queue,
            bottom_send_queue: raw.bottom_send_queue,
            cache: raw.cache,
            send_queue: raw.send_queue,
        })
    }
}

impl From<&LegacyMemInfo> for LegacyMemInfoBuffer {
    fn from(value: &LegacyMemInfo) -> Self {
        Self {
            receive_queue: value.receive_queue,
            bottom_send_queue: value.bottom_send_queue,
            cache: value.cache,
            send_queue: value.send_queue,
        }
    }
}

impl Emitable for LegacyMemInfo {
    fn buffer_len(&self) -> usize {
        size_of::<LegacyMemInfoBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = LegacyMemInfoBuffer::from(self);
        buffer.copy_from_slice(raw.as_bytes());
    }
}

// FIXME: the last 2 fields are not present on old linux kernels. We
// should support optional fields in the buffer parser.
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C, packed)]
pub struct MemInfoBuffer {
    receive_queue: u32,
    receive_queue_max: u32,
    bottom_send_queues: u32,
    send_queue_max: u32,
    cache: u32,
    send_queue: u32,
    options: u32,
    backlog_queue_length: u32,
    drops: u32,
}

/// Socket memory information. To understand this information, one
/// must understand how the memory allocated for the send and receive
/// queues of a socket is managed.
///
/// # Warning
///
/// This data structure is not well documented. The explanations given
/// here are the results of my personal research on this topic, but I
/// am by no mean an expert in Linux networking, so take this
/// documentation with a huge grain of salt. Please report any error
/// you may notice. Here are the references I used:
///
/// - [a short introduction to `sk_buff`, the struct used in the kernel to store
///   packets](https://wiki.linuxfoundation.org/networking/sk_buff)
/// - [vger.kernel.org has a lot of documentation about the low level network stack APIs](http://vger.kernel.org/~davem/skb_data.html)
/// - [thorough high level explanation of buffering in the network stack](https://www.coverfire.com/articles/queueing-in-the-linux-network-stack/)
/// - [understanding the backlog queue](http://veithen.io/2014/01/01/how-tcp-backlog-works-in-linux.html)
/// - [high level explanation of packet reception](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/performance_tuning_guide/s-network-packet-reception)
/// - [a StackExchange question about the different send queues used by a socket](https://unix.stackexchange.com/questions/551444/what-is-the-difference-between-sock-sk-wmem-alloc-and-sock-sk-wmem-queued)
/// - other useful resources: [here](https://www.cl.cam.ac.uk/~pes20/Netsem/linuxnet.pdf)
///   and [here](https://people.cs.clemson.edu/~westall/853/notes/skbuff.pdf)
/// - [explanation of the socket backlog queue](https://medium.com/@c0ngwang/the-design-of-lock-sock-in-linux-kernel-69c3406e504b)
///
/// # Linux networking in a nutshell
///
/// The network stack uses multiple queues, both for sending an
/// receiving data. Let's start with the simplest case: packet
/// receptions.
///
/// When data is received, it is first handled by the device driver
/// and put in the device driver queue. The kernel then move the
/// packet to the socket receive queue (also called _receive
/// buffer_). Finally, this application reads it (with `recv`, `read`
/// or `recvfrom`) and the packet is dequeued.
///
/// Sending packet it slightly more complicated and the exact workflow
/// may differ from one protocol to the other so we'll just give a
/// high level overview. When an application sends data, a packet is
/// created and stored in the socket send queue (also called _send
/// buffer_). It is then passed down to the QDisc (Queuing
/// Disciplines) queue. The QDisc facility enables quality of service:
/// if some data is more urgent to transmit than other, QDisc will
/// make sure it is sent in priority. Finally, the data is put on the
/// device driver queue to be sent out.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MemInfo {
    /// Memory currently allocated for the socket's receive
    /// queue. This attribute is known as `sk_rmem_alloc` in the
    /// kernel.
    pub receive_queue: u32,
    /// Maximum amount of memory that can be allocated for the
    /// socket's receive queue. This is set by `SO_RCVBUF`. This is
    /// _not_ the amount of memory currently allocated. This attribute
    /// is known as `sk_rcvbuf` in the kernel.
    pub receive_queue_max: u32,
    /// Memory currently allocated for the socket send queue. This
    /// attribute is known as `sk_wmem_queued` in the kernel. This
    /// does does not account for data that have been passed down the
    /// network stack (i.e. to the QDisc and device driver queues),
    /// which is reported by the `bottow_send_queue` (known as
    /// `sk_wmem_alloc` in the kernel).
    ///
    /// For a TCP socket, if the congestion window is small, the
    /// kernel will move the data fron the socket send queue to the
    /// QDisc queues more slowly. Thus, if the process sends of lot of
    /// data, the socket send queue (which memory is tracked by
    /// `sk_wmem_queued`) will grow while `sk_wmem_alloc` will remain
    /// small.
    pub send_queue: u32,
    /// Maximum amount of memory (in bytes) that can be allocated for
    /// this socket's send queue. This is set by `SO_SNDBUF`. This is
    /// _not_ the amount of memory currently allocated. This attribute
    /// is known as `sk_sndbuf` in the kernel.
    pub send_queue_max: u32,
    /// Memory used for packets that have been passed down the network
    /// stack, i.e. that are either in the QDisc or device driver
    /// queues. This attribute is known as `sk_wmem_alloc` in the
    /// kernel. See also [`send_queue`](#structfield.send_queue).
    pub bottom_send_queues: u32,
    /// The amount of memory already allocated for this socket but
    /// currently unused. When more memory is needed either for
    /// sending or for receiving data, it will be taken from this
    /// pool. This attribute is known as `sk_fwd_alloc` in the kernel.
    pub cache: u32,
    /// The amount of memory allocated for storing socket options, for
    /// instance the key for TCP MD5 signature. This attribute is
    /// known as `sk_optmem` in the kernel.
    pub options: u32,
    /// The length of the backlog queue. When the process is using the
    /// socket, the socket is locked so the kernel cannot enqueue new
    /// packets in the receive queue. To avoid blocking the bottom
    /// half of network stack waiting for the process to release the
    /// socket, the packets are enqueued in the backlog queue. Upon
    /// releasing the socket, those packets are processed and put in
    /// the regular receive queue.
    // FIXME: this should be an Option because it's not present on old
    // linux kernels.
    pub backlog_queue_length: u32,
    /// The amount of packets dropped. Depending on the kernel
    /// version, this field may not be present.
    // FIXME: this should be an Option because it's not present on old
    // linux kernels.
    pub drops: u32,
}

impl MemInfo {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            MemInfoBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<MemInfoBuffer>(),
                )
            })?;
        Ok(Self {
            receive_queue: raw.receive_queue,
            receive_queue_max: raw.receive_queue_max,
            bottom_send_queues: raw.bottom_send_queues,
            send_queue_max: raw.send_queue_max,
            cache: raw.cache,
            send_queue: raw.send_queue,
            options: raw.options,
            backlog_queue_length: raw.backlog_queue_length,
            drops: raw.drops,
        })
    }
}

impl From<&MemInfo> for MemInfoBuffer {
    fn from(value: &MemInfo) -> Self {
        Self {
            receive_queue: value.receive_queue,
            receive_queue_max: value.receive_queue_max,
            bottom_send_queues: value.bottom_send_queues,
            send_queue_max: value.send_queue_max,
            cache: value.cache,
            send_queue: value.send_queue,
            options: value.options,
            backlog_queue_length: value.backlog_queue_length,
            drops: value.drops,
        }
    }
}

impl Emitable for MemInfo {
    fn buffer_len(&self) -> usize {
        size_of::<MemInfoBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = MemInfoBuffer::from(self);
        buffer.copy_from_slice(raw.as_bytes());
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nla {
    /// The memory information of the socket. This attribute is
    /// similar to `Nla::MemInfo` but provides less information. On
    /// recent kernels, `Nla::MemInfo` is used instead.
    // ref: https://patchwork.ozlabs.org/patch/154816/
    LegacyMemInfo(LegacyMemInfo),
    /// the TCP information
    #[cfg(feature = "rich_nlas")]
    TcpInfo(TcpInfo),
    #[cfg(not(feature = "rich_nlas"))]
    TcpInfo(Vec<u8>),
    /// the congestion control algorithm used
    Congestion(String),
    /// the TOS of the socket.
    Tos(u8),
    /// the traffic class of the socket.
    Tc(u8),
    /// The memory information of the socket
    MemInfo(MemInfo),
    /// Shutown state: one of [`SHUT_RD`], [`SHUT_WR`] or [`SHUT_RDWR`]
    Shutdown(u8),
    /// The protocol
    Protocol(u8),
    /// Whether the socket is IPv6 only
    SkV6Only(bool),
    /// The mark of the socket.
    Mark(u32),
    /// The class ID of the socket.
    ClassId(u32),
    /// other attribute
    Other(DefaultNla),
}

impl netlink_packet_core::Nla for Nla {
    fn value_len(&self) -> usize {
        use self::Nla::*;
        match *self {
            LegacyMemInfo(_) => size_of::<LegacyMemInfoBuffer>(),
            #[cfg(feature = "rich_nlas")]
            TcpInfo(_) => size_of::<TcpInfoBuffer>(),
            #[cfg(not(feature = "rich_nlas"))]
            TcpInfo(ref bytes) => bytes.len(),
            // +1 because we need to append a null byte
            Congestion(ref s) => s.len() + 1,
            Tos(_) | Tc(_) | Shutdown(_) | Protocol(_) | SkV6Only(_) => 1,
            MemInfo(_) => size_of::<MemInfoBuffer>(),
            Mark(_) | ClassId(_) => 4,
            Other(ref attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        use self::Nla::*;
        match *self {
            LegacyMemInfo(_) => INET_DIAG_MEMINFO,
            TcpInfo(_) => INET_DIAG_INFO,
            Congestion(_) => INET_DIAG_CONG,
            Tos(_) => INET_DIAG_TOS,
            Tc(_) => INET_DIAG_TCLASS,
            MemInfo(_) => INET_DIAG_SKMEMINFO,
            Shutdown(_) => INET_DIAG_SHUTDOWN,
            Protocol(_) => INET_DIAG_PROTOCOL,
            SkV6Only(_) => INET_DIAG_SKV6ONLY,
            Mark(_) => INET_DIAG_MARK,
            ClassId(_) => INET_DIAG_CLASS_ID,
            Other(ref attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::Nla::*;
        match *self {
            LegacyMemInfo(ref value) => value.emit(buffer),
            #[cfg(feature = "rich_nlas")]
            TcpInfo(ref value) => value.emit(buffer),
            #[cfg(not(feature = "rich_nlas"))]
            TcpInfo(ref bytes) => {
                buffer[..bytes.len()].copy_from_slice(&bytes[..])
            }
            Congestion(ref s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            Tos(b) | Tc(b) | Shutdown(b) | Protocol(b) => buffer[0] = b,
            SkV6Only(value) => buffer[0] = value.into(),
            MemInfo(ref value) => value.emit(buffer),
            Mark(value) | ClassId(value) => emit_u32(buffer, value).unwrap(),
            Other(ref attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Nla {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            INET_DIAG_MEMINFO => {
                let err = "invalid INET_DIAG_MEMINFO value";
                Self::LegacyMemInfo(LegacyMemInfo::parse(payload).context(err)?)
            }
            #[cfg(feature = "rich_nlas")]
            INET_DIAG_INFO => {
                let err = "invalid INET_DIAG_INFO value";
                Self::TcpInfo(TcpInfo::parse(payload).context(err)?)
            }
            #[cfg(not(feature = "rich_nlas"))]
            INET_DIAG_INFO => Self::TcpInfo(payload.to_vec()),
            INET_DIAG_CONG => Self::Congestion(
                parse_string(payload)
                    .context("invalid INET_DIAG_CONG value")?,
            ),
            INET_DIAG_TOS => Self::Tos(
                parse_u8(payload).context("invalid INET_DIAG_TOS value")?,
            ),
            INET_DIAG_TCLASS => Self::Tc(
                parse_u8(payload).context("invalid INET_DIAG_TCLASS value")?,
            ),
            INET_DIAG_SKMEMINFO => {
                let err = "invalid INET_DIAG_SKMEMINFO value";
                Self::MemInfo(MemInfo::parse(payload).context(err)?)
            }
            INET_DIAG_SHUTDOWN => Self::Shutdown(
                parse_u8(payload)
                    .context("invalid INET_DIAG_SHUTDOWN value")?,
            ),
            INET_DIAG_PROTOCOL => Self::Protocol(
                parse_u8(payload)
                    .context("invalid INET_DIAG_PROTOCOL value")?,
            ),
            INET_DIAG_SKV6ONLY => Self::SkV6Only(
                parse_u8(payload)
                    .context("invalid INET_DIAG_SKV6ONLY value")?
                    != 0,
            ),
            INET_DIAG_MARK => Self::Mark(
                parse_u32(payload).context("invalid INET_DIAG_MARK value")?,
            ),
            INET_DIAG_CLASS_ID => Self::ClassId(
                parse_u32(payload)
                    .context("invalid INET_DIAG_CLASS_ID value")?,
            ),
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind}"))?,
            ),
        })
    }
}

#[cfg(feature = "rich_nlas")]
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C, packed)]
pub struct TcpInfoBuffer {
    // State of the TCP connection. This should be set to one of the
    // `TCP_*` constants: `TCP_ESTABLISHED`, `TCP_SYN_SENT`, etc. This
    // attribute is known as `tcpi_state` in the kernel.
    state: u8,
    // State of congestion avoidance. Sender's congestion state
    // indicating normal or abnormal situations in the last round of
    // packets sent. The state is driven by the ACK information and
    // timer events. This should be set to one of the `TCP_CA_*`
    // constants. This attribute is known as `tcpi_ca_state` in the
    // kernel.
    congestion_avoidance_state: u8,
    // Number of retranmissions on timeout invoked. This attribute is
    // known as `tcpi_retransmits` in the kernel.
    retransmits: u8,
    // Number of window or keep alive probes sent. This attribute is
    // known as `tcpi_probes`.
    probes: u8,
    // Number of times the retransmission backoff timer invoked
    backoff: u8,
    options: u8,
    wscale: u8,
    delivery_rate_app_limited: u8,

    rto: u32,
    ato: u32,
    snd_mss: u32,
    rcv_mss: u32,

    unacked: u32,
    sacked: u32,
    lost: u32,
    retrans: u32,
    fackets: u32,

    // Times
    last_data_sent: u32,
    last_ack_sent: u32,
    last_data_recv: u32,
    last_ack_recv: u32,

    // Metrics
    pmtu: u32,
    rcv_ssthresh: u32,
    rtt: u32,
    rttvar: u32,
    snd_ssthresh: u32,
    snd_cwnd: u32,
    advmss: u32,
    reordering: u32,

    rcv_rtt: u32,
    rcv_space: u32,

    total_retrans: u32,

    pacing_rate: u64,
    max_pacing_rate: u64,
    bytes_acked: u64,    // RFC4898 tcpEStatsAppHCThruOctetsAcked
    bytes_received: u64, // RFC4898 tcpEStatsAppHCThruOctetsReceived
    segs_out: u32,       // RFC4898 tcpEStatsPerfSegsOut
    segs_in: u32,        // RFC4898 tcpEStatsPerfSegsIn

    notsent_bytes: u32,
    min_rtt: u32,
    data_segs_in: u32,  // RFC4898 tcpEStatsDataSegsIn
    data_segs_out: u32, // RFC4898 tcpEStatsDataSegsOut

    delivery_rate: u64,

    busy_time: u64,      // Time (usec) busy sending data
    rwnd_limited: u64,   // Time (usec) limited by receive window
    sndbuf_limited: u64, // Time (usec) limited by send buffer

    delivered: u32,
    delivered_ce: u32,

    bytes_sent: u64,    // RFC4898 tcpEStatsPerfHCDataOctetsOut
    bytes_retrans: u64, // RFC4898 tcpEStatsPerfOctetsRetrans
    dsack_dups: u32,    // RFC4898 tcpEStatsStackDSACKDups
    reord_seen: u32,    // reordering events seen
    rcv_ooopack: u32,   // Out-of-order packets received
    snd_wnd: u32,       /* peer's advertised receive window after scaling
                         * (bytes) */
}

// https://unix.stackexchange.com/questions/542712/detailed-output-of-ss-command

#[cfg(feature = "rich_nlas")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpInfo {
    /// State of the TCP connection: one of `TCP_ESTABLISHED`,
    /// `TCP_SYN_SENT`, `TP_SYN_RECV`, `TCP_FIN_WAIT1`,
    /// `TCP_FIN_WAIT2` `TCP_TIME_WAIT`, `TCP_CLOSE`,
    /// `TCP_CLOSE_WAIT`, `TCP_LAST_ACK` `TCP_LISTEN`, `TCP_CLOSING`.
    pub state: u8,
    /// Congestion algorithm state: one of `TCP_CA_OPEN`,
    /// `TCP_CA_DISORDER`, `TCP_CA_CWR`, `TCP_CA_RECOVERY`,
    /// `TCP_CA_LOSS`
    pub ca_state: u8,
    /// Number of retransmits since the last ACK
    pub retransmits: u8,
    pub probes: u8,
    pub backoff: u8,
    pub options: u8,
    // First 4 bits are snd_wscale, last 4 bits rcv_wscale
    pub wscale: u8,
    /// A boolean indicating if the goodput was measured when the
    /// socket's throughput was limited by the sending application.
    /// tcpi_delivery_rate_app_limited:1, tcpi_fastopen_client_fail:2
    pub delivery_rate_app_limited: u8,

    /// Value of the RTO (Retransmission TimeOut) timer. This value is
    /// calculated using the RTT.
    pub rto: u32,
    /// Value of the ATO (ACK TimeOut) timer.
    pub ato: u32,
    /// MSS (Maximum Segment Size). Not shure how it differs from
    /// `advmss`.
    pub snd_mss: u32,
    /// MSS (Maximum Segment Size) advertised by peer
    pub rcv_mss: u32,

    /// Number of segments that have not been ACKnowledged yet, ie the
    /// number of in-flight segments.
    pub unacked: u32,
    /// Number of segments that have been SACKed
    pub sacked: u32,
    /// Number of segments that have been lost
    pub lost: u32,
    /// Number of segments that are currently being retransmitted
    pub retrans: u32,
    /// Number of segments that have been FACKed
    pub fackets: u32,

    pub last_data_sent: u32,
    pub last_ack_sent: u32,
    pub last_data_recv: u32,
    pub last_ack_recv: u32,

    pub pmtu: u32,
    pub rcv_ssthresh: u32,
    /// RTT (Round Trip Time). There RTT is the time between the
    /// moment a segment is sent out and the moment it is
    /// acknowledged. There are different kinds of RTT values, and I
    /// don't know which one this value corresponds to: mRTT (measured
    /// RTT), sRTT (smoothed RTT), RTTd (deviated RTT), etc.
    pub rtt: u32,
    /// RTT variance (or variation?)
    pub rttvar: u32,
    /// Slow-Start Threshold
    pub snd_ssthresh: u32,
    /// Size of the congestion window
    pub snd_cwnd: u32,
    /// MSS advertised by this peer
    pub advmss: u32,

    pub reordering: u32,

    pub rcv_rtt: u32,
    pub rcv_space: u32,

    /// Number of segments that have been retransmitted during lifetime of the
    /// socket
    pub total_retrans: u32,

    pub pacing_rate: u64,
    pub max_pacing_rate: u64,
    pub bytes_acked: u64, // RFC4898 tcpEStatsAppHCThruOctetsAcked
    pub bytes_received: u64, // RFC4898 tcpEStatsAppHCThruOctetsReceived
    pub segs_out: u32,    // RFC4898 tcpEStatsPerfSegsOut
    pub segs_in: u32,     // RFC4898 tcpEStatsPerfSegsIn

    pub notsent_bytes: u32,
    pub min_rtt: u32,
    pub data_segs_in: u32,  // RFC4898 tcpEStatsDataSegsIn
    pub data_segs_out: u32, // RFC4898 tcpEStatsDataSegsOut

    /// The most recent goodput, as measured by tcp_rate_gen(). If the
    /// socket is limited by the sending application (e.g., no data to
    /// send), it reports the highest measurement instead of the most
    /// recent. The unit is bytes per second (like other rate fields
    /// in tcp_info).
    pub delivery_rate: u64,

    pub busy_time: u64,      // Time (usec) busy sending data
    pub rwnd_limited: u64,   // Time (usec) limited by receive window
    pub sndbuf_limited: u64, // Time (usec) limited by send buffer

    pub delivered: u32,
    pub delivered_ce: u32,

    pub bytes_sent: u64, // RFC4898 tcpEStatsPerfHCDataOctetsOut
    pub bytes_retrans: u64, // RFC4898 tcpEStatsPerfOctetsRetrans
    pub dsack_dups: u32, // RFC4898 tcpEStatsStackDSACKDups
    /// reordering events seen
    pub reord_seen: u32,

    /// Out-of-order packets received
    pub rcv_ooopack: u32,
    /// peer's advertised receive window after scaling (bytes)
    pub snd_wnd: u32,
}

#[cfg(feature = "rich_nlas")]
impl TcpInfo {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            TcpInfoBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<TcpInfoBuffer>(),
                )
            })?;
        Ok(Self {
            state: raw.state,
            ca_state: raw.congestion_avoidance_state,
            retransmits: raw.retransmits,
            probes: raw.probes,
            backoff: raw.backoff,
            options: raw.options,
            wscale: raw.wscale,
            delivery_rate_app_limited: raw.delivery_rate_app_limited,
            rto: raw.rto,
            ato: raw.ato,
            snd_mss: raw.snd_mss,
            rcv_mss: raw.rcv_mss,
            unacked: raw.unacked,
            sacked: raw.sacked,
            lost: raw.lost,
            retrans: raw.retrans,
            fackets: raw.fackets,
            last_data_sent: raw.last_data_sent,
            last_ack_sent: raw.last_ack_sent,
            last_data_recv: raw.last_data_recv,
            last_ack_recv: raw.last_ack_recv,
            pmtu: raw.pmtu,
            rcv_ssthresh: raw.rcv_ssthresh,
            rtt: raw.rtt,
            rttvar: raw.rttvar,
            snd_ssthresh: raw.snd_ssthresh,
            snd_cwnd: raw.snd_cwnd,
            advmss: raw.advmss,
            reordering: raw.reordering,
            rcv_rtt: raw.rcv_rtt,
            rcv_space: raw.rcv_space,
            total_retrans: raw.total_retrans,
            pacing_rate: raw.pacing_rate,
            max_pacing_rate: raw.max_pacing_rate,
            bytes_acked: raw.bytes_acked,
            bytes_received: raw.bytes_received,
            segs_out: raw.segs_out,
            segs_in: raw.segs_in,
            notsent_bytes: raw.notsent_bytes,
            min_rtt: raw.min_rtt,
            data_segs_in: raw.data_segs_in,
            data_segs_out: raw.data_segs_out,
            delivery_rate: raw.delivery_rate,
            busy_time: raw.busy_time,
            rwnd_limited: raw.rwnd_limited,
            sndbuf_limited: raw.sndbuf_limited,
            delivered: raw.delivered,
            delivered_ce: raw.delivered_ce,
            bytes_sent: raw.bytes_sent,
            bytes_retrans: raw.bytes_retrans,
            dsack_dups: raw.dsack_dups,
            reord_seen: raw.reord_seen,
            rcv_ooopack: raw.rcv_ooopack,
            snd_wnd: raw.snd_wnd,
        })
    }
}

#[cfg(feature = "rich_nlas")]
impl From<&TcpInfo> for TcpInfoBuffer {
    fn from(value: &TcpInfo) -> Self {
        Self {
            state: value.state,
            congestion_avoidance_state: value.ca_state,
            retransmits: value.retransmits,
            probes: value.probes,
            backoff: value.backoff,
            options: value.options,
            wscale: value.wscale,
            delivery_rate_app_limited: value.delivery_rate_app_limited,
            rto: value.rto,
            ato: value.ato,
            snd_mss: value.snd_mss,
            rcv_mss: value.rcv_mss,
            unacked: value.unacked,
            sacked: value.sacked,
            lost: value.lost,
            retrans: value.retrans,
            fackets: value.fackets,
            last_data_sent: value.last_data_sent,
            last_ack_sent: value.last_ack_sent,
            last_data_recv: value.last_data_recv,
            last_ack_recv: value.last_ack_recv,
            pmtu: value.pmtu,
            rcv_ssthresh: value.rcv_ssthresh,
            rtt: value.rtt,
            rttvar: value.rttvar,
            snd_ssthresh: value.snd_ssthresh,
            snd_cwnd: value.snd_cwnd,
            advmss: value.advmss,
            reordering: value.reordering,
            rcv_rtt: value.rcv_rtt,
            rcv_space: value.rcv_space,
            total_retrans: value.total_retrans,
            pacing_rate: value.pacing_rate,
            max_pacing_rate: value.max_pacing_rate,
            bytes_acked: value.bytes_acked,
            bytes_received: value.bytes_received,
            segs_out: value.segs_out,
            segs_in: value.segs_in,
            notsent_bytes: value.notsent_bytes,
            min_rtt: value.min_rtt,
            data_segs_in: value.data_segs_in,
            data_segs_out: value.data_segs_out,
            delivery_rate: value.delivery_rate,
            busy_time: value.busy_time,
            rwnd_limited: value.rwnd_limited,
            sndbuf_limited: value.sndbuf_limited,
            delivered: value.delivered,
            delivered_ce: value.delivered_ce,
            bytes_sent: value.bytes_sent,
            bytes_retrans: value.bytes_retrans,
            dsack_dups: value.dsack_dups,
            reord_seen: value.reord_seen,
            rcv_ooopack: value.rcv_ooopack,
            snd_wnd: value.snd_wnd,
        }
    }
}

#[cfg(feature = "rich_nlas")]
impl Emitable for TcpInfo {
    fn buffer_len(&self) -> usize {
        size_of::<TcpInfoBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = TcpInfoBuffer::from(self);
        buffer.copy_from_slice(raw.as_bytes());
    }
}
