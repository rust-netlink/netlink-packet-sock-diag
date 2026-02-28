// SPDX-License-Identifier: MIT

use crate::constants::*;
use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian, WriteBytesExt};
use netlink_packet_utils::{
    buffer,
    nla::{self, DefaultNla, NlaBuffer},
    traits::{Emitable, Parseable},
    DecodeError,
};
use smallvec::SmallVec;
use std::io::Cursor;
use std::iter::FromIterator;
use std::mem::size_of;

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Nla {
    /// Socket memory information. This attribute is known as
    /// `NETLINK_DIAG_MEMINFO` in the kernel. See [MemInfo] for more
    /// details.
    MemInfo(MemInfo),
    /// A variable-length bitmask array of all subscribed groups, capable of
    /// exceeding the 32-group limit. This attribute is known as
    /// `NETLINK_DIAG_GROUPS` in the kernel. See [Groups] for more details.
    Groups(Groups),
    /// Information about memory-mapped ring buffers for the socket. This
    /// attribute is known as `NETLINK_DIAG_RX_RING` in the kernel. See
    /// [RingInfo] for more details.
    RxRing(RingInfo),
    /// Information about memory-mapped ring buffers for the socket. This
    /// attribute is known as `NETLINK_DIAG_TX_RING` in the kernel. See
    /// [RingInfo] for more details.
    TxRing(RingInfo),
    /// Additional boolean flags about the socket's internal state. This
    /// attribute is known as `NETLINK_DIAG_FLAGS` in the kernel. See
    /// [StateFlags] for more details.
    Flags(StateFlags),
    /// Unknown attribute.
    Other(DefaultNla),
}

pub const MEM_INFO_LEN: usize = 36;

buffer!(MemInfoBuffer(MEM_INFO_LEN) {
    rmem_alloc: (u32, 0..4),
    rcvbuf: (u32, 4..8),
    wmem_alloc: (u32, 8..12),
    sndbuf: (u32, 12..16),
    unused_fwd_alloc: (u32, 16..20),
    unused_wmem_queued: (u32, 20..24),
    sk_optmem: (u32, 24..28),
    backlog: (u32, 28..32),
    drops: (u32, 32..36),
});

/// Socket memory allocation and queue statistics.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct MemInfo {
    /// The amount of memory (in bytes) currently allocated for receiving
    /// packets.
    pub rmem_alloc: u32,
    /// The maximum allowed size (in bytes) of the receiving buffer
    /// (`SO_RCVBUF`).
    pub rcvbuf: u32,
    /// The amount of memory (in bytes) currently allocated for sending
    /// packets.
    pub wmem_alloc: u32,
    /// The maximum allowed size (in bytes) of the send buffer (`SO_SNDBUF`).
    pub sndbuf: u32,
    /// The amount of memory (in bytes) allocated for socket options and
    /// control messages (ancillary data).
    pub sk_optmem: u32,
    /// The number of packets currently queued in the socket's backlog. These
    /// are packets that have been received by the network stack but not
    /// yet processed by the receiving application.
    pub backlog: u32,
    /// The total number of packets dropped by the socket. This typically
    /// occurs when the receiving buffer (`rcvbuf`) is full.
    pub drops: u32,
}

impl<T: AsRef<[u8]>> Parseable<MemInfoBuffer<T>> for MemInfo {
    fn parse(buf: &MemInfoBuffer<T>) -> Result<Self, DecodeError> {
        Ok(Self {
            rmem_alloc: buf.rmem_alloc(),
            rcvbuf: buf.rcvbuf(),
            wmem_alloc: buf.wmem_alloc(),
            sndbuf: buf.sndbuf(),
            sk_optmem: buf.sk_optmem(),
            backlog: buf.backlog(),
            drops: buf.drops(),
        })
    }
}

impl Emitable for MemInfo {
    fn buffer_len(&self) -> usize {
        MEM_INFO_LEN
    }

    fn emit(&self, buf: &mut [u8]) {
        let mut buf = MemInfoBuffer::new(buf);

        buf.set_rmem_alloc(self.rmem_alloc);
        buf.set_rcvbuf(self.rcvbuf);
        buf.set_wmem_alloc(self.wmem_alloc);
        buf.set_sndbuf(self.sndbuf);
        buf.set_unused_fwd_alloc(0);
        buf.set_unused_wmem_queued(0);
        buf.set_sk_optmem(self.sk_optmem);
        buf.set_backlog(self.backlog);
        buf.set_drops(self.drops);
    }
}

/// The multicast groups the netlink socket is currently subscribed to.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Groups(SmallVec<[u32; 8]>);

impl Parseable<[u8]> for Groups {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        if !buf.len().is_multiple_of(size_of::<u32>()) {
            return Err("invalid groups length".into())
        }

        Ok(Self(
            buf.chunks(size_of::<u32>())
                .map(NativeEndian::read_u32)
                .collect(),
        ))
    }
}

impl Groups {
    /// Creates a new empty set of multicast groups.
    pub fn new() -> Self {
        Self(SmallVec::new())
    }

    fn index_and_offset(group: u32) -> (usize, u32) {
        let bit_index = group - 1;
        let vec_index = (bit_index / 32) as usize;
        let bit_offset = bit_index % 32;
        (vec_index, bit_offset)
    }

    fn group(vec_index: usize, bit_offset: u32) -> u32 {
        (vec_index as u32 * 32) + bit_offset + 1
    }

    fn is_bit_set(bitmask: u32, bit_offset: u32) -> bool {
        (bitmask & (1 << bit_offset)) != 0
    }

    /// Adds a multicast group.
    pub fn add(&mut self, group: u32) {
        // Group 0 is not valid.
        if group == 0 {
            return;
        }

        let (vec_index, bit_offset) = Self::index_and_offset(group);
        if vec_index >= self.0.len() {
            self.0.resize(vec_index + 1, 0)
        }
        self.0[vec_index] |= 1 << bit_offset;
    }

    /// Checks if the specified multicast group is present.
    pub fn contains(&self, group: u32) -> bool {
        // Group 0 is not valid.
        if group == 0 {
            return false;
        }

        let (vec_index, bit_offset) = Self::index_and_offset(group);

        let Some(&bitmask) = self.0.get(vec_index) else {
            return false;
        };

        Self::is_bit_set(bitmask, bit_offset)
    }

    /// Returns an iterator over all subscribed multicast groups.
    pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.0.iter().enumerate().flat_map(|(vec_index, &bitmask)| {
            (0..32).filter_map(move |bit_offset| {
                if Self::is_bit_set(bitmask, bit_offset) {
                    Some(Self::group(vec_index, bit_offset))
                } else {
                    None
                }
            })
        })
    }
}

impl FromIterator<u32> for Groups {
    fn from_iter<T: IntoIterator<Item = u32>>(iter: T) -> Self {
        let mut groups = Groups::new();
        for group in iter {
            groups.add(group)
        }
        groups
    }
}

impl Emitable for Groups {
    fn buffer_len(&self) -> usize {
        self.0.len() * size_of::<u32>()
    }

    fn emit(&self, buf: &mut [u8]) {
        let mut cursor = Cursor::new(buf);
        for &v in self.0.iter() {
            cursor.write_u32::<NativeEndian>(v).unwrap();
        }
    }
}

pub const NETLINK_DIAG_RING_LEN: usize = 16;

buffer!(RingInfoBuffer(NETLINK_DIAG_RING_LEN) {
    block_size: (u32, 0..4),
    block_nr: (u32, 4..8),
    frame_size: (u32, 8..12),
    frame_nr: (u32, 12..16),
});

/// Configuration details for a memory-mapped netlink ring buffer.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct RingInfo {
    /// The size (in bytes) of a single contiguous memory block in the ring.
    pub block_size: u32,
    /// The total number of memory blocks allocated for the ring.
    pub block_nr: u32,
    /// The maximum size (in bytes) of a single Netlink frame (message) within
    /// a block.
    pub frame_size: u32,
    /// The total number of frames across all blocks in the entire ring.
    pub frame_nr: u32,
}

impl<T: AsRef<[u8]>> Parseable<RingInfoBuffer<T>> for RingInfo {
    fn parse(buf: &RingInfoBuffer<T>) -> Result<Self, DecodeError> {
        Ok(Self {
            block_size: buf.block_size(),
            block_nr: buf.block_nr(),
            frame_size: buf.frame_size(),
            frame_nr: buf.frame_nr(),
        })
    }
}

impl Emitable for RingInfo {
    fn buffer_len(&self) -> usize {
        NETLINK_DIAG_RING_LEN
    }

    fn emit(&self, buf: &mut [u8]) {
        let mut buf = RingInfoBuffer::new(buf);

        buf.set_block_size(self.block_size);
        buf.set_block_nr(self.block_nr);
        buf.set_frame_size(self.frame_size);
        buf.set_frame_nr(self.frame_nr);
    }
}
bitflags! {
    /// Internal state flags and socket options for a netlink socket.
    pub struct StateFlags: u32 {
        const CB_RUNNING = NDIAG_FLAG_CB_RUNNING;
        const PKTINFO = NDIAG_FLAG_PKTINFO;
        const BROADCAST_ERROR = NDIAG_FLAG_BROADCAST_ERROR;
        const NO_ENOBUFS = NDIAG_FLAG_NO_ENOBUFS;
        const LISTEN_ALL_NSID = NDIAG_FLAG_LISTEN_ALL_NSID;
        const CAP_ACK = NDIAG_FLAG_CAP_ACK;
    }
}

impl nla::Nla for Nla {
    fn value_len(&self) -> usize {
        use self::Nla::*;
        match *self {
            MemInfo(_) => MEM_INFO_LEN,
            Groups(ref groups) => groups.buffer_len(),
            RxRing(_) => NETLINK_DIAG_RING_LEN,
            TxRing(_) => NETLINK_DIAG_RING_LEN,
            Flags(_) => 4,
            Other(ref attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        use self::Nla::*;
        match *self {
            MemInfo(_) => NETLINK_DIAG_MEMINFO,
            Groups(_) => NETLINK_DIAG_GROUPS,
            RxRing(_) => NETLINK_DIAG_RX_RING,
            TxRing(_) => NETLINK_DIAG_TX_RING,
            Flags(_) => NETLINK_DIAG_FLAGS,
            Other(ref attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::Nla::*;
        match *self {
            MemInfo(ref value) => value.emit(buffer),
            Groups(ref value) => value.emit(buffer),
            RxRing(ref value) => value.emit(buffer),
            TxRing(ref value) => value.emit(buffer),
            Flags(flags) => NativeEndian::write_u32(buffer, flags.bits()),
            Other(ref attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Nla {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NETLINK_DIAG_MEMINFO => {
                let err = "invalid NETLINK_DIAG_MEMINFO value";
                let buf = MemInfoBuffer::new_checked(payload).context(err)?;
                Self::MemInfo(MemInfo::parse(&buf).context(err)?)
            }
            NETLINK_DIAG_GROUPS => {
                let err = "invalid NETLINK_DIAG_GROUPS value";
                Self::Groups(Groups::parse(&payload).context(err)?)
            }
            NETLINK_DIAG_RX_RING => {
                let err = "invalid NETLINK_DIAG_RX_RING value";
                let buf = RingInfoBuffer::new_checked(payload).context(err)?;
                Self::RxRing(RingInfo::parse(&buf).context(err)?)
            }
            NETLINK_DIAG_TX_RING => {
                let err = "invalid NETLINK_DIAG_TX_RING value";
                let buf = RingInfoBuffer::new_checked(payload).context(err)?;
                Self::TxRing(RingInfo::parse(&buf).context(err)?)
            }
            NETLINK_DIAG_FLAGS => {
                let err = "invalid NETLINK_DIAG_FLAGS value";
                let payload_bytes = payload.get(..4).context(err)?;
                let value = NativeEndian::read_u32(payload_bytes);
                Self::Flags(StateFlags::from_bits_truncate(value))
            }
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind}"))?,
            ),
        })
    }
}
