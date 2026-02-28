// SPDX-License-Identifier: MIT

use std::convert::TryFrom;

use anyhow::Context;
use netlink_packet_utils::{
    buffer,
    nla::{NlaBuffer, NlasIterator},
    traits::{Emitable, Parseable},
    DecodeError,
};
use smallvec::SmallVec;

use crate::netlink::nlas::{Groups, RingInfo, StateFlags};
use crate::{
    constants::*,
    netlink::nlas::{MemInfo, Nla},
};

pub const NETLINK_RESPONSE_HEADER_LEN: usize = 28;

buffer!(NetlinkResponseBuffer(NETLINK_RESPONSE_HEADER_LEN) {
    family: (u8, 0),
    kind: (u8, 1),
    protocol: (u8, 2),
    state: (u8, 3),
    portid: (u32, 4..8),
    dst_portid: (u32, 8..12),
    dst_group: (u32, 12..16),
    inode: (u32, 16..20),
    cookie: (slice, 20..NETLINK_RESPONSE_HEADER_LEN),
    payload: (slice, NETLINK_RESPONSE_HEADER_LEN..),
});

/// The response to a query for netlink sockets.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NetlinkResponseHeader {
    /// One of `SOCK_RAW` or `SOCK_DGRAM`.
    pub kind: u8,
    /// One of `NETLINK_*` available netlink protocols, as documented in `man 7
    /// netlink`.
    pub protocol: u8,
    /// State of the socket. It can be `NETLINK_UNCONNECTED` or
    /// `NETLINK_CONNECTED`.
    pub state: u8,
    /// The local address of the netlink socket. This is 0 for a kernel socket,
    /// and typically the process ID (or a generated unique identifier) for
    /// userspace sockets.
    pub portid: u32,
    /// The remote address the netlink socket is connected to. This is 0 if the
    /// socket is not connected or connected to the kernel.
    pub dst_portid: u32,
    /// A bitmask representing the first 32 multicast groups the socket is
    /// currently subscribed to. Each set bit corresponds to a specific
    /// multicast group within the netlink protocol. If the socket is not
    /// listening to any multicast groups, this is 0. Any multicast group the
    /// socket is subscribed to beyond the first 32 is accessible via the
    /// `NETLINK_DIAG_GROUPS` attribute.
    pub dst_group: u32,
    /// Socket inode number.
    pub inode: u32,
    /// An opaque identifier that can be used along with the `inode` to
    /// uniquely identify this specific socket instance.
    pub cookie: [u8; 8],
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NetlinkResponseBuffer<&'a T>>
    for NetlinkResponseHeader
{
    fn parse(buf: &NetlinkResponseBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(Self {
            kind: buf.kind(),
            protocol: buf.protocol(),
            state: buf.state(),
            portid: buf.portid(),
            dst_portid: buf.dst_portid(),
            dst_group: buf.dst_group(),
            inode: buf.inode(),
            // Unwrapping is safe because NetlinkResponseBuffer::cookie()
            // returns a slice of exactly 8 bytes.
            cookie: TryFrom::try_from(buf.cookie()).unwrap(),
        })
    }
}

impl Emitable for NetlinkResponseHeader {
    fn buffer_len(&self) -> usize {
        NETLINK_RESPONSE_HEADER_LEN
    }

    fn emit(&self, buf: &mut [u8]) {
        let mut buf = NetlinkResponseBuffer::new(buf);
        buf.set_family(AF_NETLINK);
        buf.set_kind(self.kind);
        buf.set_protocol(self.protocol);
        buf.set_state(self.state);
        buf.set_portid(self.portid);
        buf.set_dst_portid(self.dst_portid);
        buf.set_dst_group(self.dst_group);
        buf.set_inode(self.inode);
        buf.cookie_mut().copy_from_slice(&self.cookie[..]);
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NetlinkResponse {
    pub header: NetlinkResponseHeader,
    pub nlas: SmallVec<[Nla; 8]>,
}

impl NetlinkResponse {
    pub fn mem_info(&self) -> Option<&MemInfo> {
        self.nlas.iter().find_map(|nla| {
            if let Nla::MemInfo(mem_info) = nla {
                Some(mem_info)
            } else {
                None
            }
        })
    }

    pub fn groups(&self) -> Option<&Groups> {
        self.nlas.iter().find_map(|nla| {
            if let Nla::Groups(groups) = nla {
                Some(groups)
            } else {
                None
            }
        })
    }

    pub fn rx_ring(&self) -> Option<&RingInfo> {
        self.nlas.iter().find_map(|nla| {
            if let Nla::RxRing(ring_info) = nla {
                Some(ring_info)
            } else {
                None
            }
        })
    }

    pub fn tx_ring(&self) -> Option<&RingInfo> {
        self.nlas.iter().find_map(|nla| {
            if let Nla::TxRing(ring_info) = nla {
                Some(ring_info)
            } else {
                None
            }
        })
    }

    pub fn state_flags(&self) -> Option<StateFlags> {
        self.nlas.iter().find_map(|nla| {
            if let Nla::Flags(state_flags) = nla {
                Some(*state_flags)
            } else {
                None
            }
        })
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> NetlinkResponseBuffer<&'a T> {
    pub fn nlas(
        &self,
    ) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.payload())
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NetlinkResponseBuffer<&'a T>>
    for SmallVec<[Nla; 8]>
{
    fn parse(buf: &NetlinkResponseBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut nlas = smallvec![];
        for nla_buf in buf.nlas() {
            nlas.push(Nla::parse(&nla_buf?)?);
        }
        Ok(nlas)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NetlinkResponseBuffer<&'a T>>
    for NetlinkResponse
{
    fn parse(buf: &NetlinkResponseBuffer<&'a T>) -> Result<Self, DecodeError> {
        let header = NetlinkResponseHeader::parse(buf)
            .context("failed to parse netlink response header")?;
        let nlas = SmallVec::<[Nla; 8]>::parse(buf)
            .context("failed to parse netlink response NLAs")?;
        Ok(NetlinkResponse { header, nlas })
    }
}

impl Emitable for NetlinkResponse {
    fn buffer_len(&self) -> usize {
        self.header.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.header.emit(buffer);
        self.nlas
            .as_slice()
            .emit(&mut buffer[self.header.buffer_len()..]);
    }
}
