// SPDX-License-Identifier: MIT

use std::convert::TryFrom;

use netlink_packet_utils::{
    buffer,
    traits::{Emitable, Parseable},
    DecodeError,
};

use crate::constants::*;

pub const NETLINK_REQUEST_LEN: usize = 20;

buffer!(NetlinkRequestBuffer(NETLINK_REQUEST_LEN) {
    // The address family; it should be set to `AF_NETLINK`.
    family: (u8, 0),
    // The specific `NETLINK_*` netlink protocol to query or `NDIAG_PROTO_ALL`.
    protocol: (u8, 1),
    // This field should be set to `0`.
    pad: (u16, 2..4),
    // This is an inode number when querying for an individual socket. Ignored
    // when querying for a list of sockets.
    inode: (u32, 4..8),
    // This is a set of flags defining what kind of information to report.
    // Supported values are the `NDIAG_SHOW_*` constants.
    show_flags: (u32, 8..12),
    // This is an array of opaque identifiers that could be used along with
    // ndiag_ino to specify an individual socket. It is ignored when querying
    // for a list of sockets, as well as when all its elements are set to
    // `0xff`.
    cookie: (slice, 12..NETLINK_REQUEST_LEN),
});

/// The request for netlink domain sockets.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NetlinkRequest {
    /// The specific `NETLINK_*` netlink protocol to query.
    ///
    /// Use `NDIAG_PROTO_ALL` to query for all netlink protocols.
    pub protocol: u8,
    /// This is an inode number when querying for an individual socket.
    ///
    /// Ignored when querying for a list of sockets.
    pub inode: u32,
    /// This is a set of flags defining what kind of information to report.
    ///
    /// Each requested kind of information is reported back as a netlink
    /// attribute.
    pub show_flags: ShowFlags,
    /// This is an opaque identifier that could be used to specify an
    /// individual socket.
    pub cookie: [u8; 8],
}

bitflags! {
    /// Bitmask that defines what kind of information to report. Supported
    /// values are the `NDIAG_SHOW_*` constants.
    pub struct ShowFlags: u32 {
        const MEMINFO = NDIAG_SHOW_MEMINFO;
        const GROUPS = NDIAG_SHOW_GROUPS;
        const RING_CFG = NDIAG_SHOW_RING_CFG;
        const FLAGS = NDIAG_SHOW_FLAGS;
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<NetlinkRequestBuffer<&'a T>>
    for NetlinkRequest
{
    fn parse(buf: &NetlinkRequestBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(Self {
            protocol: buf.protocol(),
            inode: buf.inode(),
            show_flags: ShowFlags::from_bits_truncate(buf.show_flags()),
            // Unwrapping is safe because NetlinkRequestBuffer::cookie()
            // returns a slice of exactly 8 bytes.
            cookie: TryFrom::try_from(buf.cookie()).unwrap(),
        })
    }
}

impl Emitable for NetlinkRequest {
    fn buffer_len(&self) -> usize {
        NETLINK_REQUEST_LEN
    }

    fn emit(&self, buf: &mut [u8]) {
        let mut buffer = NetlinkRequestBuffer::new(buf);
        buffer.set_family(AF_NETLINK);
        buffer.set_protocol(self.protocol);
        buffer.set_inode(self.inode);
        buffer.set_pad(0);
        buffer.set_show_flags(self.show_flags.bits());
        buffer.cookie_mut().copy_from_slice(&self.cookie[..]);
    }
}
