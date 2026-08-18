// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable, Parseable};
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
pub struct UnixRequestBuffer {
    // The address family; it should be set to `AF_UNIX`
    family: u8,
    // This field should be set to `0`
    protocol: u8,
    // This field should be set to `0`
    pad: u16,
    // This is a bit mask that defines a filter of sockets
    // states. Only those sockets whose states are in this mask will
    // be reported. Ignored when querying for an individual
    // socket. Supported values are:
    //
    // ```no_rust
    // 1 << UNIX_ESTABLISHED
    // 1 << UNIX_LISTEN
    // ```
    state_flags: u32,
    // This is an inode number when querying for an individual
    // socket. Ignored when querying for a list of sockets.
    inode: u32,
    // This is a set of flags defining what kind of information to
    // report. Supported values are the `UDIAG_SHOW_*` constants.
    show_flags: u32,
    // This is an array of opaque identifiers that could be used
    // along with udiag_ino to specify an individual socket. It is
    // ignored when querying for a list of sockets, as well as when
    // all its elements are set to `0xff`.
    cookie: [u8; 8],
}

/// The request for UNIX domain sockets
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UnixRequest {
    /// This is a bit mask that defines a filter of sockets states.
    ///
    /// Only those sockets whose states are in this mask will be reported.
    /// Ignored when querying for an individual socket.
    pub state_flags: StateFlags,
    /// This is an inode number when querying for an individual socket.
    ///
    /// Ignored when querying for a list of sockets.
    pub inode: u32,
    /// This is a set of flags defining what kind of information to report.
    ///
    /// Each requested kind of information is reported back as a netlink
    /// attribute
    pub show_flags: ShowFlags,
    /// This is an opaque identifiers that could be used to specify an
    /// individual socket.
    pub cookie: [u8; 8],
}

bitflags! {
    /// Bitmask that defines a filter of UNIX socket states
    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct StateFlags: u32 {
        const ESTABLISHED = 1 << TCP_ESTABLISHED;
        const LISTEN = 1 << TCP_LISTEN;
    }
}

bitflags! {
    /// Bitmask that defines what kind of information to
    /// report. Supported values are the `UDIAG_SHOW_*` constants.
    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct ShowFlags: u32 {
        const NAME = UDIAG_SHOW_NAME;
        const VFS = UDIAG_SHOW_VFS;
        const PEER = UDIAG_SHOW_PEER;
        const ICONS = UDIAG_SHOW_ICONS;
        const RQLEN = UDIAG_SHOW_RQLEN;
        const MEMINFO = UDIAG_SHOW_MEMINFO;
    }
}

impl Parseable<[u8]> for UnixRequest {
    fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            UnixRequestBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<UnixRequestBuffer>(),
                )
            })?;

        Ok(Self {
            state_flags: StateFlags::from_bits_truncate(raw.state_flags),
            inode: raw.inode,
            show_flags: ShowFlags::from_bits_truncate(raw.show_flags),
            cookie: raw.cookie,
        })
    }
}

impl From<&UnixRequest> for UnixRequestBuffer {
    fn from(value: &UnixRequest) -> Self {
        Self {
            family: AF_UNIX,
            protocol: 0,
            pad: 0,
            state_flags: value.state_flags.bits(),
            inode: value.inode,
            show_flags: value.show_flags.bits(),
            cookie: value.cookie,
        }
    }
}

impl Emitable for UnixRequest {
    fn buffer_len(&self) -> usize {
        size_of::<UnixRequestBuffer>()
    }

    fn emit(&self, buf: &mut [u8]) {
        let raw = UnixRequestBuffer::from(self);
        buf.copy_from_slice(raw.as_bytes());
    }
}
