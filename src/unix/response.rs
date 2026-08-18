// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{
    DecodeError, Emitable, ErrorContext, NlasIterator, Parseable,
};
use smallvec::SmallVec;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    constants::*,
    unix::nlas::{MemInfo, Nla, UnixDiagName},
};

const UNIX_RESPONSE_HEADER_LEN: usize = size_of::<UnixResponseBuffer>();

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
pub struct UnixResponseBuffer {
    family: u8,
    kind: u8,
    state: u8,
    pad: u8,
    inode: u32,
    cookie: [u8; 8],
}

/// The response to a query for IPv4 or IPv6 sockets
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UnixResponseHeader {
    /// One of `SOCK_PACKET`, `SOCK_STREAM`, or `SOCK_SEQPACKET`
    pub kind: u8,
    /// State of the socket. According to `man 7 sock_diag` it can be
    /// either `TCP_ESTABLISHED` or `TCP_LISTEN`. However datagram
    /// UNIX sockets are not connection oriented so I would assume
    /// that this field can also take other value (maybe `0`) for
    /// these sockets.
    pub state: u8,
    /// Socket inode number.
    pub inode: u32,
    pub cookie: [u8; 8],
}

impl Parseable<[u8]> for UnixResponseHeader {
    fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            UnixResponseBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    UNIX_RESPONSE_HEADER_LEN,
                )
            })?;

        Ok(Self {
            kind: raw.kind,
            state: raw.state,
            inode: raw.inode,
            cookie: raw.cookie,
        })
    }
}

impl From<&UnixResponseHeader> for UnixResponseBuffer {
    fn from(header: &UnixResponseHeader) -> Self {
        Self {
            family: AF_UNIX,
            kind: header.kind,
            state: header.state,
            pad: 0,
            inode: header.inode,
            cookie: header.cookie,
        }
    }
}

impl Emitable for UnixResponseHeader {
    fn buffer_len(&self) -> usize {
        UNIX_RESPONSE_HEADER_LEN
    }

    fn emit(&self, buf: &mut [u8]) {
        let raw = UnixResponseBuffer::from(self);
        buf[..UNIX_RESPONSE_HEADER_LEN].copy_from_slice(raw.as_bytes());
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UnixResponse {
    pub header: UnixResponseHeader,
    pub nlas: SmallVec<[Nla; 8]>,
}

impl UnixResponse {
    pub fn peer(&self) -> Option<u32> {
        self.nlas.iter().find_map(|nla| {
            if let Nla::Peer(inode) = nla {
                Some(*inode)
            } else {
                None
            }
        })
    }

    pub fn name(&self) -> Option<&UnixDiagName> {
        self.nlas.iter().find_map(|nla| {
            if let Nla::Name(name) = nla {
                Some(name)
            } else {
                None
            }
        })
    }

    pub fn pending_connections(&self) -> Option<&[u32]> {
        self.nlas.iter().find_map(|nla| {
            if let Nla::PendingConnections(connections) = nla {
                Some(&connections[..])
            } else {
                None
            }
        })
    }

    fn mem_info(&self) -> Option<MemInfo> {
        self.nlas.iter().find_map(|nla| {
            if let Nla::MemInfo(mem_info) = nla {
                Some(*mem_info)
            } else {
                None
            }
        })
    }

    pub fn shutdown_state(&self) -> Option<u8> {
        self.nlas.iter().find_map(|nla| {
            if let Nla::Shutdown(shutdown_state) = nla {
                Some(*shutdown_state)
            } else {
                None
            }
        })
    }

    fn receive_queue_length(&self) -> Option<(u32, u32)> {
        self.nlas.iter().find_map(|nla| {
            if let Nla::ReceiveQueueLength(x, y) = nla {
                Some((*x, *y))
            } else {
                None
            }
        })
    }

    pub fn number_of_pending_connection(&self) -> Option<u32> {
        if self.header.state == TCP_LISTEN {
            self.receive_queue_length().map(|(n, _)| n)
        } else {
            None
        }
    }

    pub fn max_number_of_pending_connection(&self) -> Option<u32> {
        if self.header.state == TCP_LISTEN {
            self.receive_queue_length().map(|(_, n)| n)
        } else {
            None
        }
    }

    pub fn receive_queue_size(&self) -> Option<u32> {
        if self.header.state == TCP_LISTEN {
            None
        } else {
            self.receive_queue_length().map(|(n, _)| n)
        }
    }

    pub fn send_queue_size(&self) -> Option<u32> {
        if self.header.state == TCP_LISTEN {
            self.receive_queue_length().map(|(n, _)| n)
        } else {
            None
        }
    }

    pub fn max_datagram_size(&self) -> Option<u32> {
        self.mem_info().map(|mem_info| mem_info.max_datagram_size)
    }

    pub fn memory_used_for_outgoing_data(&self) -> Option<u32> {
        self.mem_info().map(|mem_info| mem_info.alloc)
    }
}

impl Parseable<[u8]> for UnixResponse {
    fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.len() < UNIX_RESPONSE_HEADER_LEN {
            return Err(DecodeError::buffer_too_small(
                payload.len(),
                UNIX_RESPONSE_HEADER_LEN,
            ));
        }

        let header =
            UnixResponseHeader::parse(&payload[..UNIX_RESPONSE_HEADER_LEN])
                .context("failed to parse unix response header")?;
        let mut nlas = smallvec![];
        for nla_buf in NlasIterator::new(&payload[UNIX_RESPONSE_HEADER_LEN..]) {
            nlas.push(
                Nla::parse(&nla_buf?)
                    .context("failed to parse unix response NLAs")?,
            );
        }
        Ok(UnixResponse { header, nlas })
    }
}

impl Emitable for UnixResponse {
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
