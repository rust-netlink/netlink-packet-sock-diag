// SPDX-License-Identifier: MIT

use std::{mem::size_of, time::Duration};

use netlink_packet_core::{
    DecodeError, Emitable, ErrorContext, NlasIterator, Parseable,
    ParseableParametrized,
};
use smallvec::SmallVec;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::inet::{nlas::Nla, SocketId, SocketIdBuffer};

/// The type of timer that is currently active for a TCP socket.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Timer {
    /// A retransmit timer
    Retransmit(Duration, u8),
    /// A keep-alive timer
    KeepAlive(Duration),
    /// A `TIME_WAIT` timer
    TimeWait,
    /// A zero window probe timer
    Probe(Duration),
}

const INET_RESPONSE_HEADER_LEN: usize = size_of::<InetResponseBuffer>();

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
pub struct InetResponseBuffer {
    family: u8,
    state: u8,
    timer: u8,
    retransmits: u8,
    socket_id: [u8; size_of::<SocketIdBuffer>()],
    expires: u32,
    recv_queue: u32,
    send_queue: u32,
    uid: u32,
    inode: u32,
}

/// The response to a query for IPv4 or IPv6 sockets
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct InetResponseHeader {
    /// This should be set to either `AF_INET` or `AF_INET6` for IPv4
    /// or IPv6 sockets respectively.
    pub family: u8,

    /// The socket state.
    pub state: u8,

    /// For TCP sockets, this field describes the type of timer
    /// that is currently active for the socket.
    pub timer: Option<Timer>,

    /// The socket ID object.
    pub socket_id: SocketId,

    /// For listening sockets: the number of pending connections. For
    /// other sockets: the amount of data in the incoming queue.
    pub recv_queue: u32,

    /// For listening sockets: the backlog length. For other sockets:
    /// the amount of memory available for sending.
    pub send_queue: u32,

    /// Socket owner UID.
    pub uid: u32,

    /// Socket inode number.
    pub inode: u32,
}

impl Parseable<[u8]> for InetResponseHeader {
    fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            InetResponseBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    INET_RESPONSE_HEADER_LEN,
                )
            })?;

        let err = "invalid socket_id value";
        let socket_id =
            SocketId::parse_with_param(raw.socket_id.as_bytes(), raw.family)
                .context(err)?;

        let timer = match raw.timer {
            1 => {
                let expires = Duration::from_millis(raw.expires as u64);
                Some(Timer::Retransmit(expires, raw.retransmits))
            }
            2 => {
                let expires = Duration::from_millis(raw.expires as u64);
                Some(Timer::KeepAlive(expires))
            }
            3 => Some(Timer::TimeWait),
            4 => {
                let expires = Duration::from_millis(raw.expires as u64);
                Some(Timer::Probe(expires))
            }
            _ => None,
        };

        Ok(Self {
            family: raw.family,
            state: raw.state,
            timer,
            socket_id,
            recv_queue: raw.recv_queue,
            send_queue: raw.send_queue,
            uid: raw.uid,
            inode: raw.inode,
        })
    }
}

impl From<&InetResponseHeader> for InetResponseBuffer {
    fn from(header: &InetResponseHeader) -> Self {
        let (timer, expires, retransmits) = match header.timer {
            Some(Timer::Retransmit(expires, retransmits)) => {
                (1, (expires.as_millis() & 0xffff_ffff) as u32, retransmits)
            }
            Some(Timer::KeepAlive(expires)) => {
                (2, (expires.as_millis() & 0xffff_ffff) as u32, 0)
            }
            Some(Timer::TimeWait) => (3, 0, 0),
            Some(Timer::Probe(expires)) => {
                (4, (expires.as_millis() & 0xffff_ffff) as u32, 0)
            }
            None => (0, 0, 0),
        };

        let mut socket_id = [0u8; size_of::<SocketIdBuffer>()];
        socket_id.copy_from_slice(
            SocketIdBuffer::from(&header.socket_id).as_bytes(),
        );
        Self {
            family: header.family,
            state: header.state,
            timer,
            retransmits,
            socket_id,
            expires,
            recv_queue: header.recv_queue,
            send_queue: header.send_queue,
            uid: header.uid,
            inode: header.inode,
        }
    }
}

impl Emitable for InetResponseHeader {
    fn buffer_len(&self) -> usize {
        INET_RESPONSE_HEADER_LEN
    }

    fn emit(&self, buf: &mut [u8]) {
        let raw = InetResponseBuffer::from(self);
        buf[..INET_RESPONSE_HEADER_LEN].copy_from_slice(raw.as_bytes());
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct InetResponse {
    pub header: InetResponseHeader,
    pub nlas: SmallVec<[Nla; 8]>,
}

impl Parseable<[u8]> for InetResponse {
    fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.len() < INET_RESPONSE_HEADER_LEN {
            return Err(DecodeError::buffer_too_small(
                payload.len(),
                INET_RESPONSE_HEADER_LEN,
            ));
        }

        let header =
            InetResponseHeader::parse(&payload[..INET_RESPONSE_HEADER_LEN])
                .context("failed to parse inet response header")?;
        let mut nlas = smallvec![];
        for nla_buf in NlasIterator::new(&payload[INET_RESPONSE_HEADER_LEN..]) {
            nlas.push(
                Nla::parse(&nla_buf?)
                    .context("failed to parse inet response NLAs")?,
            );
        }
        Ok(InetResponse { header, nlas })
    }
}

impl Emitable for InetResponse {
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
