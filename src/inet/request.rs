// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{
    DecodeError, Emitable, ErrorContext, Parseable, ParseableParametrized,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    constants::*,
    inet::{SocketId, SocketIdBuffer},
};

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
pub struct InetRequestBuffer {
    family: u8,
    protocol: u8,
    extensions: u8,
    pad: u8,
    states: u32,
    socket_id: [u8; size_of::<SocketIdBuffer>()],
}

/// A request for Ipv4 and Ipv6 sockets
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct InetRequest {
    /// The address family, either `AF_INET` or `AF_INET6`
    pub family: u8,
    /// The IP protocol. This field should be set to one of the
    /// `IPPROTO_*` constants
    pub protocol: u8,
    /// Set of flags defining what kind of extended information to
    /// report. Each requested kind of information is reported back as
    /// a netlink attribute.
    pub extensions: ExtensionFlags,
    /// Bitmask that defines a filter of TCP socket states
    pub states: StateFlags,
    /// A socket ID object that is used in dump requests, in queries
    /// about individual sockets, and is reported back in each
    /// response.
    ///
    /// Unlike UNIX domain sockets, IPv4 and IPv6 sockets are
    /// identified using addresses and ports.
    pub socket_id: SocketId,
}

bitflags! {
    /// Bitmask that defines a filter of TCP socket states
    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct StateFlags: u32 {
        /// (server and client) represents an open connection,
        /// data received can be delivered to the user. The normal
        /// state for the data transfer phase of the connection.
        const ESTABLISHED = 1 << TCP_ESTABLISHED ;
        /// (client) represents waiting for a matching connection
        /// request after having sent a connection request.
        const SYN_SENT = 1 <<TCP_SYN_SENT ;
        /// (server) represents waiting for a confirming connection
        /// request acknowledgment after having both received and sent
        /// a connection request.
        const SYN_RECV = 1 << TCP_SYN_RECV ;
        /// (both server and client) represents waiting for a
        /// connection termination request from the remote TCP, or an
        /// acknowledgment of the connection termination request
        /// previously sent.
        const FIN_WAIT1 = 1 << TCP_FIN_WAIT1 ;
        /// (both server and client) represents waiting for a
        /// connection termination request from the remote TCP.
        const FIN_WAIT2 = 1 << TCP_FIN_WAIT2 ;
        /// (either server or client) represents waiting for enough
        /// time to pass to be sure the remote TCP received the
        /// acknowledgment of its connection termination request.
        const TIME_WAIT = 1 << TCP_TIME_WAIT ;
        /// (both server and client) represents no connection state at
        /// all.
        const CLOSE = 1 << TCP_CLOSE ;
        /// (both server and client) represents waiting for a
        /// connection termination request from the local user.
        const CLOSE_WAIT = 1 << TCP_CLOSE_WAIT ;
        /// (both server and client) represents waiting for an
        /// acknowledgment of the connection termination request
        /// previously sent to the remote TCP (which includes an
        /// acknowledgment of its connection termination request).
        const LAST_ACK = 1 << TCP_LAST_ACK ;
        /// (server) represents waiting for a connection request from
        /// any remote TCP and port.
        const LISTEN = 1 << TCP_LISTEN ;
        /// (both server and client) represents waiting for a
        /// connection termination request acknowledgment from the
        /// remote TCP.
        const CLOSING = 1 << TCP_CLOSING ;
    }
}

bitflags! {
    /// This is a set of flags defining what kind of extended
    /// information to report.
    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct ExtensionFlags: u8 {
        const MEMINFO = 1 << (INET_DIAG_MEMINFO - 1);
        const INFO = 1 << (INET_DIAG_INFO - 1);
        const VEGASINFO = 1 << (INET_DIAG_VEGASINFO - 1);
        const CONG = 1 << (INET_DIAG_CONG - 1);
        const TOS = 1 << (INET_DIAG_TOS - 1);
        const TCLASS = 1 << (INET_DIAG_TCLASS - 1);
        const SKMEMINFO = 1 << (INET_DIAG_SKMEMINFO - 1);
        const SHUTDOWN = 1 << (INET_DIAG_SHUTDOWN - 1);
    }
}

impl Parseable<[u8]> for InetRequest {
    fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            InetRequestBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<InetRequestBuffer>(),
                )
            })?;

        let err = "invalid socket_id value";
        let socket_id =
            SocketId::parse_with_param(raw.socket_id.as_bytes(), raw.family)
                .context(err)?;

        Ok(Self {
            family: raw.family,
            protocol: raw.protocol,
            extensions: ExtensionFlags::from_bits_truncate(raw.extensions),
            states: StateFlags::from_bits_truncate(raw.states),
            socket_id,
        })
    }
}

impl From<&InetRequest> for InetRequestBuffer {
    fn from(value: &InetRequest) -> Self {
        let mut socket_id = [0u8; size_of::<SocketIdBuffer>()];
        socket_id
            .copy_from_slice(SocketIdBuffer::from(&value.socket_id).as_bytes());
        Self {
            family: value.family,
            protocol: value.protocol,
            extensions: value.extensions.bits(),
            pad: 0,
            states: value.states.bits(),
            socket_id,
        }
    }
}

impl Emitable for InetRequest {
    fn buffer_len(&self) -> usize {
        size_of::<InetRequestBuffer>()
    }

    fn emit(&self, buf: &mut [u8]) {
        let raw = InetRequestBuffer::from(self);
        buf.copy_from_slice(raw.as_bytes());
    }
}
