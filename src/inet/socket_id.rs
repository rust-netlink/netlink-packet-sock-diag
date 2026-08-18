// SPDX-License-Identifier: MIT

use std::{
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use netlink_packet_core::{DecodeError, Emitable, ParseableParametrized};
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
pub struct SocketIdBuffer {
    source_port: u16,
    destination_port: u16,
    source_address: [u8; 16],
    destination_address: [u8; 16],
    interface_id: u32,
    cookie: [u8; 8],
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SocketId {
    pub source_port: u16,
    pub destination_port: u16,
    pub source_address: IpAddr,
    pub destination_address: IpAddr,
    pub interface_id: u32,
    /// An array of opaque identifiers that could be used along with
    /// other fields of this structure to specify an individual
    /// socket. It is ignored when querying for a list of sockets, as
    /// well as when all its elements are set to `0xff`.
    pub cookie: [u8; 8],
}

impl SocketId {
    pub fn new_v4() -> Self {
        Self {
            source_port: 0,
            destination_port: 0,
            source_address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            destination_address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            interface_id: 0,
            cookie: [0; 8],
        }
    }
    pub fn new_v6() -> Self {
        Self {
            source_port: 0,
            destination_port: 0,
            source_address: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
            destination_address: IpAddr::V6(Ipv6Addr::new(
                0, 0, 0, 0, 0, 0, 0, 0,
            )),
            interface_id: 0,
            cookie: [0; 8],
        }
    }
}

impl ParseableParametrized<[u8], u8> for SocketId {
    fn parse_with_param(payload: &[u8], af: u8) -> Result<Self, DecodeError> {
        let (raw, _) =
            SocketIdBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<SocketIdBuffer>(),
                )
            })?;

        let (source_address, destination_address) = match af {
            AF_INET => {
                let source = IpAddr::V4(Ipv4Addr::new(
                    raw.source_address[0],
                    raw.source_address[1],
                    raw.source_address[2],
                    raw.source_address[3],
                ));
                let destination = IpAddr::V4(Ipv4Addr::new(
                    raw.destination_address[0],
                    raw.destination_address[1],
                    raw.destination_address[2],
                    raw.destination_address[3],
                ));
                (source, destination)
            }
            AF_INET6 => {
                let source = IpAddr::V6(Ipv6Addr::from(raw.source_address));
                let destination =
                    IpAddr::V6(Ipv6Addr::from(raw.destination_address));
                (source, destination)
            }
            _ => {
                return Err(DecodeError::from(format!(
                    "unsupported address family {af}: expected AF_INET ({AF_INET}) or AF_INET6 ({AF_INET6})"
                )));
            }
        };

        Ok(Self {
            source_port: u16::from_be(raw.source_port),
            destination_port: u16::from_be(raw.destination_port),
            source_address,
            destination_address,
            interface_id: raw.interface_id,
            cookie: raw.cookie,
        })
    }
}

impl From<&SocketId> for SocketIdBuffer {
    fn from(value: &SocketId) -> Self {
        let mut source_address = [0u8; 16];
        match value.source_address {
            IpAddr::V4(ip) => source_address[..4].copy_from_slice(&ip.octets()),
            IpAddr::V6(ip) => source_address.copy_from_slice(&ip.octets()),
        }

        let mut destination_address = [0u8; 16];
        match value.destination_address {
            IpAddr::V4(ip) => {
                destination_address[..4].copy_from_slice(&ip.octets())
            }
            IpAddr::V6(ip) => destination_address.copy_from_slice(&ip.octets()),
        }

        Self {
            source_port: value.source_port.to_be(),
            destination_port: value.destination_port.to_be(),
            source_address,
            destination_address,
            interface_id: value.interface_id,
            cookie: value.cookie,
        }
    }
}

impl Emitable for SocketId {
    fn buffer_len(&self) -> usize {
        size_of::<SocketIdBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = SocketIdBuffer::from(self);
        buffer.copy_from_slice(raw.as_bytes());
    }
}
