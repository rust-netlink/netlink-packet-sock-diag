// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, EncodeError, ErrorContext, NetlinkDeserializable,
    NetlinkHeader, NetlinkMessagePayload, NetlinkPayload, Parseable,
    ParseableParametrized,
};

use crate::constants::*;
use crate::{inet, unix, SOCK_DESTROY, SOCK_DIAG_BY_FAMILY};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SockDiagMessage {
    InetRequest(inet::InetRequest),
    InetResponse(Box<inet::InetResponse>),
    UnixRequest(unix::UnixRequest),
    UnixResponse(Box<unix::UnixResponse>),
}

impl SockDiagMessage {
    pub fn is_inet_request(&self) -> bool {
        matches!(self, SockDiagMessage::InetRequest(_))
    }

    pub fn is_inet_response(&self) -> bool {
        matches!(self, SockDiagMessage::InetResponse(_))
    }
    pub fn is_unix_request(&self) -> bool {
        matches!(self, SockDiagMessage::UnixRequest(_))
    }

    pub fn is_unix_response(&self) -> bool {
        matches!(self, SockDiagMessage::UnixResponse(_))
    }

    pub fn message_type(&self) -> u16 {
        SOCK_DIAG_BY_FAMILY
    }
}

impl ParseableParametrized<[u8], u16> for SockDiagMessage {
    fn parse_with_param(
        buf: &[u8],
        message_type: u16,
    ) -> Result<Self, DecodeError> {
        use self::SockDiagMessage::*;

        if buf.len() < 2 {
            return Err(format!(
                "invalid buffer: length is {} but packets are at least 2 bytes",
                buf.len()
            )
            .into());
        }

        let message = match (message_type, buf[0]) {
            (SOCK_DIAG_BY_FAMILY, AF_INET) => {
                let err = "invalid AF_INET response";
                InetResponse(Box::new(
                    inet::InetResponse::parse(buf).context(err)?,
                ))
            }
            (SOCK_DIAG_BY_FAMILY, AF_INET6) => {
                let err = "invalid AF_INET6 response";
                InetResponse(Box::new(
                    inet::InetResponse::parse(buf).context(err)?,
                ))
            }
            (SOCK_DIAG_BY_FAMILY, AF_UNIX) => {
                let err = "invalid AF_UNIX response";
                UnixResponse(Box::new(
                    unix::UnixResponse::parse(buf).context(err)?,
                ))
            }
            (SOCK_DIAG_BY_FAMILY, af) => {
                return Err(format!("unknown address family {af}").into())
            }
            _ => {
                return Err(
                    format!("unknown message type {message_type}").into()
                )
            }
        };
        Ok(message)
    }
}

impl Emitable for SockDiagMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        use SockDiagMessage::*;

        match self {
            InetRequest(ref msg) => msg.emit(out)?,
            InetResponse(ref msg) => msg.emit(out)?,
            UnixRequest(ref msg) => msg.emit(out)?,
            UnixResponse(ref msg) => msg.emit(out)?,
        }
        Ok(())
    }
}

impl NetlinkMessagePayload for SockDiagMessage {
    fn message_type(&self) -> u16 {
        SockDiagMessage::message_type(self)
    }
}

impl NetlinkDeserializable for SockDiagMessage {
    fn deserialize(
        header: &NetlinkHeader,
        payload: &[u8],
    ) -> Result<Self, DecodeError> {
        SockDiagMessage::parse_with_param(payload, header.message_type)
    }
}

impl From<SockDiagMessage> for NetlinkPayload<SockDiagMessage> {
    fn from(message: SockDiagMessage) -> Self {
        NetlinkPayload::InnerMessage(message)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SockDiagDestroy(SockDiagMessage);

impl SockDiagDestroy {
    pub fn new(message: SockDiagMessage) -> SockDiagDestroy {
        SockDiagDestroy(message)
    }
}

impl Emitable for SockDiagDestroy {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.0.emit(out)
    }
}

impl NetlinkMessagePayload for SockDiagDestroy {
    fn message_type(&self) -> u16 {
        SOCK_DESTROY
    }
}

impl NetlinkDeserializable for SockDiagDestroy {
    fn deserialize(
        header: &NetlinkHeader,
        payload: &[u8],
    ) -> Result<Self, DecodeError> {
        Ok(SockDiagDestroy::new(SockDiagMessage::deserialize(
            header, payload,
        )?))
    }
}

impl From<SockDiagDestroy> for NetlinkPayload<SockDiagDestroy> {
    fn from(message: SockDiagDestroy) -> Self {
        NetlinkPayload::InnerMessage(message)
    }
}
