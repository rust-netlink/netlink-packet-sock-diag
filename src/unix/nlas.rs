// SPDX-License-Identifier: MIT

use std::{
    ffi::{CStr, OsString},
    mem::size_of,
    os::unix::ffi::{OsStrExt, OsStringExt},
};

use netlink_packet_core::{
    append_u32, parse_u32, parse_u8, DecodeError, DefaultNla, Emitable,
    ErrorContext, NlaBuffer, Parseable,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::constants::*;

use netlink_packet_core::{append_bytes, EncodeError};
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum UnixDiagName {
    /// Filesystem pathname to which the socket was bound.
    Pathname(OsString),
    /// Abstract socket address to which the socket was bound.
    Abstract(Vec<u8>),
}

impl<T: AsRef<[u8]>> Parseable<T> for UnixDiagName {
    fn parse(buf: &T) -> Result<Self, DecodeError> {
        let buf = buf.as_ref();
        if let Some((0, address)) = buf.split_first() {
            Ok(UnixDiagName::Abstract(address.to_owned()))
        } else {
            Ok(UnixDiagName::Pathname(OsString::from_vec(
                CStr::from_bytes_with_nul(buf)
                    .map_err(|e| {
                        DecodeError::from(format!(
                            "pathname is not null-terminated: {e}"
                        ))
                    })?
                    .to_owned()
                    .into(),
            )))
        }
    }
}

impl Emitable for UnixDiagName {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            UnixDiagName::Pathname(pathname) => {
                append_bytes(out, pathname.as_bytes());
                out.push(0);
            }
            UnixDiagName::Abstract(address) => {
                out.push(0);
                append_bytes(out, address);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Nla {
    /// Name to which the socket was bound. This attribute is known as
    /// `UNIX_DIAG_NAME` in the kernel.
    Name(UnixDiagName),
    /// VFS information for this socket. This attribute is known as
    /// `UNIX_DIAG_VFS` in the kernel.
    Vfs(Vfs),
    /// Inode number of the socket's peer. This attribute is reported
    /// for connected socket only. This attribute is known as
    /// `UNIX_DIAG_PEER` in the kernel.
    Peer(u32),
    /// The payload associated with this attribute is an array of
    /// inode numbers of sockets that have passed the `connect(2)`
    /// call, but haven't been processed with `accept(2)` yet. This
    /// attribute is reported for listening sockets only. This
    /// attribute is known as `UNIX_DIAG_ICONS` in the kernel.
    PendingConnections(Vec<u32>),
    /// This attribute corresponds to the `UNIX_DIAG_RQLEN`. Actual meaning of
    /// this attribute differs depending on the type of socket.
    ///
    /// For **listening** sockets:
    ///
    /// - the first the number is the number of pending connections. It should
    ///   be equal to `Nla::PendingConnections` value's length.
    /// - the second number is the backlog queue maximum length, which equals
    ///   to the value passed as the second argument to `listen(2)`
    ///
    /// For other sockets:
    ///
    /// - the first number is the amount of data in receive queue (**note**: I
    ///   am not sure if it is the actual amount of data or the amount of
    ///   memory allocated. The two might differ because of memory allocation
    ///   strategies: more memory than strictly necessary may be allocated for
    ///   a given `sk_buff`)
    /// - the second number is the memory used by outgoing data. Note that
    ///   strictly UNIX sockets don't have a send queue, since the data they
    ///   send is directly written into the destination socket receive queue.
    ///   But the memory allocated for this data is still counted from the
    ///   sender point of view.
    ReceiveQueueLength(u32, u32),
    /// Socket memory information. See [`MemInfo`] for more details.
    MemInfo(MemInfo),
    /// Shutown state: one of [`SHUT_RD`], [`SHUT_WR`] or [`SHUT_RDWR`]
    Shutdown(u8),
    /// Unknown attribute
    Other(DefaultNla),
}

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
pub struct VfsBuffer {
    inode: u32,
    device: u32,
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Vfs {
    /// Inode number
    inode: u32,
    /// Device number
    device: u32,
}

impl Vfs {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) = VfsBuffer::ref_from_prefix(payload).map_err(|_| {
            DecodeError::buffer_too_small(payload.len(), size_of::<VfsBuffer>())
        })?;
        Ok(Self {
            inode: raw.inode,
            device: raw.device,
        })
    }
}

impl From<&Vfs> for VfsBuffer {
    fn from(value: &Vfs) -> Self {
        Self {
            inode: value.inode,
            device: value.device,
        }
    }
}

impl Emitable for Vfs {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let raw = VfsBuffer::from(self);
        append_bytes(out, raw.as_bytes());
        Ok(())
    }
}

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
    unused_sk_rmem_alloc: u32,
    so_rcvbuf: u32,
    unused_sk_wmem_queued: u32,
    max_datagram_size: u32,
    unused_sk_fwd_alloc: u32,
    alloc: u32,
    unused_sk_optmem: u32,
    unused_backlog: u32,
    unused_drops: u32,
}

/// # Warning
///
/// I don't have a good understanding of the Unix Domain Sockets, thus
/// take the following documentation with a *huge* grain of salt.
///
/// # Documentation
///
/// ## `UNIX_DIAG_MEMINFO` vs `INET_DIAG_SK_MEMINFO`
///
/// `MemInfo` represent an `UNIX_DIAG_MEMINFO` NLA. This NLA has the
/// same structure than `INET_DIAG_SKMEMINFO`, but since Unix sockets
/// don't actually use the network stack, many fields are not relevant
/// and are always set to 0. According to iproute2 commit
/// [51ff9f2453d066933f24170f0106a7deeefa02d9](https://patchwork.ozlabs.org/patch/222700/), only three attributes can have non-zero values.
///
/// ## Particularities of UNIX sockets
///
/// One particularity of UNIX sockets is that they don't really have a
/// send queue: when sending data, the kernel finds the destination
/// socket and enqueues the data directly in its receive queue (which
/// [see also this StackOverflow
/// answer](https://stackoverflow.com/questions/9644251/how-do-unix-domain-sockets-differentiate-between-multiple-clients)). For
/// instance in `unix_dgram_sendmsg()` in `net/unix/af_unix.c` we
/// have:
///
/// ```c
/// // `other` refers to the peer socket here
/// skb_queue_tail(&other->sk_receive_queue, skb);
/// ```
///
/// Another particularity is that the kernel keeps track of the memory
/// using the sender's `sock.sk_wmem_alloc` attribute. The receiver's
/// `sock.sk_rmem_alloc` is always zero. Memory is allocated when data
/// is written to a socket, and is reclaimed when the data is read
/// from the peer's socket.
///
/// Last but not least, the way unix sockets handle incoming
/// connection differs from the TCP sockets. For TCP sockets, the
/// queue used to store pending connections is
/// `sock.sk_ack_backlog`. But UNIX sockets use the receive queue to
/// store them. They can do that because a listening socket only
/// receive connections, they do not receive actual data from other
/// socket, so there is no ambiguity about the nature of the data
/// stored in the receive queue.
// /// We can see that in `unix_stream_sendmsg()` for instance we have
// /// the follownig function calls:
// ///
// /// ```
// /// unix_stream_sendmsg()
// ///     -> sock_alloc_send_pskb()
// ///     -> skb_set_owner_w()
// ///     -> refcount_add(size, &sk->sk_wmem_alloc);
/// ```
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct MemInfo {
    /// Value of `SO_RCVBUF`, although it does not have any effect on
    /// Unix Domain Sockets. As per `man unix(7)`:
    ///
    /// > The `SO_SNDBUF` socket option does have an effect for UNIX
    /// > domain sockets, but the `SO_RCVBUF` option does not.
    ///
    /// This attribute corresponds to `sock.sk_rcvbuf` in the kernel.
    pub so_rcvbuf: u32,
    /// Maximum size in in bytes of a datagram, as set by
    /// `SO_SNDBUF`. As per `man unix(7)`:
    ///
    /// > For datagram sockets, the `SO_SNDBUF` value imposes an upper
    /// > limit on the size of outgoing datagrams. This limit is
    /// > calculated as the doubled (see `socket(7)`) option value
    /// > less 32 bytes used for overhead.
    ///
    /// This attribute corresponds to `sock.sk_sndbuf` in the kernel.
    pub max_datagram_size: u32,
    /// Memory currently allocated for the data sent but not yet read
    /// from the receiving socket(s). The memory is tracked using the
    /// sending socket `sock.sk_wmem_queued` attribute in the kernel.
    ///
    /// Note that this quantity is a little larger than the actual
    /// data being sent because it takes into account the overhead of
    /// the `sk_buff`s used internally:
    ///
    /// ```c
    /// /* in net/core/sock.c, sk_wmem_alloc is set in
    ///    skb_set_owner_w() with: */
    /// refcount_add(skb->truesize, &sk->sk_wmem_alloc);
    ///
    /// /* truesize is set by __alloc_skb() in net/core/skbuff.c
    ///    by: */
    /// skb->truesize = SKB_TRUESIZE(size);
    ///
    /// /* and SKB_TRUESIZE is defined as: */
    /// #define SKB_TRUESIZE(X) ((X) +                        \
    ///     SKB_DATA_ALIGN(sizeof(struct sk_buff)) +          \
    ///     SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))
    /// ```
    pub alloc: u32,
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
            so_rcvbuf: raw.so_rcvbuf,
            max_datagram_size: raw.max_datagram_size,
            alloc: raw.alloc,
        })
    }
}

impl From<&MemInfo> for MemInfoBuffer {
    fn from(value: &MemInfo) -> Self {
        Self {
            unused_sk_rmem_alloc: 0,
            so_rcvbuf: value.so_rcvbuf,
            unused_sk_wmem_queued: 0,
            max_datagram_size: value.max_datagram_size,
            unused_sk_fwd_alloc: 0,
            alloc: value.alloc,
            unused_sk_optmem: 0,
            unused_backlog: 0,
            unused_drops: 0,
        }
    }
}

impl Emitable for MemInfo {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let raw = MemInfoBuffer::from(self);
        append_bytes(out, raw.as_bytes());
        Ok(())
    }
}

impl netlink_packet_core::Nla for Nla {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        use self::Nla::*;
        match *self {
            Name(ref s) => s.emit(out)?,
            Vfs(ref value) => value.emit(out)?,
            Peer(value) => append_u32(out, value),
            PendingConnections(ref values) => {
                for v in values.iter() {
                    append_u32(out, *v);
                }
            }
            ReceiveQueueLength(v1, v2) => {
                append_u32(out, v1);
                append_u32(out, v2);
            }
            MemInfo(ref value) => value.emit(out)?,
            Shutdown(value) => out.push(value),
            Other(ref attr) => return attr.emit_value(out),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        use self::Nla::*;
        match *self {
            Name(_) => UNIX_DIAG_NAME,
            Vfs(_) => UNIX_DIAG_VFS,
            Peer(_) => UNIX_DIAG_PEER,
            PendingConnections(_) => UNIX_DIAG_ICONS,
            ReceiveQueueLength(_, _) => UNIX_DIAG_RQLEN,
            MemInfo(_) => UNIX_DIAG_MEMINFO,
            Shutdown(_) => UNIX_DIAG_SHUTDOWN,
            Other(ref attr) => attr.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for Nla {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            UNIX_DIAG_NAME => Self::Name(
                UnixDiagName::parse(&payload)
                    .context("invalid UNIX_DIAG_NAME value")?,
            ),
            UNIX_DIAG_VFS => {
                let err = "invalid UNIX_DIAG_VFS value";
                Self::Vfs(Vfs::parse(payload).context(err)?)
            }
            UNIX_DIAG_PEER => Self::Peer(
                parse_u32(payload).context("invalid UNIX_DIAG_PEER value")?,
            ),
            UNIX_DIAG_ICONS => {
                if !payload.len().is_multiple_of(4) {
                    return Err(DecodeError::from("invalid UNIX_DIAG_ICONS"));
                }
                Self::PendingConnections(
                    payload.chunks(4).map(|b| parse_u32(b).unwrap()).collect(),
                )
            }
            UNIX_DIAG_RQLEN => {
                if payload.len() != 8 {
                    return Err(DecodeError::from("invalid UNIX_DIAG_RQLEN"));
                }
                Self::ReceiveQueueLength(
                    parse_u32(&payload[..4])?,
                    parse_u32(&payload[4..])?,
                )
            }
            UNIX_DIAG_MEMINFO => {
                let err = "invalid UNIX_DIAG_MEMINFO value";
                Self::MemInfo(MemInfo::parse(payload).context(err)?)
            }
            UNIX_DIAG_SHUTDOWN => Self::Shutdown(
                parse_u8(payload)
                    .context("invalid UNIX_DIAG_SHUTDOWN value")?,
            ),
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind}"))?,
            ),
        })
    }
}
