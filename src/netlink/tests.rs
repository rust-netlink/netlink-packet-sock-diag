// SPDX-License-Identifier: MIT

use crate::netlink::nlas::{MemInfo, RingInfo, StateFlags};
use crate::netlink::NetlinkResponseBuffer;
use crate::{
    constants::*,
    netlink::{
        nlas::Nla, NetlinkRequest, NetlinkResponse, NetlinkResponseHeader,
        ShowFlags,
    },
};
use netlink_packet_utils::traits::Emitable;
use netlink_packet_utils::Parseable;

lazy_static! {
    static ref SOCKET_INFO: NetlinkRequest = NetlinkRequest {
        protocol: NETLINK_ROUTE,
        inode: 0x1234,
        show_flags: ShowFlags::MEMINFO,
        cookie: [0xff; 8]
    };
}

#[rustfmt::skip]
static SOCKET_INFO_BUF: [u8; 20] = [
    0x10, // family: AF_NETLINK
    0x00, // protocol: NETLINK_ROUTE
    0x00, 0x00, // padding
    0x34, 0x12, 0x00, 0x00, // inode number
    0x01, 0x00, 0x00, 0x00, // show_flags - NDIAG_SHOW_MEMINFO
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // cookie
];

#[test]
fn emit_socket_info() {
    assert_eq!(SOCKET_INFO.buffer_len(), 20);
    let mut buf = vec![0xff; SOCKET_INFO.buffer_len()];
    SOCKET_INFO.emit(&mut buf);
    assert_eq!(&buf[..], &SOCKET_INFO_BUF[..]);
}

lazy_static! {
    static ref LISTENING: NetlinkResponse = NetlinkResponse {
        header: NetlinkResponseHeader {
            kind: SOCK_DGRAM,
            protocol: NETLINK_ROUTE,
            state: NETLINK_UNCONNECTED,
            portid: 0x5678,
            dst_portid: 0,
            dst_group: RTMGRP_LINK | RTMGRP_NEIGH,
            inode: 20238,
            cookie: [0xa0, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        },
        nlas: smallvec![
            // Use `IntoIterator::into_iter()` to explicitly iterate the array by value (see:
            // https://doc.rust-lang.org/std/primitive.array.html#editions). This could be replaced
            // with a call to `[...].into_iter()` once the crate is updated to edition 2021.
            Nla::Groups(IntoIterator::into_iter([RTNLGRP_LINK, RTNLGRP_NEIGH]).collect()),
            Nla::Flags(StateFlags::PKTINFO),
            Nla::RxRing(RingInfo {
                block_size: 16 * 1024,
                block_nr: 4,
                frame_size: 8 * 1024,
                frame_nr: 8
            }),
        ]
    };
}

#[rustfmt::skip]
static LISTENING_BUF: [u8; 64] = [
    0x10, // family: AF_NETLINK
    0x02, // kind: SOCK_DGRAM
    0x00, // protocol: NETLINK_ROUTE
    0x00, // state: NETLINK_UNCONNECTED
    0x78, 0x56, 0x00, 0x00, // portid
    0x00, 0x00, 0x00, 0x00, // dst_portid
    0x05, 0x00, 0x00, 0x00, // dst_group: RTMGRP_LINK | RTMGRP_NEIGH
    0x0e, 0x4f, 0x00, 0x00, // inode number
    0xa0, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // cookie

    // NLAs
   // 1. Groups
    0x08, 0x00, // length: 8
    0x01, 0x00, // type: NETLINK_DIAG_GROUPS
    0x05, 0x00, 0x00, 0x00, // value: RTNLGRP_LINK | RTNLGRP_NEIGH

    // 2. Flags
    0x08, 0x00, // length: 8
    0x04, 0x00, // type: NETLINK_DIAG_FLAGS
    0x02, 0x00, 0x00, 0x00, // value: NDIAG_FLAG_PKTINFO

    // 3. RxRing
    0x14, 0x00, // length: 20
    0x02, 0x00, // type: NETLINK_DIAG_RX_RING
    0x00, 0x40, 0x00, 0x00, // block_size
    0x04, 0x00, 0x00, 0x00, // block_nr
    0x00, 0x20, 0x00, 0x00, // frame_size
    0x08, 0x00, 0x00, 0x00, // frame_nr
];

#[test]
fn parse_listening() {
    let parsed = NetlinkResponse::parse(
        &NetlinkResponseBuffer::new_checked(&&LISTENING_BUF[..]).unwrap(),
    )
    .unwrap();
    assert_eq!(parsed, *LISTENING);
}

#[test]
fn emit_listening() {
    assert_eq!(LISTENING.buffer_len(), 64);
    // Initialize the buffer with 0xaa to check that padding bytes are set to 0.
    let mut buf = vec![0xaa; LISTENING.buffer_len()];
    LISTENING.emit(&mut buf);
    assert_eq!(&buf[..], &LISTENING_BUF[..]);
}

lazy_static! {
    static ref ESTABLISHED: NetlinkResponse = NetlinkResponse {
        header: NetlinkResponseHeader {
            kind: SOCK_RAW,
            protocol: NETLINK_ROUTE,
            state: NETLINK_CONNECTED,
            portid: 0x1234,
            dst_portid: 0,
            dst_group: 0,
            inode: 54321,
            cookie: [0xbb, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        },
        nlas: smallvec![
            Nla::MemInfo(MemInfo {
                rmem_alloc: 1024,
                rcvbuf: 8192,
                wmem_alloc: 2048,
                sndbuf: 16384,
                sk_optmem: 0,
                backlog: 5,
                drops: 1,
            }),
            Nla::TxRing(RingInfo {
                block_size: 4096,
                block_nr: 2,
                frame_size: 2048,
                frame_nr: 4
            }),
        ]
    };
}

#[rustfmt::skip]
static ESTABLISHED_BUF: [u8; 88] = [
    0x10, // family: AF_NETLINK
    0x03, // kind: SOCK_RAW
    0x00, // protocol: NETLINK_ROUTE
    0x01, // state: NETLINK_CONNECTED
    0x34, 0x12, 0x00, 0x00, // portid
    0x00, 0x00, 0x00, 0x00, // dst_portid
    0x00, 0x00, 0x00, 0x00, // dst_group
    0x31, 0xd4, 0x00, 0x00, // inode number
    0xbb, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // cookie

    // NLAs
    // 1. MemInfo
    0x28, 0x00, // length: 40
    0x00, 0x00, // type: NETLINK_DIAG_MEMINFO
    0x00, 0x04, 0x00, 0x00, // rmem_alloc
    0x00, 0x20, 0x00, 0x00, // rcvbuf
    0x00, 0x08, 0x00, 0x00, // wmem_alloc
    0x00, 0x40, 0x00, 0x00, // sndbuf
    0x00, 0x00, 0x00, 0x00, // unused_fwd_alloc
    0x00, 0x00, 0x00, 0x00, // unused_wmem_queued
    0x00, 0x00, 0x00, 0x00, // sk_optmem
    0x05, 0x00, 0x00, 0x00, // backlog
    0x01, 0x00, 0x00, 0x00, // drops

    // 2. TxRing
    0x14, 0x00, // length: 20
    0x03, 0x00, // type: NETLINK_DIAG_TX_RING
    0x00, 0x10, 0x00, 0x00, // block_size
    0x02, 0x00, 0x00, 0x00, // block_nr
    0x00, 0x08, 0x00, 0x00, // frame_size
    0x04, 0x00, 0x00, 0x00, // frame_nr
];

#[test]
fn parse_established() {
    let parsed = NetlinkResponse::parse(
        &NetlinkResponseBuffer::new_checked(&&ESTABLISHED_BUF[..]).unwrap(),
    )
    .unwrap();
    assert_eq!(parsed, *ESTABLISHED);
}

#[test]
fn emit_established() {
    assert_eq!(ESTABLISHED.buffer_len(), 88);
    // Initialize the buffer with 0xbb to check that padding bytes are set to 0.
    let mut buf = vec![0xbb; ESTABLISHED.buffer_len()];
    ESTABLISHED.emit(&mut buf);
    assert_eq!(&buf[..], &ESTABLISHED_BUF[..]);
}
