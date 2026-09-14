//! The one struct that crosses from the kernel into this program.
//!
//! It is `no_std` because the eBPF side has no standard library, and `repr(C)`
//! with every field explicitly placed because both sides must agree on the
//! bytes exactly — the kernel writes them into a ring buffer and userspace
//! reads them straight back out. A field reordered on one side only would not
//! fail to compile; it would quietly report the wrong numbers.
//!
//! Fields are ordered widest-first so the layout has no padding the compiler
//! had to invent, which is one fewer thing for the two sides to disagree on.

#![no_std]

pub const PROTO_TCP: u8 = 0;
pub const PROTO_UDP: u8 = 1;

pub const DIR_SENT: u8 = 0;
pub const DIR_RECEIVED: u8 = 1;

pub const FAMILY_V4: u8 = 4;
pub const FAMILY_V6: u8 = 6;

/// Where the eBPF program finds the offsets of the `struct sock` fields it
/// reads. The program that loads it looks them up in the running kernel's own
/// BTF and writes them here before attaching anything, because the offsets
/// differ between kernel builds and a guess would be read as an answer.
///
/// Slot `READY` is written last and gates the rest: a program that started
/// before the offsets arrived must report no peer rather than read address
/// zero and call it one.
pub mod sock {
    pub const READY: u32 = 0;
    pub const FAMILY: u32 = 1;
    pub const DADDR: u32 = 2;
    pub const DPORT: u32 = 3;
    pub const DADDR6: u32 = 4;
    /// How many slots the map needs.
    pub const SLOTS: u32 = 5;

    /// Written in place of an offset for a field this kernel does not have,
    /// such as `skc_v6_daddr` on a build without IPv6. It has to be a value no
    /// real offset can take: zero is a perfectly ordinary offset.
    pub const NO_FIELD: u64 = u64::MAX;
}

/// The address families as the kernel numbers them, which is not the same
/// numbering this program uses on the wire to userspace.
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

/// One send or receive, as the kernel saw it happen.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawTransfer {
    /// How much moved, in bytes.
    pub bytes: u64,
    /// The process the kernel charged it to.
    pub pid: u32,
    /// The peer's address, in network byte order. IPv4 uses the first four
    /// bytes; the rest are zero and `family` says which to read.
    pub addr: [u8; 16],
    /// The peer's port, in host byte order — converted in the kernel, where
    /// the value came from, rather than left for the reader to remember.
    pub port: u16,
    pub proto: u8,
    pub dir: u8,
    pub family: u8,
    pub _pad: [u8; 7],
}
