//! What a data source reports, in terms that have nothing to do with how it
//! was measured.
//!
//! Windows answers this question through ETW and Linux through eBPF, and the
//! two have nothing in common but the answer. Everything above them — the
//! aggregation, the log, the reports, the live view — is written against these
//! types and does not know which kernel it is reading. Adding a third source
//! means writing a producer of `Event` and nothing else.

use std::net::IpAddr;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dir {
    /// Out of this machine.
    Sent,
    /// Into it.
    Received,
}

/// Anything the kernel told us, in the order it said it.
///
/// Names and transfers share one channel deliberately: a DNS answer arrives
/// before the traffic that follows it, and one ordered stream keeps it that
/// way. Two channels would race, and a peer would be named a moment after it
/// first appeared on screen.
#[derive(Clone, Debug)]
pub enum Event {
    Transfer(Transfer),
    /// An address the machine looked up, and the name it asked for.
    Named {
        addr: IpAddr,
        host: String,
    },
}

/// One send or receive, as the kernel reported it.
#[derive(Clone, Copy, Debug)]
pub struct Transfer {
    pub pid: u32,
    pub proto: Proto,
    pub dir: Dir,
    pub bytes: u64,
    /// The other end. For a send this is where it went; for a receive, where
    /// it came from — a source that names both fields from the packet's point
    /// of view must normalise them to mean "the peer".
    pub peer: IpAddr,
    pub peer_port: u16,
}
