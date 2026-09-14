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
    /// A program started, and what started it.
    ///
    /// This is the question "what set this off". A program that appears on
    /// screen using the connection is only half an answer; the other half is
    /// that it was started by a browser, or by a scheduled task, or by
    /// something in a temp directory. Both halves have to be recorded as they
    /// happen — a parent is often gone by the time anyone asks, and `/proc`
    /// then says the process was started by init, which is true and useless.
    Started(Start),
}

/// One program starting, as the kernel reported it.
///
/// Everything here is gathered at the moment of the start, because most of it
/// cannot be gathered afterwards: a program that runs for a tenth of a second
/// is exactly the one worth knowing about, and by the time anything asks, its
/// command line and its path are gone.
#[derive(Clone, Debug)]
pub struct Start {
    pub pid: u32,
    pub parent: u32,
    /// The name it runs under. From the kernel at the moment it started, not
    /// looked up afterwards, because it may not last long enough to be found.
    pub name: String,
    pub parent_name: String,
    /// Where it was run from. The single most useful fact about a program:
    /// `svchost.exe` in System32 is the operating system, and the same name
    /// from a temp directory is not.
    pub path: String,
    /// The whole command, arguments and all.
    ///
    /// Often this *is* the story. A program called `sh` says nothing; `sh -c
    /// "curl http://… | sh"` says everything, and the name is the same in both
    /// cases.
    pub cmdline: String,
    /// Who it runs as. Empty where it could not be read.
    pub user: String,
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
