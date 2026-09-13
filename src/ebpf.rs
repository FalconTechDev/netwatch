//! Reading the kernel on Linux.
//!
//! The counterpart to `etw` on Windows, and deliberately the same shape: hand
//! it a `Sender` and it produces the same `Event` stream from then on. The
//! program it loads lives in `netwatch-ebpf` and is compiled into this binary
//! at build time, so there is no object file to install, find, or get out of
//! step with the program that loads it.
//!
//! Loading anything into the kernel needs privilege. Run as root, or give the
//! binary `CAP_BPF` and `CAP_PERFMON`; without them the load fails with a
//! permission error and nothing else, which is why that is said plainly in the
//! message rather than left to be guessed.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::thread::JoinHandle;
use std::time::Duration;

use aya::maps::RingBuf;
use aya::programs::KProbe;

use netwatch_common::{DIR_SENT, FAMILY_V6, PROTO_UDP, RawTransfer};

use crate::event::{Dir, Event, Proto, Transfer};

/// The kernel functions the two probes attach to. Named here rather than at
/// the point of use so that the pair reads as one decision: every TCP byte in
/// the system passes through one of these.
const PROBES: [(&str, &str); 2] = [
    ("tcp_sendmsg", "tcp_sendmsg"),
    ("tcp_cleanup_rbuf", "tcp_cleanup_rbuf"),
];

/// A running trace. Dropping it — or calling `stop` — detaches the probes and
/// the kernel goes back to doing nothing extra.
pub struct Session {
    /// Holding the loaded program keeps the probes attached; when this is
    /// dropped the kernel unloads them.
    _ebpf: aya::Ebpf,
    stop: Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
}

impl Session {
    pub fn stop(mut self) -> Result<(), String> {
        self.shutdown();
        Ok(())
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.reader.take() {
            let _ = h.join();
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Load the program, attach both probes, and start turning what they report
/// into events.
pub fn start(tx: Sender<Event>) -> Result<Session, String> {
    raise_memlock();

    // The eBPF object is embedded at build time by `build.rs`.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/netwatch"
    )))
    .map_err(|e| {
        format!(
            "could not load the eBPF program: {e}\n\n\
             This needs privilege. Run it with sudo, or grant the binary \
             CAP_BPF and CAP_PERFMON."
        )
    })?;

    tell_kernel_our_namespace(&mut ebpf)?;

    for (program, function) in PROBES {
        let probe: &mut KProbe = ebpf
            .program_mut(program)
            .ok_or_else(|| format!("the eBPF object has no program named {program}"))?
            .try_into()
            .map_err(|e| format!("{program} is not a kprobe: {e}"))?;
        probe
            .load()
            .map_err(|e| format!("could not load {program}: {e}"))?;
        probe.attach(function, 0).map_err(|e| {
            format!(
                "could not attach to {function}: {e}\n\n\
                 The kernel may not have that function, which happens on \
                 kernels built without it."
            )
        })?;
    }

    let ring = RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .ok_or_else(|| "the eBPF object has no EVENTS map".to_string())?,
    )
    .map_err(|e| format!("EVENTS is not a ring buffer: {e}"))?;

    let stop = Arc::new(AtomicBool::new(false));
    let reader = std::thread::spawn({
        let stop = Arc::clone(&stop);
        move || read_loop(ring, tx, stop)
    });

    Ok(Session {
        _ebpf: ebpf,
        stop,
        reader: Some(reader),
    })
}

/// Tell the eBPF program which pid namespace to count in: this one.
///
/// Without this it reports the kernel's own numbering, which inside a
/// container — and WSL is one — names nothing that `/proc` or `ps` can find.
/// The numbers would look perfectly reasonable and refer to other processes
/// entirely, so this is not a refinement; it is the difference between a pid
/// that can be looked up and one that quietly cannot.
fn tell_kernel_our_namespace(ebpf: &mut aya::Ebpf) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    let md = std::fs::metadata("/proc/self/ns/pid")
        .map_err(|e| format!("could not read this process's pid namespace: {e}"))?;

    let mut ns: aya::maps::Array<_, u64> = ebpf
        .map_mut("PIDNS")
        .ok_or_else(|| "the eBPF object has no PIDNS map".to_string())?
        .try_into()
        .map_err(|e| format!("PIDNS is not an array: {e}"))?;

    ns.set(0, md.dev(), 0)
        .map_err(|e| format!("could not set the namespace device: {e}"))?;
    ns.set(1, md.ino(), 0)
        .map_err(|e| format!("could not set the namespace inode: {e}"))?;
    Ok(())
}

/// Drain the ring buffer for as long as the session lasts.
///
/// It sleeps only when there was nothing to read. Draining fully before
/// sleeping matters: the kernel drops events it cannot fit, so time spent
/// asleep with a full buffer is measurement lost, and a burst is exactly when
/// it would be lost.
fn read_loop(mut ring: RingBuf<aya::maps::MapData>, tx: Sender<Event>, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Relaxed) {
        let mut moved = false;
        while let Some(item) = ring.next() {
            moved = true;
            if let Some(ev) = decode(&item) {
                // The receiver going away means the program is shutting down;
                // there is nobody left to tell.
                if tx.send(ev).is_err() {
                    return;
                }
            }
        }
        if !moved {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

/// Turn the bytes the kernel wrote into an event, or nothing if they are not
/// the size they should be.
fn decode(raw: &[u8]) -> Option<Event> {
    if raw.len() < size_of::<RawTransfer>() {
        return None;
    }
    // SAFETY: the length is checked above, and the kernel side writes exactly
    // this `repr(C)` type into the ring buffer. `read_unaligned` because the
    // ring buffer only guarantees 8-byte alignment of the record start.
    let t: RawTransfer = unsafe { std::ptr::read_unaligned(raw.as_ptr().cast()) };

    Some(Event::Transfer(Transfer {
        pid: t.pid,
        proto: if t.proto == PROTO_UDP {
            Proto::Udp
        } else {
            Proto::Tcp
        },
        dir: if t.dir == DIR_SENT {
            Dir::Sent
        } else {
            Dir::Received
        },
        bytes: t.bytes,
        peer: peer_addr(&t),
        peer_port: t.port,
    }))
}

fn peer_addr(t: &RawTransfer) -> IpAddr {
    if t.family == FAMILY_V6 {
        IpAddr::V6(Ipv6Addr::from(t.addr))
    } else {
        IpAddr::V4(Ipv4Addr::new(t.addr[0], t.addr[1], t.addr[2], t.addr[3]))
    }
}

/// Older kernels charge eBPF maps against the locked-memory limit, which is a
/// few megabytes by default and not enough. Newer ones account for it properly
/// and ignore this. Failing to raise it is not worth reporting: the load that
/// follows will fail with a message that names the real problem.
fn raise_memlock() {
    let lim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: `lim` is a valid, fully initialised rlimit for the duration of
    // the call.
    unsafe {
        libc::setrlimit(libc::RLIMIT_MEMLOCK, &lim);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netwatch_common::{DIR_RECEIVED, FAMILY_V4, PROTO_TCP};

    fn raw(dir: u8, proto: u8, bytes: u64, family: u8, addr: [u8; 16], port: u16) -> Vec<u8> {
        let t = RawTransfer {
            bytes,
            pid: 1234,
            addr,
            port,
            proto,
            dir,
            family,
            _pad: [0; 7],
        };
        // SAFETY: RawTransfer is repr(C) and plain data, so its bytes are a
        // faithful representation of it — which is the property the kernel
        // side relies on too.
        unsafe {
            std::slice::from_raw_parts(
                (&t as *const RawTransfer).cast::<u8>(),
                size_of::<RawTransfer>(),
            )
        }
        .to_vec()
    }

    /// The decoder and the kernel struct have to agree byte for byte. If they
    /// drift, nothing fails to compile — the numbers just come out wrong — so
    /// this pins the round trip.
    #[test]
    fn a_record_survives_the_crossing() {
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&[192, 168, 1, 10]);
        let bytes = raw(DIR_SENT, PROTO_TCP, 4096, FAMILY_V4, a, 443);

        let Some(Event::Transfer(t)) = decode(&bytes) else {
            panic!("did not decode to a transfer");
        };
        assert_eq!(t.pid, 1234);
        assert_eq!(t.bytes, 4096);
        assert_eq!(t.dir, Dir::Sent);
        assert_eq!(t.proto, Proto::Tcp);
        assert_eq!(t.peer_port, 443);
        assert_eq!(t.peer, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
    }

    #[test]
    fn the_receive_direction_and_v6_are_read_too() {
        let a = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let bytes = raw(DIR_RECEIVED, PROTO_UDP, 99, FAMILY_V6, a, 53);

        let Some(Event::Transfer(t)) = decode(&bytes) else {
            panic!("did not decode to a transfer");
        };
        assert_eq!(t.dir, Dir::Received);
        assert_eq!(t.proto, Proto::Udp);
        assert_eq!(t.peer, IpAddr::V6(Ipv6Addr::from(a)));
    }

    /// A short read is a bug somewhere else, but it must not be read past.
    #[test]
    fn a_truncated_record_is_refused() {
        assert!(decode(&[0u8; 4]).is_none());
    }
}
