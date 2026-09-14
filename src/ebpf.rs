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
use aya::programs::uprobe::UProbeScope;
use aya::programs::{KProbe, UProbe};

use netwatch_common::{
    DIR_SENT, FAMILY_V6, KIND_DNS, KIND_FILE, KIND_NAME, KIND_START, KIND_TRANSFER, PROTO_UDP,
    RawDns, RawFile, RawName, RawStart, RawTransfer, sock,
};

use crate::event::{Dir, Event, Proto, Start, Transfer};

/// The programs in the object, and the kernel function each attaches to.
/// Listed here rather than at the point of use so the set reads as one
/// decision: every byte in the system passes through one of these.
const PROBES: [(&str, &str); 5] = [
    ("tcp_sendmsg", "tcp_sendmsg"),
    ("tcp_cleanup_rbuf", "tcp_cleanup_rbuf"),
    ("udp_sendmsg", "udp_sendmsg"),
    ("udpv6_sendmsg", "udpv6_sendmsg"),
    ("skb_consume_udp", "skb_consume_udp"),
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
    tell_kernel_where_its_fields_are(&mut ebpf);

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

    attach_name_lookups(&mut ebpf);
    attach_exec(&mut ebpf);
    attach_writes(&mut ebpf);

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

/// Watch files being opened for writing.
///
/// Failing is not fatal: everything else still works, and what a program wrote
/// is simply not known. Said once rather than silently.
fn attach_writes(ebpf: &mut aya::Ebpf) {
    let program: Option<&mut aya::programs::TracePoint> = ebpf
        .program_mut("sys_enter_openat")
        .and_then(|p| p.try_into().ok());
    let Some(program) = program else {
        eprintln!("netwatch: what programs write will not be shown — no openat program");
        return;
    };
    if let Err(e) = program.load() {
        eprintln!("netwatch: what programs write will not be shown — {e}");
        return;
    }
    if let Err(e) = program.attach("syscalls", "sys_enter_openat") {
        eprintln!("netwatch: what programs write will not be shown — {e}");
    }
}

/// Watch programs start, so that what set some traffic off can be shown
/// beside the traffic itself.
///
/// Failing is not fatal: the traffic is still measured, and the chain is
/// simply not known. Said once rather than silently, because an empty chain
/// otherwise reads as "nothing started anything".
fn attach_exec(ebpf: &mut aya::Ebpf) {
    let program: Option<&mut aya::programs::TracePoint> = ebpf
        .program_mut("sched_process_exec")
        .and_then(|p| p.try_into().ok());
    let Some(program) = program else {
        eprintln!("netwatch: what started what will not be shown — no exec program");
        return;
    };
    if let Err(e) = program.load() {
        eprintln!("netwatch: what started what will not be shown — {e}");
        return;
    }
    if let Err(e) = program.attach("sched", "sched_process_exec") {
        eprintln!("netwatch: what started what will not be shown — {e}");
    }
}

/// Watch the C library resolve names, so a peer can be shown as the name the
/// machine asked for rather than as the address it got back.
///
/// This is the counterpart to the DNS provider netwatch reads on Windows, and
/// it makes the same promise: a name on screen is one a program here actually
/// looked up. It is not a reverse lookup, which would invent a name the
/// traffic never mentioned.
///
/// Failing is not fatal — peers simply stay addresses, which is what they were
/// a moment ago. It is reported once rather than silently, because "no names
/// appeared" is otherwise indistinguishable from "nothing was looked up".
///
/// What it cannot see: a program that does not use the C library's resolver —
/// a statically linked Go binary, most obviously, which carries its own.
fn attach_name_lookups(ebpf: &mut aya::Ebpf) {
    const LIBC: &str = "libc";

    for (program, entry) in [("getaddrinfo", true), ("getaddrinfo_ret", false)] {
        let probe: Option<&mut UProbe> = ebpf.program_mut(program).and_then(|p| p.try_into().ok());
        let Some(probe) = probe else {
            eprintln!("netwatch: peers will stay addresses — no {program} program");
            return;
        };
        if let Err(e) = probe.load() {
            eprintln!("netwatch: peers will stay addresses — could not load {program}: {e}");
            return;
        }
        // Attached by symbol in the C library rather than by a path, so it
        // follows wherever this distribution keeps it, and for every process
        // rather than one.
        if let Err(e) = probe.attach("getaddrinfo", LIBC, UProbeScope::AllProcesses) {
            let _ = entry;
            eprintln!("netwatch: peers will stay addresses — could not watch getaddrinfo: {e}");
            return;
        }
    }
}

/// Tell the eBPF program where this kernel keeps the `struct sock` fields it
/// reads, by looking them up in the kernel's own BTF.
///
/// Failing is not fatal. Without the offsets the program reports no peer, and
/// the byte counts and processes — which is most of what netwatch is for —
/// are unaffected. Refusing to start at all over a missing address would trade
/// a partial answer for none.
///
/// This is called before the probes are attached, and the ready flag is
/// written last, so a probe can never run against half a set of offsets.
fn tell_kernel_where_its_fields_are(ebpf: &mut aya::Ebpf) {
    let btf = match crate::btf::Btf::from_running_kernel() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("netwatch: peers will be unnamed — {e}");
            return;
        }
    };

    let at = |field: &str| btf.offset_of("sock", &["__sk_common", field]);
    let (family, daddr, dport) = match (at("skc_family"), at("skc_daddr"), at("skc_dport")) {
        (Ok(f), Ok(d), Ok(p)) => (f, d, p),
        _ => {
            eprintln!(
                "netwatch: this kernel's struct sock is not shaped as expected;                  traffic will be reported without peer addresses."
            );
            return;
        }
    };
    // A kernel built without IPv6 has no such field, which is not a problem
    // until an IPv6 socket appears — and on such a kernel none will. The
    // sentinel is shared with the eBPF side so it cannot be read as an offset;
    // zero would have been a plausible one.
    let daddr6 = at("skc_v6_daddr")
        .map(u64::from)
        .unwrap_or(netwatch_common::sock::NO_FIELD);

    // Where a received packet's bytes begin. Without it a reply cannot be
    // read, and programs that carry their own resolver keep unnamed peers —
    // which is a smaller loss than reading the wrong memory.
    let skb_data = btf
        .offset_of("sk_buff", &["data"])
        .map(u64::from)
        .unwrap_or(netwatch_common::sock::NO_FIELD);

    let mut map: aya::maps::Array<_, u64> = match ebpf.map_mut("SOCK").map(TryInto::try_into) {
        Some(Ok(m)) => m,
        _ => {
            eprintln!("netwatch: the eBPF object has no usable SOCK map");
            return;
        }
    };

    let slots = [
        (sock::FAMILY, family as u64),
        (sock::DADDR, daddr as u64),
        (sock::DPORT, dport as u64),
        (sock::DADDR6, daddr6),
        (sock::SKB_DATA, skb_data),
    ];
    for (slot, value) in slots {
        if let Err(e) = map.set(slot, value, 0) {
            eprintln!("netwatch: could not pass a field offset to the kernel: {e}");
            return;
        }
    }
    // Last, and only once every offset above is in place.
    let _ = map.set(sock::READY, 1, 0);
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
            if item.first().copied() == Some(KIND_DNS) {
                for ev in decode_dns(&item) {
                    if tx.send(ev).is_err() {
                        return;
                    }
                }
                continue;
            }
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

/// Turn the bytes the kernel wrote into an event.
///
/// Two kinds of record share the buffer, and the first byte says which. A
/// record of the wrong length for what it claims to be is dropped rather than
/// read: the alternative is reading whatever follows it as an address.
fn decode(raw: &[u8]) -> Option<Event> {
    match raw.first().copied()? {
        KIND_TRANSFER => decode_transfer(raw),
        KIND_NAME => decode_name(raw),
        KIND_START => decode_start(raw),
        KIND_FILE => decode_file(raw),
        // A reply carries many answers, and `decode` returns one event, so the
        // caller handles this kind itself.
        _ => None,
    }
}

/// Every name-to-address pairing in a captured DNS reply.
///
/// Separate from `decode` because one reply commonly answers with several
/// addresses, and collapsing them to one would leave most of a CDN unnamed.
fn decode_dns(raw: &[u8]) -> Vec<Event> {
    if raw.len() < size_of::<RawDns>() {
        return Vec::new();
    }
    // SAFETY: length checked above; the kernel side writes exactly this
    // `repr(C)` type. `read_unaligned` because the ring buffer only promises
    // 8-byte alignment of the record start.
    let d: RawDns = unsafe { std::ptr::read_unaligned(raw.as_ptr().cast()) };

    let len = (d.len as usize).min(d.data.len());
    let payload = &d.data[..len];

    // Where the reply begins relative to what the kernel handed over differs
    // by kernel path: here the UDP header has already been pulled, and on
    // another it may not have been. Both are tried because the parser is
    // strict — it checks the reply bit, the response code and the record
    // counts — so a wrong start yields nothing rather than nonsense.
    let mut got = crate::dns::wire::answers(payload);
    if got.is_empty() && len > 8 {
        got = crate::dns::wire::answers(&payload[8..]);
    }

    got.into_iter()
        .map(|(host, addr)| Event::Named { addr, host })
        .collect()
}

/// A file a program opened for writing.
fn decode_file(raw: &[u8]) -> Option<Event> {
    if raw.len() < size_of::<RawFile>() {
        return None;
    }
    // SAFETY: length checked above; the kernel side writes exactly this
    // `repr(C)` type. `read_unaligned` because the ring buffer only promises
    // 8-byte alignment of the record start.
    let f: RawFile = unsafe { std::ptr::read_unaligned(raw.as_ptr().cast()) };

    let len = (f.len as usize).min(f.path.len());
    if len == 0 {
        return None;
    }
    // The helper writes a terminator inside the length it reports, so drop it
    // rather than carrying a stray NUL into a string.
    let bytes = &f.path[..len];
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    if bytes.is_empty() {
        return None;
    }

    let mut path = String::from_utf8_lossy(bytes).into_owned();
    if f.truncated != 0 {
        path.push('…');
    }
    Some(Event::Wrote { pid: f.pid, path })
}

/// A program started. The kernel says which and what it is called; who started
/// it is asked of `/proc`, which counts parents in this namespace where the
/// kernel counts them in its own.
///
/// The parent is read now, while the event is fresh, because a process that
/// lives a fraction of a second is exactly the one worth knowing the parent
/// of — and a moment later there is nothing left to ask.
fn decode_start(raw: &[u8]) -> Option<Event> {
    if raw.len() < size_of::<RawStart>() {
        return None;
    }
    // SAFETY: length checked above; the kernel side writes exactly this
    // `repr(C)` type. `read_unaligned` because the ring buffer only promises
    // 8-byte alignment of the record start.
    let s: RawStart = unsafe { std::ptr::read_unaligned(raw.as_ptr().cast()) };

    let len = s.len as usize;
    if len == 0 || len > s.comm.len() {
        return None;
    }
    let comm = String::from_utf8_lossy(&s.comm[..len]).into_owned();

    let (parent, parent_name) = parent_of(s.pid);
    let path = exe_path(s.pid).unwrap_or_default();
    Some(Event::Started(Start {
        // The path is preferred where it can still be read: the kernel cuts a
        // name at fifteen characters, so `comm` alone turns two different
        // programs into the same one.
        name: file_name(&path).unwrap_or(comm),
        pid: s.pid,
        parent,
        parent_name,
        path,
        cmdline: cmdline_of(s.pid),
        user: user_of(s.pid),
    }))
}

/// Where a running process was run from, or nothing if it has already gone.
fn exe_path(pid: u32) -> Option<String> {
    let path = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    Some(path.to_string_lossy().into_owned())
}

fn file_name(path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    Some(
        std::path::Path::new(path)
            .file_name()?
            .to_string_lossy()
            .into_owned(),
    )
}

/// The file name of a running process, or nothing if it has already gone.
fn exe_name(pid: u32) -> Option<String> {
    file_name(&exe_path(pid)?)
}

/// The whole command a process was given.
///
/// `/proc/<pid>/cmdline` separates the arguments with NUL bytes, which is what
/// makes it trustworthy: an argument containing a space is still one argument,
/// where a command line reassembled from a string is a guess.
fn cmdline_of(pid: u32) -> String {
    /// Long enough to show the shape of any command worth reading.
    const MAX: usize = 2048;

    let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return String::new();
    };
    let mut out = String::new();
    for arg in raw.split(|b| *b == 0).filter(|a| !a.is_empty()) {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&String::from_utf8_lossy(arg));
        if out.len() >= MAX {
            out.truncate(MAX);
            out.push('…');
            break;
        }
    }
    out
}

/// Who a process runs as, by name where `/etc/passwd` knows it.
///
/// The real uid rather than the effective one: it says who set this off, which
/// is the question, where the effective uid says what it is allowed to do.
fn user_of(pid: u32) -> String {
    let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
        return String::new();
    };
    let Some(uid) = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse::<u32>().ok())
    else {
        return String::new();
    };
    user_name(uid).unwrap_or_else(|| format!("uid {uid}"))
}

/// A user id turned into a name, from `/etc/passwd`.
///
/// Read once and kept: it is the same answer every time, and this is called
/// for every program that starts.
fn user_name(uid: u32) -> Option<String> {
    use std::collections::HashMap;
    use std::sync::OnceLock;

    static USERS: OnceLock<HashMap<u32, String>> = OnceLock::new();
    let users = USERS.get_or_init(|| {
        let mut map = HashMap::new();
        if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
            for line in passwd.lines() {
                let mut f = line.split(':');
                if let (Some(name), Some(_), Some(id)) = (f.next(), f.next(), f.next())
                    && let Ok(id) = id.parse::<u32>()
                {
                    map.insert(id, name.to_owned());
                }
            }
        }
        map
    });
    users.get(&uid).cloned()
}

/// Who started a process, from `/proc/<pid>/status`.
///
/// Zero and an empty name when it cannot be read, which says "not known"
/// rather than naming the wrong thing.
fn parent_of(pid: u32) -> (u32, String) {
    let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
        return (0, String::new());
    };
    let ppid = status
        .lines()
        .find_map(|l| l.strip_prefix("PPid:"))
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(0);
    if ppid == 0 {
        return (0, String::new());
    }

    let name = exe_name(ppid)
        .or_else(|| {
            std::fs::read_to_string(format!("/proc/{ppid}/comm"))
                .ok()
                .map(|s| s.trim().to_owned())
        })
        .unwrap_or_default();
    (ppid, name)
}

fn decode_name(raw: &[u8]) -> Option<Event> {
    if raw.len() < size_of::<RawName>() {
        return None;
    }
    // SAFETY: length checked above; the kernel side writes exactly this
    // `repr(C)` type. `read_unaligned` because the ring buffer only promises
    // 8-byte alignment of the record start.
    let n: RawName = unsafe { std::ptr::read_unaligned(raw.as_ptr().cast()) };

    let len = n.len as usize;
    if len == 0 || len > n.host.len() {
        return None;
    }
    let host = std::str::from_utf8(&n.host[..len]).ok()?.to_owned();
    if !crate::dns::is_plausible_name(&host) {
        return None;
    }

    Some(Event::Named {
        addr: address(n.family, &n.addr),
        host,
    })
}

fn decode_transfer(raw: &[u8]) -> Option<Event> {
    if raw.len() < size_of::<RawTransfer>() {
        return None;
    }
    // SAFETY: as above.
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
        peer: address(t.family, &t.addr),
        peer_port: t.port,
    }))
}

fn address(family: u8, raw: &[u8; 16]) -> IpAddr {
    if family == FAMILY_V6 {
        IpAddr::V6(Ipv6Addr::from(*raw))
    } else {
        IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))
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

    /// The bytes of any plain-data record, exactly as the kernel would have
    /// written them — which is the property both sides rely on.
    ///
    /// # Safety
    /// `T` must be `repr(C)` and contain no padding the reader would misread,
    /// which is true of both record types by construction.
    unsafe fn bytes_of<T>(v: &T) -> Vec<u8> {
        // SAFETY: the caller's contract.
        unsafe { std::slice::from_raw_parts((v as *const T).cast::<u8>(), size_of::<T>()) }.to_vec()
    }

    fn raw(dir: u8, proto: u8, bytes: u64, family: u8, addr: [u8; 16], port: u16) -> Vec<u8> {
        let t = RawTransfer {
            kind: KIND_TRANSFER,
            proto,
            dir,
            family,
            pid: 1234,
            bytes,
            addr,
            port,
            _pad: [0; 6],
        };
        // SAFETY: RawTransfer is repr(C) plain data.
        unsafe { bytes_of(&t) }
    }

    fn raw_name(host: &str, family: u8, addr: [u8; 16]) -> Vec<u8> {
        let mut buf = [0u8; netwatch_common::HOST_MAX];
        buf[..host.len()].copy_from_slice(host.as_bytes());
        let n = RawName {
            kind: KIND_NAME,
            family,
            len: host.len() as u8,
            _pad: [0; 5],
            addr,
            host: buf,
        };
        // SAFETY: RawName is repr(C) plain data.
        unsafe { bytes_of(&n) }
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

    /// Two kinds of record share one buffer, so the first byte has to decide
    /// which is which. Reading a name as a transfer would turn a hostname into
    /// a byte count.
    #[test]
    fn a_name_record_is_read_as_a_name() {
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&[104, 20, 23, 154]);
        let bytes = raw_name("example.com", netwatch_common::FAMILY_V4, a);

        let Some(Event::Named { addr, host }) = decode(&bytes) else {
            panic!("did not decode to a name");
        };
        assert_eq!(host, "example.com");
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(104, 20, 23, 154)));
    }

    /// A name that is not a name must not become one. The kernel copies bytes
    /// out of another program's memory, and nothing there is guaranteed.
    #[test]
    fn rubbish_in_the_name_field_is_refused() {
        let a = [0u8; 16];
        // A length that claims more than the buffer holds.
        let mut bad = raw_name("example.com", netwatch_common::FAMILY_V4, a);
        bad[2] = 200;
        assert!(decode(&bad).is_none(), "an impossible length was accepted");

        // Zero length: nothing was read at all.
        let mut empty = raw_name("example.com", netwatch_common::FAMILY_V4, a);
        empty[2] = 0;
        assert!(decode(&empty).is_none());

        // Something that is not a hostname.
        assert!(
            decode(&raw_name("not a host name!", netwatch_common::FAMILY_V4, a)).is_none(),
            "an implausible name was accepted"
        );
    }

    /// A record whose kind byte is neither is from a version that wrote
    /// something this one does not know. Skipping it is right; guessing is not.
    #[test]
    fn an_unknown_kind_is_skipped() {
        let mut bytes = raw(DIR_SENT, PROTO_TCP, 1, FAMILY_V4, [0; 16], 1);
        bytes[0] = 200;
        assert!(decode(&bytes).is_none());
    }
}
