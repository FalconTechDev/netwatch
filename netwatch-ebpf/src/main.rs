//! What runs inside the kernel.
//!
//! Probes on the functions every byte in the system passes through, one pair
//! per protocol and direction:
//!
//! * `tcp_sendmsg(sk, msg, size)` — called once per send, with the byte count
//!   as its third argument.
//! * `tcp_cleanup_rbuf(sk, copied)` — called when a socket's receive queue is
//!   drained, with the number of bytes actually handed to the process. This is
//!   the receive side's counterpart rather than `tcp_recvmsg`, because
//!   `tcp_recvmsg` is entered before it knows how much it will return; the
//!   count is only known on the way out.
//! * `udp_sendmsg` and `udpv6_sendmsg` — the same for UDP, which needs both
//!   because the two families have separate send paths.
//! * `skb_consume_udp(sk, skb, len)` — the UDP receive side, and the reason
//!   `udp_recvmsg` is not used: this one is handed the socket and the length
//!   together, where `udp_recvmsg` again knows the length only on the way out.
//!
//! Both are entry probes, so the work done here is a few loads and a write
//! into a ring buffer — the kernel is blocked in a hot path while this runs,
//! and anything slower would be felt by every connection on the machine.
//!
//! The process is charged by pid from `bpf_get_current_pid_tgid`, which is
//! correct here because both functions run in the context of the process doing
//! the syscall, not in a softirq.

#![no_std]
#![no_main]

use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel,
    bpf_probe_read_kernel_buf, bpf_probe_read_user, bpf_probe_read_user_buf,
    bpf_probe_read_user_str_bytes,
};
use aya_ebpf::macros::{kprobe, map, tracepoint, uprobe, uretprobe};
use aya_ebpf::maps::{Array, HashMap, RingBuf};
use aya_ebpf::programs::{ProbeContext, RetProbeContext, TracePointContext};
use aya_ebpf_bindings::bindings::bpf_pidns_info;
use aya_ebpf_bindings::helpers::bpf_get_ns_current_pid_tgid;

use netwatch_common::{
    AF_INET, AF_INET6, COMM_MAX, DIR_RECEIVED, DIR_SENT, FAMILY_V4, FAMILY_V6, HOST_MAX, KIND_FILE,
    KIND_NAME, KIND_START, KIND_TRANSFER, PATH_MAX, PROTO_TCP, PROTO_UDP, RawFile, RawName,
    RawStart, RawTransfer, sock,
};

/// The pid namespace to report process ids in, as a device number and inode,
/// written here by the program that loads this one.
///
/// The kernel counts processes in the namespace it booted in, but a program
/// running inside a container — or inside WSL, which is one — sees entirely
/// different numbers for the same processes. Reporting the kernel's numbers
/// would give ids that match nothing in `/proc`, `ps`, or anything else the
/// person can see, and a pid that cannot be looked up is worse than useless:
/// it looks like an answer.
///
/// Slot 0 is the device, slot 1 the inode. Both zero means "not configured",
/// and the kernel's own numbering is used.
#[map]
static PIDNS: Array<u64> = Array::with_max_entries(2, 0);

/// Byte offsets of the `struct sock` fields read below, filled in by the
/// loader from this kernel's own BTF. See `netwatch_common::sock`.
#[map]
static SOCK: Array<u64> = Array::with_max_entries(sock::SLOTS, 0);

/// Where events go on their way out. A ring buffer rather than a perf buffer:
/// it is shared across CPUs, so events keep their order, which is what lets a
/// name be recorded before the traffic it belongs to.
///
/// 256 KiB holds a burst comfortably. If userspace ever falls far enough
/// behind to fill it, `reserve` returns nothing and the event is dropped —
/// losing a sample is better than stalling the kernel's send path.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[kprobe]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    // First argument: the socket. Third: the number of bytes handed to it.
    let Some(sk) = ctx.arg::<u64>(0) else {
        return 0;
    };
    let Some(size) = ctx.arg::<usize>(2) else {
        return 0;
    };
    emit(sk, size as u64, DIR_SENT, PROTO_TCP);
    0
}

#[kprobe]
pub fn tcp_cleanup_rbuf(ctx: ProbeContext) -> u32 {
    // Second argument: bytes copied to the process. It is signed and is zero
    // or negative on the calls that moved nothing, which are the majority.
    let Some(sk) = ctx.arg::<u64>(0) else {
        return 0;
    };
    let Some(copied) = ctx.arg::<i32>(1) else {
        return 0;
    };
    if copied <= 0 {
        return 0;
    }
    emit(sk, copied as u64, DIR_RECEIVED, PROTO_TCP);
    0
}

#[kprobe]
pub fn udp_sendmsg(ctx: ProbeContext) -> u32 {
    udp_send(ctx)
}

/// IPv6 has its own send path, so it needs its own probe; the receive side is
/// shared between the two families and does not.
#[kprobe]
pub fn udpv6_sendmsg(ctx: ProbeContext) -> u32 {
    udp_send(ctx)
}

fn udp_send(ctx: ProbeContext) -> u32 {
    let Some(sk) = ctx.arg::<u64>(0) else {
        return 0;
    };
    let Some(len) = ctx.arg::<usize>(2) else {
        return 0;
    };
    emit(sk, len as u64, DIR_SENT, PROTO_UDP);
    0
}

#[kprobe]
pub fn skb_consume_udp(ctx: ProbeContext) -> u32 {
    let Some(sk) = ctx.arg::<u64>(0) else {
        return 0;
    };
    // Third argument: how much was handed to the process. Negative on the
    // paths that delivered nothing.
    let Some(len) = ctx.arg::<i32>(2) else {
        return 0;
    };
    if len <= 0 {
        return 0;
    }
    emit(sk, len as u64, DIR_RECEIVED, PROTO_UDP);
    0
}

/// Put one transfer on the ring buffer, or drop it if there is no room.
fn emit(sk: u64, bytes: u64, dir: u8, proto: u8) {
    let Some(mut entry) = EVENTS.reserve::<RawTransfer>(0) else {
        return;
    };

    let (addr, port, family) = peer(sk);

    entry.write(RawTransfer {
        kind: KIND_TRANSFER,
        proto,
        dir,
        family,
        pid: current_tgid(),
        bytes,
        addr,
        port,
        _pad: [0u8; 6],
    });
    entry.submit(0);
}

/// What a thread asked `getaddrinfo` for, remembered between the call and its
/// return — the name is only known going in, and the answer only coming out.
#[repr(C)]
#[derive(Clone, Copy)]
struct Lookup {
    /// The name asked for, as a pointer into the calling program.
    host: u64,
    /// Where the answer will be written: the `res` out-parameter.
    res: u64,
}

/// Keyed by thread, not process: two threads of one program can be resolving
/// different names at the same time, and keying by process would hand one
/// thread's answer the other's question.
#[map]
static LOOKUPS: HashMap<u64, Lookup> = HashMap::with_max_entries(4096, 0);

/// The layout of glibc's `struct addrinfo` and of the socket addresses it
/// points at.
///
/// These are hard-coded where the kernel's are looked up, and the difference
/// is the point: `struct sock` is internal to a kernel build and moves between
/// them, while `struct addrinfo` is part of the C library's published ABI. A
/// program compiled ten years ago still walks this list the same way; if these
/// offsets moved, every binary on the system would break, not just this one.
mod addrinfo {
    /// `int ai_family`
    pub const FAMILY: u64 = 4;
    /// `struct sockaddr *ai_addr`
    pub const ADDR: u64 = 24;
    /// `struct addrinfo *ai_next`
    pub const NEXT: u64 = 40;

    /// `sa_family_t sin_family` — the same first field in both families.
    pub const SA_FAMILY: u64 = 0;
    /// `struct in_addr sin_addr`
    pub const SIN_ADDR: u64 = 4;
    /// `struct in6_addr sin6_addr`
    pub const SIN6_ADDR: u64 = 8;

    /// How far down the list to walk. A name with more addresses than this is
    /// unusual, and the loop has to be bounded for the verifier to accept it
    /// at all.
    pub const MAX: usize = 8;
}

/// Going in: remember the name and where the answer will land.
#[uprobe]
pub fn getaddrinfo(ctx: ProbeContext) -> u32 {
    let (Some(host), Some(res)) = (ctx.arg::<u64>(0), ctx.arg::<u64>(3)) else {
        return 0;
    };
    if host == 0 || res == 0 {
        return 0;
    }
    let _ = LOOKUPS.insert(&bpf_get_current_pid_tgid(), &Lookup { host, res }, 0);
    0
}

/// Coming out: if it succeeded, read the name it was asked for and every
/// address it answered with.
#[uretprobe]
pub fn getaddrinfo_ret(ctx: RetProbeContext) -> u32 {
    let tid = bpf_get_current_pid_tgid();
    // SAFETY: the key is a plain u64 and the map returns a pointer into its
    // own storage, read before anything else can remove the entry.
    let Some(&saved) = (unsafe { LOOKUPS.get(&tid) }) else {
        return 0;
    };
    let _ = LOOKUPS.remove(&tid);

    // Anything other than zero means it failed, and a failed lookup names
    // nothing.
    if ctx.ret::<i32>() != 0 {
        return 0;
    }

    let mut host = [0u8; HOST_MAX];
    // SAFETY: the pointer came from the calling program's own arguments and
    // is read through the helper, which faults safely.
    let Ok(name) = (unsafe { bpf_probe_read_user_str_bytes(saved.host as *const u8, &mut host) })
    else {
        return 0;
    };
    let len = name.len();
    if len == 0 || len >= HOST_MAX {
        // An empty name says nothing, and one that filled the buffer was
        // truncated — half a domain is a different domain.
        return 0;
    }

    // SAFETY: every dereference below goes through a user probe read.
    let mut node = match unsafe { bpf_probe_read_user::<u64>(saved.res as *const u64) } {
        Ok(p) => p,
        Err(_) => return 0,
    };

    for _ in 0..addrinfo::MAX {
        if node == 0 {
            break;
        }
        // SAFETY: as above — probe reads, which return an error rather than
        // faulting, on pointers taken from the program's own answer.
        unsafe {
            let family = bpf_probe_read_user::<i32>((node + addrinfo::FAMILY) as *const i32);
            let sa = bpf_probe_read_user::<u64>((node + addrinfo::ADDR) as *const u64);
            let next = bpf_probe_read_user::<u64>((node + addrinfo::NEXT) as *const u64);

            if let (Ok(family), Ok(sa)) = (family, sa)
                && sa != 0
            {
                emit_name(family as u16, sa, &host, len);
            }
            node = next.unwrap_or(0);
        }
    }
    0
}

/// Put one name-to-address pairing on the ring buffer.
///
/// # Safety
/// `sa` must be a socket address in the calling program, read here only
/// through user probe reads.
unsafe fn emit_name(family: u16, sa: u64, host: &[u8; HOST_MAX], len: usize) {
    let (off, want, mark) = match family {
        AF_INET => (addrinfo::SIN_ADDR, 4usize, FAMILY_V4),
        AF_INET6 => (addrinfo::SIN6_ADDR, 16usize, FAMILY_V6),
        _ => return,
    };

    let mut addr = [0u8; 16];
    // SAFETY: the caller's contract, and the helper faults safely regardless.
    unsafe {
        // The family is checked against the address itself as well as against
        // the entry that pointed here; a disagreement means this is not the
        // structure it was said to be.
        let Ok(sa_family) = bpf_probe_read_user::<u16>((sa + addrinfo::SA_FAMILY) as *const u16)
        else {
            return;
        };
        if sa_family != family {
            return;
        }
        if bpf_probe_read_user_buf((sa + off) as *const u8, &mut addr[..want]).is_err() {
            return;
        }
    }

    let Some(mut entry) = EVENTS.reserve::<RawName>(0) else {
        return;
    };
    entry.write(RawName {
        kind: KIND_NAME,
        family: mark,
        len: len as u8,
        _pad: [0u8; 5],
        addr,
        host: *host,
    });
    entry.submit(0);
}

/// `sys_enter_openat`, where the arguments begin. The first eight bytes are
/// the tracepoint's own header and the next eight the syscall number.
mod openat {
    /// `const char *filename`
    pub const FILENAME: usize = 24;
    /// `int flags`
    pub const FLAGS: usize = 32;
}

/// The open flags that mean a program intends to change the file.
mod oflag {
    pub const WRONLY: u64 = 0o1;
    pub const RDWR: u64 = 0o2;
    pub const CREAT: u64 = 0o100;
    pub const TRUNC: u64 = 0o1000;
    pub const APPEND: u64 = 0o2000;
}

/// A file opened for writing.
///
/// Only writes, and the filtering happens here rather than in userspace
/// because `openat` fires thousands of times a second on an idle machine.
/// Sending all of it up and discarding it there would cost the ring buffer,
/// the reader, and every event that got dropped to make room.
///
/// What a program reads is almost entirely its own libraries, locale data and
/// configuration. What it writes is a short list, and is the thing anyone
/// actually wants to see.
#[tracepoint(category = "syscalls", name = "sys_enter_openat")]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    // SAFETY: both reads are at fixed offsets inside the tracepoint's own
    // record, whose layout the kernel publishes and which is checked against
    // /sys/kernel/tracing at development time.
    let (filename, flags) = unsafe {
        let Ok(filename) = ctx.read_at::<u64>(openat::FILENAME) else {
            return 0;
        };
        let Ok(flags) = ctx.read_at::<u64>(openat::FLAGS) else {
            return 0;
        };
        (filename, flags)
    };
    if filename == 0 {
        return 0;
    }

    let writing = flags & (oflag::WRONLY | oflag::RDWR) != 0
        || flags & (oflag::CREAT | oflag::TRUNC | oflag::APPEND) != 0;
    if !writing {
        return 0;
    }

    let mut path = [0u8; PATH_MAX];
    // SAFETY: the pointer is an argument of the calling program's own syscall
    // and is read through the helper, which faults safely.
    let Ok(read) = (unsafe { bpf_probe_read_user_str_bytes(filename as *const u8, &mut path) })
    else {
        return 0;
    };
    let len = read.len();
    if len == 0 {
        return 0;
    }
    if noise(&path, len) {
        return 0;
    }

    let Some(mut entry) = EVENTS.reserve::<RawFile>(0) else {
        return 0;
    };
    entry.write(RawFile {
        kind: KIND_FILE,
        len: len as u8,
        // The helper fills the buffer and stops; a path that needed every byte
        // was probably longer than that.
        truncated: u8::from(len >= PATH_MAX - 1),
        _pad: [0u8; 1],
        pid: current_tgid(),
        path,
    });
    entry.submit(0);
    0
}

/// Whether a path is one of the places nothing interesting is ever written.
///
/// These are the kernel's own pseudo-filesystems and the terminal. Writes
/// there are constant, and none of them is a program storing anything: they
/// are how a process talks to the kernel and to its own screen.
fn noise(path: &[u8; PATH_MAX], len: usize) -> bool {
    const PREFIXES: [&[u8]; 5] = [b"/proc/", b"/sys/", b"/dev/pts/", b"/dev/tty", b"/dev/null"];

    for prefix in PREFIXES {
        if len >= prefix.len() {
            // A bounded compare: the verifier needs the length known, and
            // these are all short.
            let mut same = true;
            let mut i = 0;
            while i < prefix.len() && i < PATH_MAX {
                if path[i] != prefix[i] {
                    same = false;
                    break;
                }
                i += 1;
            }
            if same {
                return true;
            }
        }
    }
    false
}

/// A program started. Reported so that what set some traffic off can be seen
/// alongside the traffic itself.
///
/// A tracepoint rather than a kprobe: this is part of the kernel's published
/// tracing interface and does not move between versions, where the function
/// behind it has been renamed more than once.
///
/// Only the process and its name are sent. Who started it is left to the
/// reader to ask `/proc`, because the parent's id in `task_struct` is counted
/// in the namespace the kernel booted in — inside a container that number
/// names a different process, and a wrong parent is worse than none.
#[tracepoint(category = "sched", name = "sched_process_exec")]
pub fn sched_process_exec(_ctx: TracePointContext) -> u32 {
    let Ok(comm) = bpf_get_current_comm() else {
        return 0;
    };
    let len = comm.iter().position(|b| *b == 0).unwrap_or(COMM_MAX);
    if len == 0 {
        return 0;
    }

    let Some(mut entry) = EVENTS.reserve::<RawStart>(0) else {
        return 0;
    };
    entry.write(RawStart {
        kind: KIND_START,
        len: len as u8,
        _pad: [0u8; 2],
        pid: current_tgid(),
        comm,
    });
    entry.submit(0);
    0
}

/// The far end of a socket: its address and port, read out of `struct sock`
/// at the offsets the loader found.
///
/// Returns a zero address when the offsets are not in place or a read faults.
/// That is reported as "no peer" rather than as address zero, because a made-up
/// address is indistinguishable from a real one once it leaves here.
fn peer(sk: u64) -> ([u8; 16], u16, u8) {
    let none = ([0u8; 16], 0u16, FAMILY_V4);

    if SOCK.get(sock::READY).copied() != Some(1) {
        return none;
    }
    let (Some(&off_family), Some(&off_daddr), Some(&off_dport), Some(&off_daddr6)) = (
        SOCK.get(sock::FAMILY),
        SOCK.get(sock::DADDR),
        SOCK.get(sock::DPORT),
        SOCK.get(sock::DADDR6),
    ) else {
        return none;
    };

    // SAFETY: every read goes through bpf_probe_read_kernel, which faults
    // safely and returns an error rather than touching bad memory. `sk` is
    // whatever the kernel passed as the socket; nothing here dereferences it
    // directly.
    unsafe {
        let Ok(family) = bpf_probe_read_kernel::<u16>((sk + off_family) as *const u16) else {
            return none;
        };

        // The port is stored the way it goes on the wire. Swapping it here,
        // where the byte order is known, means nothing downstream has to
        // remember that it was ever big-endian.
        let Ok(dport) = bpf_probe_read_kernel::<u16>((sk + off_dport) as *const u16) else {
            return none;
        };
        let port = u16::from_be(dport);

        let mut addr = [0u8; 16];
        match family {
            AF_INET => {
                if bpf_probe_read_kernel_buf((sk + off_daddr) as *const u8, &mut addr[..4]).is_err()
                {
                    return none;
                }
                (addr, port, FAMILY_V4)
            }
            AF_INET6 => {
                // This kernel was built without IPv6, so there is no field to
                // read. Adding the sentinel to the pointer would read whatever
                // happens to sit there.
                if off_daddr6 == sock::NO_FIELD {
                    return none;
                }
                if bpf_probe_read_kernel_buf((sk + off_daddr6) as *const u8, &mut addr).is_err() {
                    return none;
                }
                (addr, port, FAMILY_V6)
            }
            // A unix socket, or anything else that is not IP. It moved bytes,
            // and that is still worth reporting against the process.
            _ => none,
        }
    }
}

/// The process id of whoever is running, counted the way the watching program
/// counts — see `PIDNS`.
///
/// The thread group id rather than the thread id: the lower half of what the
/// kernel returns identifies one thread, which would split a browser across as
/// many rows as it has threads.
fn current_tgid() -> u32 {
    let kernels = || (bpf_get_current_pid_tgid() >> 32) as u32;

    let (Some(&dev), Some(&ino)) = (PIDNS.get(0), PIDNS.get(1)) else {
        return kernels();
    };
    if dev == 0 && ino == 0 {
        return kernels();
    }

    let mut ns = bpf_pidns_info { pid: 0, tgid: 0 };
    // SAFETY: `ns` is a live, fully initialised `bpf_pidns_info`, and the size
    // passed is its own. The helper writes only within it.
    let ret = unsafe {
        bpf_get_ns_current_pid_tgid(
            dev,
            ino,
            &mut ns as *mut bpf_pidns_info,
            size_of::<bpf_pidns_info>() as u32,
        )
    };
    // It fails when the process is not in that namespace at all — a host
    // process seen from inside a container. Its own numbering is the only
    // thing left to report.
    if ret == 0 { ns.tgid } else { kernels() }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
