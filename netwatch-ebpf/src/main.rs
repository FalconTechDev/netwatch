//! What runs inside the kernel.
//!
//! Two probes, one for each direction, on the functions every TCP byte in the
//! system passes through:
//!
//! * `tcp_sendmsg(sk, msg, size)` — called once per send, with the byte count
//!   as its third argument.
//! * `tcp_cleanup_rbuf(sk, copied)` — called when a socket's receive queue is
//!   drained, with the number of bytes actually handed to the process. This is
//!   the receive side's counterpart rather than `tcp_recvmsg`, because
//!   `tcp_recvmsg` is entered before it knows how much it will return; the
//!   count is only known on the way out.
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

use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::macros::{kprobe, map};
use aya_ebpf::maps::{Array, RingBuf};
use aya_ebpf::programs::ProbeContext;
use aya_ebpf_bindings::bindings::bpf_pidns_info;
use aya_ebpf_bindings::helpers::bpf_get_ns_current_pid_tgid;

use netwatch_common::{DIR_RECEIVED, DIR_SENT, FAMILY_V4, PROTO_TCP, RawTransfer};

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
    // Third argument: the number of bytes handed to the kernel.
    let Some(size) = ctx.arg::<usize>(2) else {
        return 0;
    };
    emit(size as u64, DIR_SENT);
    0
}

#[kprobe]
pub fn tcp_cleanup_rbuf(ctx: ProbeContext) -> u32 {
    // Second argument: bytes copied to the process. It is signed and is zero
    // or negative on the calls that moved nothing, which are the majority.
    let Some(copied) = ctx.arg::<i32>(1) else {
        return 0;
    };
    if copied <= 0 {
        return 0;
    }
    emit(copied as u64, DIR_RECEIVED);
    0
}

/// Put one transfer on the ring buffer, or drop it if there is no room.
fn emit(bytes: u64, dir: u8) {
    let Some(mut entry) = EVENTS.reserve::<RawTransfer>(0) else {
        return;
    };

    entry.write(RawTransfer {
        bytes,
        pid: current_tgid(),
        // The peer is not read yet: reaching into `struct sock` needs field
        // offsets for the running kernel, which is the next step. Until then
        // every byte is still charged to the right process.
        addr: [0u8; 16],
        port: 0,
        proto: PROTO_TCP,
        dir,
        family: FAMILY_V4,
        _pad: [0u8; 7],
    });
    entry.submit(0);
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
