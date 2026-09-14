//! The one place Windows will tell you which program sent a byte.
//!
//! `Microsoft-Windows-Kernel-Network` reports every send and receive with the
//! owning process id and the byte count already attached. That is the whole
//! reason netwatch needs no driver and no packet capture: the attribution
//! problem — which is the hard part, and the part Wireshark cannot solve at
//! all — is answered by the kernel before we ever see the event.
//!
//! A real-time session needs Administrator. Without it the session simply
//! refuses to start, which is reported rather than worked around.

use std::net::IpAddr;
use std::sync::mpsc::Sender;

use crate::event::{Dir, Event, Proto, Start, Transfer};

use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{UserTrace, stop_trace_by_name};

/// {7DD42A49-5329-4832-8DFD-43D979153A88}
const KERNEL_NETWORK: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";

/// Microsoft-Windows-Kernel-Process, which reports every process start with
/// the process that started it. That pairing is the whole point: a program
/// using the connection is half an answer, and what set it off is the other
/// half.
const KERNEL_PROCESS: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";

/// `WINEVENT_KEYWORD_PROCESS`. Without it the provider reports threads, images
/// and much else besides — a great deal of traffic through the session for
/// events nothing here reads.
const KEYWORD_PROCESS: u64 = 0x10;

/// `ProcessStart`. The provider numbers stops and rundowns differently, and
/// reading one of those as a start would report a program's exit as its birth.
const OPCODE_PROCESS_START: u8 = 1;

/// Microsoft-Windows-Kernel-File, which reports every file opened, with the
/// name and the intent behind the open.
const KERNEL_FILE: &str = "edd08927-9cc4-4e65-b970-c2560fb5c289";

/// `KERNEL_FILE_KEYWORD_CREATE`. The provider can also report every read and
/// every write, which on an idle machine is a flood, and those events carry a
/// file object rather than a name — the name only ever arrives here.
const KEYWORD_FILE_CREATE: u64 = 0x80;

/// The `Create` event.
const EVENT_FILE_CREATE: u16 = 12;

/// `CreateOptions` carries the disposition in its top byte and the options in
/// the rest. The disposition is what says whether the caller meant to change
/// the file: everything except `FILE_OPEN` either creates it, replaces it, or
/// creates it if it is not there.
///
/// What this cannot see is a plain `FILE_OPEN` asked for with write access —
/// the desired access is not in the event. So this reports files created or
/// replaced, which is most of what "wrote" means and never claims more.
const DISPOSITION_OPEN: u32 = 1;

/// The name our trace session runs under.
///
/// Fixed, not generated. An ETW session outlives the process that made it: if
/// netwatch is killed — by a timeout, a crash, a reboot of the service — the
/// session stays registered in the kernel. With a generated name every start
/// leaks a new one, and Windows allows only about sixty-four in total, so a
/// service that restarts often would eventually break tracing for everything
/// on the machine. One fixed name means there is only ever one, and a
/// leftover can be found and cleared.
const SESSION: &str = "netwatch";

/// Opcodes from the provider's manifest. They come in send/receive pairs, one
/// pair per protocol and address family, and nothing else in the provider is
/// a data transfer.
fn classify(opcode: u8) -> Option<(Proto, Dir)> {
    match opcode {
        10 => Some((Proto::Tcp, Dir::Sent)),
        11 => Some((Proto::Tcp, Dir::Received)),
        26 => Some((Proto::Tcp, Dir::Sent)),     // IPv6
        27 => Some((Proto::Tcp, Dir::Received)), // IPv6
        42 => Some((Proto::Udp, Dir::Sent)),
        43 => Some((Proto::Udp, Dir::Received)),
        58 => Some((Proto::Udp, Dir::Sent)),     // IPv6
        59 => Some((Proto::Udp, Dir::Received)), // IPv6
        _ => None,
    }
}

/// A process starting, from the kernel's process provider.
///
/// The parent's name is not in the event and is left empty; whoever collects
/// these fills it in from what it already knows about that pid.
fn decode_start(record: &EventRecord, locator: &SchemaLocator) -> Option<Start> {
    // The provider reports starts, stops and rundowns on the same keyword.
    // Only a start says what started what.
    if record.opcode() != OPCODE_PROCESS_START {
        return None;
    }
    let schema = locator.event_schema(record).ok()?;
    let parser = Parser::create(record, &schema);

    let pid: u32 = parser.try_parse("ProcessID").ok()?;
    let parent: u32 = parser.try_parse("ParentProcessID").unwrap_or(0);
    let image: String = parser.try_parse("ImageName").ok()?;

    let name = image
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(&image)
        .to_string();

    Some(Start {
        pid,
        parent,
        // The file name is what anything else on the machine calls the
        // program; the whole path is where it actually lives, which is the
        // more interesting of the two.
        name,
        parent_name: String::new(),
        // The provider gives a device path, which names the same file by a
        // route nobody recognises. Turned back into a drive letter here.
        path: crate::procs::drive_path(&image),
        // Not carried by the event, so it is read from the process itself
        // while it is still there to read.
        cmdline: crate::procs::command_line(pid),
        user: crate::procs::user_of(pid),
    })
}

/// A file opened with the intent to change it.
fn decode_file(record: &EventRecord, locator: &SchemaLocator) -> Option<Event> {
    if record.event_id() != EVENT_FILE_CREATE {
        return None;
    }
    let schema = locator.event_schema(record).ok()?;
    let parser = Parser::create(record, &schema);

    let options: u32 = parser.try_parse("CreateOptions").ok()?;
    if options >> 24 == DISPOSITION_OPEN {
        return None;
    }

    let name: String = parser.try_parse("FileName").ok()?;
    if name.is_empty() || is_own_trace(&name) {
        return None;
    }

    // The event carries no process id; the record it arrived in does, and it
    // is the process that made the call.
    Some(Event::Wrote {
        pid: record.process_id(),
        path: crate::procs::drive_path(&name),
    })
}

/// netwatch's own trace session writes its buffer file constantly. Reporting
/// that would be true, useless, and a little absurd: the tool would spend its
/// time telling you about itself.
fn is_own_trace(path: &str) -> bool {
    let p = path.to_lowercase();
    p.contains(r"logfiles\wmi\rtbackup") || p.ends_with(".etl")
}

fn decode(record: &EventRecord, locator: &SchemaLocator) -> Option<Transfer> {
    let (proto, dir) = classify(record.opcode())?;
    let schema = locator.event_schema(record).ok()?;
    let parser = Parser::create(record, &schema);

    let pid: u32 = parser.try_parse("PID").ok()?;
    let bytes: u32 = parser.try_parse("size").ok()?;

    // The provider always names the fields from the packet's direction, so on
    // a receive the peer is the source. Reading `daddr` for both would report
    // this machine's own address as the peer for half the traffic.
    let (addr_field, port_field) = match dir {
        Dir::Sent => ("daddr", "dport"),
        Dir::Received => ("saddr", "sport"),
    };
    let peer: IpAddr = parser.try_parse(addr_field).ok()?;
    let peer_port: u16 = parser.try_parse(port_field).unwrap_or(0);

    Some(Transfer {
        pid,
        proto,
        dir,
        bytes: bytes as u64,
        peer,
        peer_port,
    })
}

/// A completed DNS lookup: one name, and every address it answered with.
fn decode_dns(record: &EventRecord, locator: &SchemaLocator) -> Vec<Event> {
    if record.event_id() != crate::dns::EVENT_QUERY_COMPLETE {
        return Vec::new();
    }
    let Ok(schema) = locator.event_schema(record) else {
        return Vec::new();
    };
    let parser = Parser::create(record, &schema);

    // A non-zero status is a lookup that failed; its results are empty and
    // recording the name against nothing would teach us nothing.
    let status: u32 = parser.try_parse("QueryStatus").unwrap_or(1);
    if status != 0 {
        return Vec::new();
    }
    let Ok(name) = parser.try_parse::<String>("QueryName") else {
        return Vec::new();
    };
    if !crate::dns::is_plausible_name(&name) {
        return Vec::new();
    }
    let results: String = parser.try_parse("QueryResults").unwrap_or_default();

    crate::dns::addresses(&results)
        .into_iter()
        .map(|addr| Event::Named {
            addr,
            host: name.clone(),
        })
        .collect()
}

/// Start listening. Events arrive on the channel until the returned trace is
/// dropped or stopped.
///
/// The callback runs on ETW's own thread and must not block: it decodes and
/// hands the event straight over, so a slow consumer costs dropped events in
/// our channel rather than dropped events in the kernel's buffers.
pub fn start(tx: Sender<Event>) -> Result<UserTrace, String> {
    // Clear a session left behind by a previous run that did not exit
    // cleanly. Failure here is the normal case — usually there is nothing to
    // clear — so it is deliberately not an error.
    let _ = stop_trace_by_name(SESSION);

    let traffic_tx = tx.clone();
    let traffic = Provider::by_guid(KERNEL_NETWORK)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            if let Some(t) = decode(record, locator) {
                let _ = traffic_tx.send(Event::Transfer(t));
            }
        })
        .build();

    // The second provider on the same session: one session, one ordered
    // stream, and one thing to clean up if this process is killed.
    let names_tx = tx.clone();
    let names = Provider::by_guid(crate::dns::DNS_CLIENT)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            for ev in decode_dns(record, locator) {
                let _ = names_tx.send(ev);
            }
        })
        .build();

    // The third provider on the same session, for the same reason as the
    // second: one session, one ordered stream, one thing to clean up.
    let starts_tx = tx.clone();
    let starts = Provider::by_guid(KERNEL_PROCESS)
        .any(KEYWORD_PROCESS)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            if let Some(s) = decode_start(record, locator) {
                let _ = starts_tx.send(Event::Started(s));
            }
        })
        .build();

    // The fourth provider on the same session, and the last: one session, one
    // ordered stream, one thing to clean up.
    let files = Provider::by_guid(KERNEL_FILE)
        .any(KEYWORD_FILE_CREATE)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            if let Some(ev) = decode_file(record, locator) {
                let _ = tx.send(ev);
            }
        })
        .build();

    UserTrace::new()
        .named(SESSION.to_string())
        .enable(traffic)
        .enable(names)
        .enable(starts)
        .enable(files)
        .start_and_process()
        .map_err(|e| {
            format!(
                "could not start the trace session ({e:?}).\n\
                 netwatch needs Administrator: reading which process sent a packet \
                 is a kernel-level question, and Windows only answers it for an \
                 elevated session."
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every opcode the provider uses for a transfer must be classified, and
    /// nothing else must be: counting a connection attempt as a byte transfer
    /// would inflate every total, and missing IPv6 would silently under-report
    /// exactly the traffic that is growing.
    #[test]
    fn transfer_opcodes_are_classified_in_both_directions() {
        assert_eq!(classify(10), Some((Proto::Tcp, Dir::Sent)));
        assert_eq!(classify(11), Some((Proto::Tcp, Dir::Received)));
        assert_eq!(classify(26), Some((Proto::Tcp, Dir::Sent)));
        assert_eq!(classify(27), Some((Proto::Tcp, Dir::Received)));
        assert_eq!(classify(42), Some((Proto::Udp, Dir::Sent)));
        assert_eq!(classify(43), Some((Proto::Udp, Dir::Received)));
        assert_eq!(classify(58), Some((Proto::Udp, Dir::Sent)));
        assert_eq!(classify(59), Some((Proto::Udp, Dir::Received)));
    }

    #[test]
    fn non_transfer_opcodes_are_ignored() {
        // 12 is a connection attempt and 13 a disconnect: real events that
        // carry no payload, and counting them as traffic would be wrong.
        for op in [0, 1, 12, 13, 15, 44, 200, 255] {
            assert_eq!(classify(op), None, "opcode {op} should not be traffic");
        }
    }
}
