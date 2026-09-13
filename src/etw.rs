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

use crate::event::{Dir, Event, Proto, Transfer};

use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{UserTrace, stop_trace_by_name};

/// {7DD42A49-5329-4832-8DFD-43D979153A88}
const KERNEL_NETWORK: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";

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
    let names = Provider::by_guid(crate::dns::DNS_CLIENT)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            for ev in decode_dns(record, locator) {
                let _ = tx.send(ev);
            }
        })
        .build();

    UserTrace::new()
        .named(SESSION.to_string())
        .enable(traffic)
        .enable(names)
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
