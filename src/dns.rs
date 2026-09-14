//! Addresses -> the names that were actually asked for.
//!
//! A peer shown as `185.184.222.3:443` tells you nothing. The obvious way to
//! fix that is a reverse lookup, and it is the wrong way: it invents a name the
//! traffic never mentioned, and for anything behind a CDN it returns something
//! like `ec2-52-216-18-11.compute-1.amazonaws.com`, which is worse than the
//! address it replaced.
//!
//! So the names come from the machine's own lookups. Windows reports every DNS
//! answer it receives, with the name that was asked for and the addresses that
//! came back; matching traffic against that means a name on screen is a name a
//! program on this machine actually resolved.
//!
//! What that cannot do is name an address nobody looked up — a hard-coded
//! address, a connection from a cached answer older than this session, a peer
//! reached by IP on purpose. Those stay addresses, which is the honest outcome.

use std::net::{IpAddr, Ipv4Addr};

/// {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}
pub const DNS_CLIENT: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";

/// The completion event: it carries the name and the addresses together.
/// The query event (3006) has only the name, and by itself would let us record
/// that something was asked without ever learning the answer.
pub const EVENT_QUERY_COMPLETE: u16 = 3008;

/// Pull the addresses out of a `QueryResults` field.
///
/// The field mixes two kinds of entry, semicolon separated: `type: 5 name` for
/// each CNAME step along the way, and bare addresses for the answers. Only the
/// addresses are of use here — the intermediate names are how the resolver got
/// there, not who the traffic will be with.
///
/// IPv4 answers arrive as IPv4-mapped IPv6 (`::ffff:140.82.121.5`) and are
/// unmapped, or every v4 address would fail to match the traffic events, which
/// report plain v4.
pub fn addresses(results: &str) -> Vec<IpAddr> {
    results
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with("type:"))
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .map(unmap)
        .collect()
}

/// `::ffff:1.2.3.4` is the same host as `1.2.3.4`, and the traffic events call
/// it the second thing.
fn unmap(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => match v6.octets() {
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d] => {
                IpAddr::V4(Ipv4Addr::new(a, b, c, d))
            }
            _ => addr,
        },
        v4 => v4,
    }
}

/// A name is worth keeping only if it is one; an empty or absurd string in the
/// name field would end up on screen next to an address and be believed.
pub fn is_plausible_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.contains('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_single_answer_is_read() {
        assert_eq!(
            addresses("::ffff:140.82.121.5;"),
            vec![IpAddr::V4(Ipv4Addr::new(140, 82, 121, 5))]
        );
    }

    /// The mapped form has to become the plain one, or no IPv4 address would
    /// ever match a traffic event and the whole feature would silently do
    /// nothing.
    #[test]
    fn mapped_addresses_become_plain_ipv4() {
        let got = addresses("::ffff:104.20.23.154;");
        assert_eq!(got, vec![IpAddr::V4(Ipv4Addr::new(104, 20, 23, 154))]);
        assert!(matches!(got[0], IpAddr::V4(_)), "not left as v6");
    }

    /// A real answer for a CDN name: several CNAME steps, then the address.
    #[test]
    fn cname_steps_are_not_addresses() {
        let raw = "type: 5 filedownload.lenovo.com.akadns.net;\
                   type: 5 e7741.g.akamaiedge.net;::ffff:23.210.17.89;";
        assert_eq!(
            addresses(raw),
            vec![IpAddr::V4(Ipv4Addr::new(23, 210, 17, 89))]
        );
    }

    #[test]
    fn both_families_come_back() {
        let raw = "2606:4700:10::ac42:93f3;::ffff:104.20.23.154;";
        let got = addresses(raw);
        assert_eq!(got.len(), 2);
        assert!(got.iter().any(|a| a.is_ipv6()));
        assert!(got.iter().any(|a| a.is_ipv4()));
    }

    #[test]
    fn a_failed_lookup_yields_nothing() {
        assert!(addresses("").is_empty());
        assert!(addresses(";;").is_empty());
        assert!(addresses("type: 5 only.a.cname.example;").is_empty());
    }

    #[test]
    fn nonsense_is_not_mistaken_for_a_name() {
        assert!(is_plausible_name("api.github.com"));
        assert!(is_plausible_name("_sip._tcp.example.org"));

        assert!(!is_plausible_name(""));
        assert!(!is_plausible_name("localhost"), "no dot, not a host name");
        assert!(!is_plausible_name("has space.com"));
        assert!(!is_plausible_name(&"a".repeat(300)));
    }
}

/// A DNS reply read straight off the wire.
///
/// Windows hands netwatch the answer already decoded; Linux has no such
/// provider, and the library call it watches instead is invisible to a program
/// that carries its own resolver — a statically linked Go binary, most
/// obviously. For those the reply itself is the only place the name exists, so
/// it is parsed here.
///
/// Deliberately in userspace rather than in the kernel: this walks
/// variable-length names and follows compression pointers, which is exactly
/// the sort of code the eBPF verifier fights and exactly the sort that should
/// be covered by tests. The kernel copies the bytes; this makes sense of them.
///
/// Nothing here trusts the input. It is a packet from the network, and every
/// length in it is a number somebody else chose.
pub mod wire {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    const HEADER: usize = 12;
    const TYPE_A: u16 = 1;
    const TYPE_AAAA: u16 = 28;
    const CLASS_IN: u16 = 1;

    /// A compression pointer: the top two bits of a length byte.
    const POINTER: u8 = 0xC0;

    /// How many pointers to follow before deciding the packet is lying. A
    /// reply can point a name at another name, and a malicious one can point
    /// it at itself — which without this is an infinite loop in the reader.
    const MAX_JUMPS: usize = 16;

    /// Every name-to-address pairing in a reply.
    ///
    /// Empty for a query, a failure, or anything that does not parse — a reply
    /// that cannot be read is not an error worth reporting, it is simply a
    /// packet this did not understand.
    pub fn answers(packet: &[u8]) -> Vec<(String, IpAddr)> {
        let mut out = Vec::new();
        if packet.len() < HEADER {
            return out;
        }

        // Bit 15 of the flags is set on a reply. A query carries the name but
        // no address, and reading one as a reply would pair a name with
        // whatever followed it.
        let flags = u16::from_be_bytes([packet[2], packet[3]]);
        if flags & 0x8000 == 0 {
            return out;
        }
        // The low four bits are the response code; anything but zero is a
        // failure, and its answer section is empty or meaningless.
        if flags & 0x000F != 0 {
            return out;
        }

        let questions = u16::from_be_bytes([packet[4], packet[5]]);
        let answers = u16::from_be_bytes([packet[6], packet[7]]);
        if answers == 0 {
            return out;
        }

        let mut at = HEADER;
        // Skip the questions: each is a name followed by two 16-bit fields.
        for _ in 0..questions {
            // A question that cannot be read means the rest of the packet
            // cannot be located either; stopping is the only safe answer.
            let Some((_, next)) = read_name(packet, at) else {
                return out;
            };
            at = next + 4;
        }

        for _ in 0..answers {
            let Some((name, next)) = read_name(packet, at) else {
                break;
            };
            at = next;
            // type, class, ttl, rdlength
            if at + 10 > packet.len() {
                break;
            }
            let kind = u16::from_be_bytes([packet[at], packet[at + 1]]);
            let class = u16::from_be_bytes([packet[at + 2], packet[at + 3]]);
            let len = u16::from_be_bytes([packet[at + 8], packet[at + 9]]) as usize;
            at += 10;
            if at + len > packet.len() {
                break;
            }

            if class == CLASS_IN && super::is_plausible_name(&name) {
                match (kind, len) {
                    (TYPE_A, 4) => {
                        let o: [u8; 4] = packet[at..at + 4].try_into().unwrap_or([0; 4]);
                        out.push((name, IpAddr::V4(Ipv4Addr::from(o))));
                    }
                    (TYPE_AAAA, 16) => {
                        let o: [u8; 16] = packet[at..at + 16].try_into().unwrap_or([0; 16]);
                        out.push((name, IpAddr::V6(Ipv6Addr::from(o))));
                    }
                    // A CNAME or anything else: not an address, and the name
                    // it does carry is answered by a later record.
                    _ => {}
                }
            }
            at += len;
        }
        out
    }

    /// A name, and where the record continues after it.
    ///
    /// Returns nothing if the packet runs out or points in circles; the caller
    /// stops rather than guessing where the next record begins, because a
    /// wrong guess would read arbitrary bytes as an address.
    fn read_name(packet: &[u8], start: usize) -> Option<(String, usize)> {
        let mut name = String::new();
        let mut at = start;
        // Where the record continues, which is not where the name ends when
        // the name ended in a pointer.
        let mut after = None;
        let mut jumps = 0;

        loop {
            let len = *packet.get(at)? as usize;
            if len == 0 {
                at += 1;
                break;
            }
            if len & POINTER as usize == POINTER as usize {
                let lo = *packet.get(at + 1)? as usize;
                let target = ((len & 0x3F) << 8) | lo;
                // A pointer must point backwards. One that points forward, or
                // at itself, is how a packet tries to make a reader loop.
                if target >= at {
                    return None;
                }
                jumps += 1;
                if jumps > MAX_JUMPS {
                    return None;
                }
                after.get_or_insert(at + 2);
                at = target;
                continue;
            }
            // A label is at most 63 bytes, which the two top bits already
            // guarantee, but the packet may still end mid-label.
            let end = at.checked_add(1)?.checked_add(len)?;
            let label = packet.get(at + 1..end)?;
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(&String::from_utf8_lossy(label));
            at = end;
        }
        Some((name, after.unwrap_or(at)))
    }
}

#[cfg(test)]
mod wire_tests {
    use super::wire::answers;
    use std::net::{IpAddr, Ipv4Addr};

    /// Builds a reply the way a resolver would, so the parser is tested
    /// against the format rather than against itself.
    fn reply(name: &str, records: &[(u16, &[u8])]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&[0x12, 0x34]); // id
        p.extend_from_slice(&[0x81, 0x80]); // reply, no error
        p.extend_from_slice(&1u16.to_be_bytes()); // questions
        p.extend_from_slice(&(records.len() as u16).to_be_bytes()); // answers
        p.extend_from_slice(&[0, 0, 0, 0]); // authority, additional

        let name_at = p.len();
        for label in name.split('.') {
            p.push(label.len() as u8);
            p.extend_from_slice(label.as_bytes());
        }
        p.push(0);
        p.extend_from_slice(&1u16.to_be_bytes()); // qtype A
        p.extend_from_slice(&1u16.to_be_bytes()); // qclass IN

        for (kind, data) in records {
            // A compression pointer back to the question's name, which is what
            // every real resolver sends and what a parser must therefore read.
            p.push(0xC0);
            p.push(name_at as u8);
            p.extend_from_slice(&kind.to_be_bytes());
            p.extend_from_slice(&1u16.to_be_bytes()); // class IN
            p.extend_from_slice(&60u32.to_be_bytes()); // ttl
            p.extend_from_slice(&(data.len() as u16).to_be_bytes());
            p.extend_from_slice(data);
        }
        p
    }

    #[test]
    fn an_address_is_read_with_the_name_it_answered() {
        let packet = reply("example.com", &[(1, &[93, 184, 216, 34])]);
        assert_eq!(
            answers(&packet),
            vec![(
                "example.com".to_string(),
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
            )]
        );
    }

    /// One name commonly answers with several addresses, and dropping all but
    /// the first would leave most of a CDN's traffic unnamed.
    #[test]
    fn every_address_in_the_reply_is_read() {
        let packet = reply(
            "cdn.example.com",
            &[(1, &[1, 1, 1, 1]), (1, &[2, 2, 2, 2]), (1, &[3, 3, 3, 3])],
        );
        assert_eq!(answers(&packet).len(), 3);
    }

    /// AAAA records are addresses too.
    #[test]
    fn ipv6_is_read() {
        let addr = [0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let packet = reply("v6.example.com", &[(28, &addr)]);
        let got = answers(&packet);
        assert_eq!(got.len(), 1);
        assert!(got[0].1.is_ipv6());
    }

    /// A CNAME is not an address. Reading its contents as one would pair a
    /// name with four bytes of somebody else's hostname.
    #[test]
    fn a_record_that_is_not_an_address_is_skipped() {
        let packet = reply("www.example.com", &[(5, b"abc ")]);
        assert!(answers(&packet).is_empty());
    }

    /// A query carries the name but no answer. Read as a reply it would pair
    /// the name with whatever bytes followed.
    #[test]
    fn a_query_is_not_an_answer() {
        let mut packet = reply("example.com", &[(1, &[1, 2, 3, 4])]);
        packet[2] = 0x01; // clear the reply bit
        assert!(answers(&packet).is_empty());
    }

    /// A failed lookup answers nothing, whatever its answer section claims.
    #[test]
    fn a_failure_is_not_read() {
        let mut packet = reply("nope.example.com", &[(1, &[1, 2, 3, 4])]);
        packet[3] = 0x83; // NXDOMAIN
        assert!(answers(&packet).is_empty());
    }

    /// This reads packets off the network, so every length in them is a number
    /// somebody else chose. None of these may panic or hang.
    #[test]
    fn a_hostile_packet_is_refused_rather_than_trusted() {
        // Truncated everywhere.
        let full = reply("example.com", &[(1, &[1, 2, 3, 4])]);
        for n in 0..full.len() {
            let _ = answers(&full[..n]);
        }

        // A pointer at itself: the classic way to make a reader loop forever.
        let mut loopy = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        loopy.extend_from_slice(&[0xC0, 12]);
        assert!(answers(&loopy).is_empty());

        // A length that claims more than the packet holds.
        let mut lying = reply("example.com", &[(1, &[1, 2, 3, 4])]);
        let last = lying.len();
        lying[last - 6] = 0xFF;
        lying[last - 5] = 0xFF;
        let _ = answers(&lying);

        // Random noise, repeatedly.
        for seed in 0..200u32 {
            let junk: Vec<u8> = (0..64)
                .map(|i| (seed.wrapping_mul(i) % 251) as u8)
                .collect();
            let _ = answers(&junk);
        }
    }

    #[test]
    fn nothing_at_all_is_not_a_reply() {
        assert!(answers(&[]).is_empty());
        assert!(answers(&[0; 11]).is_empty());
    }
}
