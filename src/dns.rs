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
