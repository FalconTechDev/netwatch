//! What has been seen so far, per process and per peer.
//!
//! Totals answer "who used the connection today"; rates answer "who is using
//! it right now". Both are wanted, and they are different questions, so both
//! are kept: totals accumulate for the life of the run, rates are the delta
//! over the last tick and nothing more.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::Instant;

use crate::etw::{Dir, Event, Proto, Transfer};
use crate::procs::{Info, Names};

#[derive(Default, Clone)]
pub struct Traffic {
    pub sent: u64,
    pub received: u64,
}

impl Traffic {
    pub fn total(&self) -> u64 {
        self.sent + self.received
    }
}

pub struct Peer {
    pub addr: IpAddr,
    pub port: u16,
    pub proto: Proto,
    pub traffic: Traffic,
    pub last_seen: Instant,
    /// The name this machine asked for when it looked the address up. None
    /// when nothing looked it up — a hard-coded address, a cached answer from
    /// before this session, a peer reached by address on purpose.
    pub host: Option<String>,
    /// Totals as of the last time a minute was written to the log.
    minute_base: Traffic,
}

pub struct Process {
    pub pid: u32,
    pub name: String,
    /// Where it lives on disk, who it says wrote it. Resolved once, when the
    /// process is first seen sending or receiving anything.
    pub info: Info,
    pub traffic: Traffic,
    /// Bytes per second over the last tick, not since the start.
    pub sent_rate: f64,
    pub received_rate: f64,
    pub peers: HashMap<IpAddr, Peer>,
    /// When netwatch first saw this process move anything. Not when the
    /// process started — netwatch cannot know that about something already
    /// running — which is why the screen says "seen" rather than "running".
    pub first_seen: Instant,
    pub last_seen: Instant,
    /// Total bytes per second for each of the last `HISTORY` ticks, oldest
    /// first. A shape says something a single number cannot: a steady stream
    /// and one large burst can average to exactly the same rate.
    pub history: VecDeque<f64>,
    /// Totals as of the previous tick, which is what makes a rate a rate.
    previous: Traffic,
    /// Totals as of the last minute written to the log. Separate from
    /// `previous` on purpose: the screen's tick and the log's minute are
    /// different clocks, and sharing one baseline would make each steal the
    /// other's bytes.
    minute_base: Traffic,
}

impl Process {
    pub fn rate(&self) -> f64 {
        self.sent_rate + self.received_rate
    }
}

/// One process's traffic over one minute, ready for the log.
pub struct MinuteRow {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub sent: u64,
    pub received: u64,
    pub peers: String,
}

/// How many ticks of rate history each process keeps. At one tick a second
/// that is the last minute, which is the span over which "is it still going"
/// is a useful question.
pub const HISTORY: usize = 60;

pub struct State {
    procs: HashMap<u32, Process>,
    names: Names,
    /// Every address this machine has looked up, and the name it asked for.
    hosts: HashMap<IpAddr, String>,
    pub total: Traffic,
    /// Events that arrived, whether or not they were for a process we can name.
    pub events: u64,
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    pub fn new() -> Self {
        Self {
            procs: HashMap::new(),
            names: Names::new(),
            hosts: HashMap::new(),
            total: Traffic::default(),
            events: 0,
        }
    }

    pub fn apply(&mut self, ev: Event) {
        match ev {
            Event::Transfer(t) => self.apply_transfer(t),
            Event::Named { addr, host } => self.apply_name(addr, host),
        }
    }

    /// Remember a lookup, and name anything already talking to that address.
    ///
    /// The backfill matters: a program often connects before we see the answer
    /// — a cached lookup, or one that happened before netwatch started — and
    /// without it those peers would stay anonymous for the whole session.
    fn apply_name(&mut self, addr: IpAddr, host: String) {
        for p in self.procs.values_mut() {
            if let Some(peer) = p.peers.get_mut(&addr)
                && peer.host.is_none()
            {
                peer.host = Some(host.clone());
            }
        }
        self.hosts.entry(addr).or_insert(host);
    }

    fn apply_transfer(&mut self, ev: Transfer) {
        self.events += 1;
        let now = Instant::now();

        match ev.dir {
            Dir::Sent => self.total.sent += ev.bytes,
            Dir::Received => self.total.received += ev.bytes,
        }

        let info = self.names.get(ev.pid).clone();
        let proc = self.procs.entry(ev.pid).or_insert_with(|| Process {
            pid: ev.pid,
            name: info.name.clone(),
            info,
            traffic: Traffic::default(),
            sent_rate: 0.0,
            received_rate: 0.0,
            peers: HashMap::new(),
            first_seen: now,
            last_seen: now,
            history: VecDeque::with_capacity(HISTORY),
            previous: Traffic::default(),
            minute_base: Traffic::default(),
        });

        proc.last_seen = now;
        let known = self.hosts.get(&ev.peer).cloned();
        let peer = proc.peers.entry(ev.peer).or_insert_with(|| Peer {
            addr: ev.peer,
            port: ev.peer_port,
            proto: ev.proto,
            traffic: Traffic::default(),
            last_seen: now,
            host: known,
            minute_base: Traffic::default(),
        });
        peer.last_seen = now;
        // A peer's port is whatever it was last talking on; for a server that
        // is stable, and for anything else the address is the identity anyway.
        peer.port = ev.peer_port;

        match ev.dir {
            Dir::Sent => {
                proc.traffic.sent += ev.bytes;
                peer.traffic.sent += ev.bytes;
            }
            Dir::Received => {
                proc.traffic.received += ev.bytes;
                peer.traffic.received += ev.bytes;
            }
        }
    }

    /// Turn the bytes since the last call into a per-second rate.
    ///
    /// `elapsed` is passed in rather than measured here so the caller's tick
    /// and the arithmetic cannot disagree — a rate computed against a
    /// different interval than the one that actually passed is wrong in a way
    /// that looks perfectly plausible.
    pub fn tick(&mut self, elapsed: f64) {
        if elapsed <= 0.0 {
            return;
        }
        for p in self.procs.values_mut() {
            p.sent_rate = (p.traffic.sent - p.previous.sent) as f64 / elapsed;
            p.received_rate = (p.traffic.received - p.previous.received) as f64 / elapsed;
            p.previous = p.traffic.clone();

            // Every process gets a point every tick, including zero: a gap
            // drawn as nothing would read as "no data" when it means "idle".
            p.history.push_back(p.sent_rate + p.received_rate);
            while p.history.len() > HISTORY {
                p.history.pop_front();
            }
        }
    }

    /// Processes worth showing, busiest first. `by_rate` sorts by what is
    /// moving now; otherwise by what has moved in total.
    pub fn ranked(&self, by_rate: bool) -> Vec<&Process> {
        let mut v: Vec<&Process> = self
            .procs
            .values()
            .filter(|p| p.traffic.total() > 0)
            .collect();
        if by_rate {
            v.sort_by(|a, b| {
                b.rate()
                    .partial_cmp(&a.rate())
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| b.traffic.total().cmp(&a.traffic.total()))
            });
        } else {
            v.sort_by_key(|p| std::cmp::Reverse(p.traffic.total()));
        }
        v
    }

    /// Fold recorded history into the totals, so the live view opens knowing
    /// what happened before it was started.
    ///
    /// Without this the screen answers "since you pressed enter", which is
    /// almost never the question — the machine has been up for hours and the
    /// recorder was watching all of it. Rates are deliberately left alone:
    /// they describe now, and a minute from three hours ago is not now.
    pub fn seed(&mut self, rows: &[crate::log::Row]) -> usize {
        let now = Instant::now();
        for r in rows {
            self.total.sent += r.sent;
            self.total.received += r.received;

            let proc = self.procs.entry(r.pid).or_insert_with(|| Process {
                pid: r.pid,
                name: r.name.clone(),
                info: Info {
                    name: r.name.clone(),
                    path: r.path.clone(),
                    ..Info::default()
                },
                traffic: Traffic::default(),
                sent_rate: 0.0,
                received_rate: 0.0,
                peers: HashMap::new(),
                first_seen: now,
                last_seen: now,
                history: VecDeque::with_capacity(HISTORY),
                previous: Traffic::default(),
                minute_base: Traffic::default(),
            });
            proc.traffic.sent += r.sent;
            proc.traffic.received += r.received;

            // The baselines move with the totals, or the first tick after
            // loading would report three hours of traffic as one second of it.
            proc.previous = proc.traffic.clone();
            proc.minute_base = proc.traffic.clone();

            for part in r.peers.split(';').filter(|s| !s.is_empty()) {
                let Some((who, moved)) = part.rsplit_once('=') else {
                    continue;
                };
                let Ok(moved) = moved.parse::<u64>() else {
                    continue;
                };
                // `name@addr:port` when the machine looked it up, plain
                // `addr:port` when it did not.
                let (host, endpoint) = match who.split_once('@') {
                    Some((h, e)) => (Some(h.to_string()), e),
                    None => (None, who),
                };
                let Some((addr, port)) = endpoint.rsplit_once(':') else {
                    continue;
                };
                let (Ok(addr), Ok(port)) = (addr.parse::<IpAddr>(), port.parse::<u16>()) else {
                    continue;
                };
                let peer = proc.peers.entry(addr).or_insert_with(|| Peer {
                    addr,
                    port,
                    proto: Proto::Tcp,
                    traffic: Traffic::default(),
                    last_seen: now,
                    host: host.clone(),
                    minute_base: Traffic::default(),
                });
                // The log keeps one figure per peer per minute rather than a
                // direction, so it lands where it cannot be mistaken for a
                // measured split: received, and said so in the README.
                peer.traffic.received += moved;
                peer.minute_base = peer.traffic.clone();
                if peer.host.is_none() {
                    peer.host = host;
                }
            }
        }
        rows.len()
    }

    pub fn get(&self, pid: u32) -> Option<&Process> {
        self.procs.get(&pid)
    }

    /// Replace what is known about a process. Only the tests use this: they
    /// have to describe a program that is not running on the machine the test
    /// happens to be executing on, or they would assert against whatever was.
    #[cfg(test)]
    pub fn set_info(&mut self, pid: u32, info: Info) {
        if let Some(p) = self.procs.get_mut(&pid) {
            p.name = info.name.clone();
            p.info = info;
        }
    }

    /// What moved since this was last called, per process, resetting the
    /// baseline as it goes. This is what the log records: a minute's traffic
    /// rather than a running total, so a reader can add up any span they like.
    ///
    /// `top_peers` bounds how many destinations each line names — one chatty
    /// program must not be able to make a log line unbounded.
    pub fn take_minute(&mut self, top_peers: usize) -> Vec<MinuteRow> {
        let mut out = Vec::new();
        for p in self.procs.values_mut() {
            let sent = p.traffic.sent - p.minute_base.sent;
            let received = p.traffic.received - p.minute_base.received;
            p.minute_base = p.traffic.clone();

            // Peer baselines move whether or not the process is reported, so a
            // quiet minute cannot leave stale bytes to be counted later.
            let mut peers: Vec<(String, u64)> = Vec::new();
            for peer in p.peers.values_mut() {
                let moved = (peer.traffic.sent - peer.minute_base.sent)
                    + (peer.traffic.received - peer.minute_base.received);
                peer.minute_base = peer.traffic.clone();
                if moved > 0 {
                    // `name@addr:port` when the machine looked it up, plain
                    // `addr:port` when it did not. The address is always there
                    // because it is the identity; the name is what makes the
                    // line readable a week later.
                    let who = match &peer.host {
                        Some(h) => format!("{h}@{}:{}", peer.addr, peer.port),
                        None => format!("{}:{}", peer.addr, peer.port),
                    };
                    peers.push((who, moved));
                }
            }

            if sent == 0 && received == 0 {
                continue;
            }
            peers.sort_by_key(|(_, b)| std::cmp::Reverse(*b));
            peers.truncate(top_peers);
            out.push(MinuteRow {
                pid: p.pid,
                name: p.name.clone(),
                path: p.info.path.clone(),
                sent,
                received,
                peers: peers
                    .iter()
                    .map(|(a, b)| format!("{a}={b}"))
                    .collect::<Vec<_>>()
                    .join(";"),
            });
        }
        out.sort_by_key(|r| std::cmp::Reverse(r.sent + r.received));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ev(pid: u32, dir: Dir, bytes: u64, peer: [u8; 4]) -> Event {
        Event::Transfer(Transfer {
            pid,
            proto: Proto::Tcp,
            dir,
            bytes,
            peer: IpAddr::V4(Ipv4Addr::from(peer)),
            peer_port: 443,
        })
    }

    fn named(peer: [u8; 4], host: &str) -> Event {
        Event::Named {
            addr: IpAddr::V4(Ipv4Addr::from(peer)),
            host: host.into(),
        }
    }

    /// A name is only worth showing if it is the one the machine asked for.
    #[test]
    fn a_looked_up_address_gets_its_name() {
        let mut s = State::new();
        s.apply(named([140, 82, 114, 25], "api.github.com"));
        s.apply(ev(1, Dir::Received, 500, [140, 82, 114, 25]));

        let p = s.get(1).unwrap();
        let peer = &p.peers[&IpAddr::V4(Ipv4Addr::new(140, 82, 114, 25))];
        assert_eq!(peer.host.as_deref(), Some("api.github.com"));
        // The address is kept alongside the name, never replaced by it.
        assert_eq!(peer.addr, IpAddr::V4(Ipv4Addr::new(140, 82, 114, 25)));
        assert_eq!(peer.port, 443);
    }

    /// Traffic usually arrives before we see the answer — a cached lookup, or
    /// one from before netwatch started. Without backfilling, those peers
    /// would stay anonymous for the whole session.
    #[test]
    fn a_name_learned_later_still_reaches_the_peer() {
        let mut s = State::new();
        s.apply(ev(1, Dir::Received, 500, [93, 184, 216, 34]));
        assert!(
            s.get(1).unwrap().peers[&IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
                .host
                .is_none()
        );

        s.apply(named([93, 184, 216, 34], "example.com"));
        assert_eq!(
            s.get(1).unwrap().peers[&IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
                .host
                .as_deref(),
            Some("example.com")
        );
    }

    /// An address nobody looked up stays an address. Inventing a name for it
    /// would be worse than leaving it bare.
    #[test]
    fn an_address_nobody_looked_up_stays_an_address() {
        let mut s = State::new();
        s.apply(ev(1, Dir::Sent, 10, [10, 0, 0, 5]));
        let peer = &s.get(1).unwrap().peers[&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))];
        assert!(peer.host.is_none());
        assert_eq!(peer.addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)));
    }

    /// The first name wins. A later lookup that maps a different name onto the
    /// same address must not rewrite history mid-session.
    #[test]
    fn the_name_that_was_asked_for_first_is_kept() {
        let mut s = State::new();
        s.apply(named([1, 1, 1, 1], "first.example"));
        s.apply(named([1, 1, 1, 1], "second.example"));
        s.apply(ev(1, Dir::Sent, 10, [1, 1, 1, 1]));
        assert_eq!(
            s.get(1).unwrap().peers[&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]
                .host
                .as_deref(),
            Some("first.example")
        );
    }

    /// The log line has to carry both: the address is the identity, the name is
    /// what makes it readable a week later.
    #[test]
    fn the_log_keeps_the_name_and_the_address() {
        let mut s = State::new();
        s.apply(named([140, 82, 114, 25], "api.github.com"));
        s.apply(ev(1, Dir::Received, 500, [140, 82, 114, 25]));
        s.apply(ev(1, Dir::Sent, 10, [10, 0, 0, 5]));

        let rows = s.take_minute(3);
        let peers = &rows[0].peers;
        assert!(
            peers.contains("api.github.com@140.82.114.25:443"),
            "{peers}"
        );
        assert!(peers.contains("10.0.0.5:443"), "unnamed peer kept: {peers}");
    }

    #[test]
    fn traffic_lands_against_the_process_and_the_peer() {
        let mut s = State::new();
        s.apply(ev(100, Dir::Sent, 1_000, [1, 1, 1, 1]));
        s.apply(ev(100, Dir::Received, 4_000, [1, 1, 1, 1]));
        s.apply(ev(100, Dir::Sent, 500, [2, 2, 2, 2]));

        let p = s.get(100).unwrap();
        assert_eq!(p.traffic.sent, 1_500);
        assert_eq!(p.traffic.received, 4_000);
        assert_eq!(p.peers.len(), 2, "two peers, not one bucket");

        let first = p.peers[&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]
            .traffic
            .clone();
        assert_eq!(first.sent, 1_000);
        assert_eq!(first.received, 4_000);
    }

    /// Direction has to survive all the way through, or "downloaded" and
    /// "uploaded" swap places and the whole display lies quietly.
    #[test]
    fn direction_is_not_conflated() {
        let mut s = State::new();
        s.apply(ev(1, Dir::Received, 9_000, [8, 8, 8, 8]));
        assert_eq!(s.total.received, 9_000);
        assert_eq!(s.total.sent, 0);
    }

    #[test]
    fn a_rate_is_the_delta_over_the_interval_that_passed() {
        let mut s = State::new();
        s.apply(ev(7, Dir::Received, 2_000, [3, 3, 3, 3]));
        s.tick(2.0);
        assert_eq!(s.get(7).unwrap().received_rate, 1_000.0);

        // Nothing new in the next interval: the rate must fall to zero rather
        // than keep reporting the old burst.
        s.tick(2.0);
        assert_eq!(s.get(7).unwrap().received_rate, 0.0);
        // …while the total stays where it was.
        assert_eq!(s.get(7).unwrap().traffic.received, 2_000);
    }

    #[test]
    fn a_zero_interval_does_not_divide_by_it() {
        let mut s = State::new();
        s.apply(ev(1, Dir::Sent, 100, [1, 2, 3, 4]));
        s.tick(0.0);
        assert!(s.get(1).unwrap().sent_rate.is_finite());
    }

    #[test]
    fn ranking_can_ask_either_question() {
        let mut s = State::new();
        // A process with a large total that has since gone quiet…
        s.apply(ev(1, Dir::Received, 10_000, [1, 1, 1, 1]));
        s.tick(1.0);
        // …and one that is busy right now but has moved less overall.
        s.apply(ev(2, Dir::Received, 3_000, [2, 2, 2, 2]));
        s.tick(1.0);

        assert_eq!(s.ranked(false)[0].pid, 1, "by total, the big one leads");
        assert_eq!(s.ranked(true)[0].pid, 2, "by rate, the busy one leads");
    }

    /// A process that has been seen but moved nothing is noise in a list whose
    /// entire purpose is showing who is using the connection.
    #[test]
    fn silent_processes_are_not_listed() {
        let mut s = State::new();
        s.apply(ev(5, Dir::Sent, 0, [1, 1, 1, 1]));
        assert!(s.ranked(false).is_empty());
    }
}
