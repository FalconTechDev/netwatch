//! What has been seen so far, per process and per peer.
//!
//! Totals answer "who used the connection today"; rates answer "who is using
//! it right now". Both are wanted, and they are different questions, so both
//! are kept: totals accumulate for the life of the run, rates are the delta
//! over the last tick and nothing more.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use crate::etw::{Dir, Event, Proto};
use crate::procs::Names;

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
}

pub struct Process {
    pub pid: u32,
    pub name: String,
    pub traffic: Traffic,
    /// Bytes per second over the last tick, not since the start.
    pub sent_rate: f64,
    pub received_rate: f64,
    pub peers: HashMap<IpAddr, Peer>,
    pub last_seen: Instant,
    /// Totals as of the previous tick, which is what makes a rate a rate.
    previous: Traffic,
}

impl Process {
    pub fn rate(&self) -> f64 {
        self.sent_rate + self.received_rate
    }
}

pub struct State {
    procs: HashMap<u32, Process>,
    names: Names,
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
            total: Traffic::default(),
            events: 0,
        }
    }

    pub fn apply(&mut self, ev: Event) {
        self.events += 1;
        let now = Instant::now();

        match ev.dir {
            Dir::Sent => self.total.sent += ev.bytes,
            Dir::Received => self.total.received += ev.bytes,
        }

        let names = &mut self.names;
        let proc = self.procs.entry(ev.pid).or_insert_with(|| Process {
            pid: ev.pid,
            name: names.get(ev.pid).to_string(),
            traffic: Traffic::default(),
            sent_rate: 0.0,
            received_rate: 0.0,
            peers: HashMap::new(),
            last_seen: now,
            previous: Traffic::default(),
        });

        proc.last_seen = now;
        let peer = proc.peers.entry(ev.peer).or_insert_with(|| Peer {
            addr: ev.peer,
            port: ev.peer_port,
            proto: ev.proto,
            traffic: Traffic::default(),
            last_seen: now,
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

    pub fn get(&self, pid: u32) -> Option<&Process> {
        self.procs.get(&pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ev(pid: u32, dir: Dir, bytes: u64, peer: [u8; 4]) -> Event {
        Event {
            pid,
            proto: Proto::Tcp,
            dir,
            bytes,
            peer: IpAddr::V4(Ipv4Addr::from(peer)),
            peer_port: 443,
        }
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
