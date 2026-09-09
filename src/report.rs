//! Reading the record back.
//!
//! The live view answers "what is happening"; this answers "what happened" —
//! which is the question people actually arrive with, usually phrased as "what
//! ate forty gigabytes last night". Answering it needs a log, and needs the log
//! to have been running at the time, which is what `netwatch service install`
//! arranges.

use std::collections::HashMap;
use std::path::Path;

use crate::log::{self, Row};
use crate::{bytes, trunc};

/// A program's traffic over the period asked about.
struct Total {
    name: String,
    sent: u64,
    received: u64,
    /// Minutes in which it moved anything — how much of the period it was busy
    /// for, which separates a steady trickle from one large transfer.
    active_minutes: usize,
    /// The minute it moved the most, and how much.
    peak_minute: u64,
    peak_bytes: u64,
}

impl Total {
    fn total(&self) -> u64 {
        self.sent + self.received
    }
}

pub fn run(dir: &Path, hours: u64, program: Option<String>, top: usize) -> Result<(), String> {
    let now = log::now_secs();
    let from = (now.saturating_sub(hours * 3_600)) / 60;
    let rows = log::read_range(dir, from, u64::MAX);

    if rows.is_empty() {
        println!(
            "Nothing recorded for the last {hours} h in {}.",
            dir.display()
        );
        println!();
        println!("If netwatch was not running then, it could not have seen it.");
        println!("To record from now on, from an elevated terminal:");
        println!("    netwatch service install");
        return Ok(());
    }

    match program {
        Some(name) => one_program(&rows, &name, hours),
        None => everything(&rows, hours, top),
    }
    Ok(())
}

fn summarise(rows: &[Row]) -> HashMap<String, Total> {
    let mut by_name: HashMap<String, Total> = HashMap::new();
    // A program's bytes are added up by name, not by pid: the same program
    // restarted is the same program, and a report split across three pids of
    // "backup.exe" answers nobody's question.
    let mut per_minute: HashMap<(String, u64), u64> = HashMap::new();

    for r in rows {
        let e = by_name.entry(r.name.clone()).or_insert_with(|| Total {
            name: r.name.clone(),
            sent: 0,
            received: 0,
            active_minutes: 0,
            peak_minute: r.minute,
            peak_bytes: 0,
        });
        e.sent += r.sent;
        e.received += r.received;
        *per_minute.entry((r.name.clone(), r.minute)).or_insert(0) += r.total();
    }

    for ((name, minute), moved) in per_minute {
        if let Some(t) = by_name.get_mut(&name) {
            t.active_minutes += 1;
            if moved > t.peak_bytes {
                t.peak_bytes = moved;
                t.peak_minute = minute;
            }
        }
    }
    by_name
}

/// Minutes since the epoch as a wall clock, UTC — the same clock the log is
/// written on, so a time printed here matches a time in the file.
fn clock(minute: u64) -> String {
    let secs = minute * 60;
    let (_, m, d) = log::civil_from_secs(secs);
    let day = secs % 86_400;
    format!(
        "{:02}-{:02} {:02}:{:02}",
        m,
        d,
        day / 3600,
        (day % 3600) / 60
    )
}

fn everything(rows: &[Row], hours: u64, top: usize) {
    let by_name = summarise(rows);
    let mut totals: Vec<&Total> = by_name.values().collect();
    totals.sort_by_key(|t| std::cmp::Reverse(t.total()));

    let grand: u64 = totals.iter().map(|t| t.total()).sum();
    let first = rows.iter().map(|r| r.minute).min().unwrap_or(0);
    let last = rows.iter().map(|r| r.minute).max().unwrap_or(0);

    println!(
        "Last {hours} h — {} moved by {} programs, {} to {} UTC\n",
        bytes(grand),
        totals.len(),
        clock(first),
        clock(last)
    );

    println!(
        "{:<26} {:>11} {:>11} {:>11} {:>8}  BUSIEST MINUTE",
        "PROGRAM", "DOWN", "UP", "TOTAL", "ACTIVE"
    );
    for t in totals.iter().take(top) {
        println!(
            "{:<26} {:>11} {:>11} {:>11} {:>7}m  {} ({})",
            trunc(&t.name, 25),
            bytes(t.received),
            bytes(t.sent),
            bytes(t.total()),
            t.active_minutes,
            clock(t.peak_minute),
            bytes(t.peak_bytes)
        );
    }

    if totals.len() > top {
        println!(
            "\n… and {} more. --top raises the limit.",
            totals.len() - top
        );
    }
    println!("\nOne program in detail:  netwatch report --program <name>");
}

fn one_program(rows: &[Row], name: &str, hours: u64) {
    let want = name.to_lowercase();
    let mine: Vec<&Row> = rows
        .iter()
        .filter(|r| r.name.to_lowercase().contains(&want))
        .collect();

    if mine.is_empty() {
        println!("Nothing recorded for a program matching \"{name}\" in the last {hours} h.");
        return;
    }

    let sent: u64 = mine.iter().map(|r| r.sent).sum();
    let received: u64 = mine.iter().map(|r| r.received).sum();
    println!(
        "{name} — last {hours} h: {} down, {} up, over {} minutes\n",
        bytes(received),
        bytes(sent),
        mine.len()
    );

    // Where it went. The log keeps only the busiest few peers per minute, so
    // this is where the bulk went rather than an exhaustive list — said here
    // rather than left to be assumed.
    let mut peers: HashMap<String, u64> = HashMap::new();
    for r in &mine {
        for part in r.peers.split(';').filter(|s| !s.is_empty()) {
            if let Some((addr, n)) = part.rsplit_once('=')
                && let Ok(n) = n.parse::<u64>()
            {
                *peers.entry(addr.to_string()).or_insert(0) += n;
            }
        }
    }
    let mut peers: Vec<(String, u64)> = peers.into_iter().collect();
    peers.sort_by_key(|(_, b)| std::cmp::Reverse(*b));

    if !peers.is_empty() {
        println!("{:<44} {:>12}", "WHERE THE BULK WENT", "BYTES");
        for (addr, n) in peers.iter().take(15) {
            println!("{:<44} {:>12}", addr, bytes(*n));
        }
        println!("\n(the busiest three destinations a minute are kept, not every one)");
    }

    let mut busiest: Vec<&&Row> = mine.iter().collect();
    busiest.sort_by_key(|r| std::cmp::Reverse(r.total()));
    println!("\n{:<18} {:>12}", "BUSIEST MINUTES", "MOVED");
    for r in busiest.iter().take(8) {
        println!("{:<18} {:>12}", clock(r.minute), bytes(r.total()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(minute: u64, pid: u32, name: &str, sent: u64, received: u64, peers: &str) -> Row {
        Row {
            minute,
            pid,
            name: name.into(),
            sent,
            received,
            peers: peers.into(),
        }
    }

    /// The same program restarted has a new pid, and a report that splits it
    /// into two lines answers nobody's question.
    #[test]
    fn one_program_across_several_pids_is_one_line() {
        let rows = vec![
            row(100, 1, "backup.exe", 1_000, 0, ""),
            row(101, 999, "backup.exe", 2_000, 0, ""),
            row(102, 5, "other.exe", 50, 0, ""),
        ];
        let s = summarise(&rows);
        assert_eq!(s.len(), 2);
        assert_eq!(s["backup.exe"].sent, 3_000);
    }

    #[test]
    fn active_minutes_count_minutes_not_rows() {
        let rows = vec![
            // Two pids of one program in the same minute is still one minute.
            row(100, 1, "a.exe", 10, 0, ""),
            row(100, 2, "a.exe", 10, 0, ""),
            row(101, 1, "a.exe", 10, 0, ""),
        ];
        let s = summarise(&rows);
        assert_eq!(s["a.exe"].active_minutes, 2);
    }

    /// The peak is what turns "40 GB overnight" into "40 GB at 03:12", which
    /// is the part that identifies what happened.
    #[test]
    fn the_busiest_minute_is_found() {
        let rows = vec![
            row(100, 1, "a.exe", 10, 10, ""),
            row(200, 1, "a.exe", 5_000, 5_000, ""),
            row(300, 1, "a.exe", 20, 20, ""),
        ];
        let s = summarise(&rows);
        assert_eq!(s["a.exe"].peak_minute, 200);
        assert_eq!(s["a.exe"].peak_bytes, 10_000);
    }

    #[test]
    fn a_minute_renders_as_a_readable_time() {
        // 1700000000 is 2023-11-14 22:13:20 UTC.
        assert_eq!(clock(1_700_000_000 / 60), "11-14 22:13");
    }
}
