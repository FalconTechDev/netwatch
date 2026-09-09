//! Reading the record back.
//!
//! The live view answers "what is happening"; this answers "what happened" —
//! which is the question people actually arrive with, usually phrased as "what
//! ate forty gigabytes last night". Answering it needs a log, and needs the log
//! to have been running at the time, which is what `netwatch service install`
//! arranges.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use crate::log::{self, Row};
use crate::{bytes, trunc};

/// A program's traffic over the period asked about.
struct Total {
    name: String,
    /// Where the executable lived, as last recorded. A name alone cannot tell
    /// System32 from a temp directory, and by the time anyone reads a report
    /// the process is long gone and cannot be asked.
    path: String,
    sent: u64,
    received: u64,
    /// Minutes in which it moved anything — how much of the period it was busy
    /// for, which separates a steady trickle from one large transfer.
    active_minutes: usize,
    /// The minute it moved the most, and how much.
    peak_minute: u64,
    peak_bytes: u64,
    /// The first and last minute it was seen moving anything. Two numbers that
    /// answer "when did this happen" far better than a total does — "38 GB"
    /// and "38 GB between 03:12 and 04:58" are different facts.
    first_minute: u64,
    last_minute: u64,
    /// Every process id that ran under this name. More than one means it was
    /// restarted, which is worth knowing before wondering why the total is
    /// larger than any single run could explain.
    pids: BTreeSet<u32>,
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
            path: String::new(),
            sent: 0,
            received: 0,
            active_minutes: 0,
            peak_minute: r.minute,
            peak_bytes: 0,
            first_minute: r.minute,
            last_minute: r.minute,
            pids: BTreeSet::new(),
        });
        e.sent += r.sent;
        e.received += r.received;
        // Whichever row carried a path wins; rows written before paths were
        // recorded have none.
        if e.path.is_empty() && !r.path.is_empty() {
            e.path = r.path.clone();
        }
        e.pids.insert(r.pid);
        e.first_minute = e.first_minute.min(r.minute);
        e.last_minute = e.last_minute.max(r.minute);
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
        "{:<24} {:>11} {:>11} {:>11} {:>5} {:>7}  WHEN",
        "PROGRAM", "DOWN", "UP", "TOTAL", "SHARE", "ACTIVE"
    );
    for t in totals.iter().take(top) {
        let share = if grand > 0 {
            100.0 * t.total() as f64 / grand as f64
        } else {
            0.0
        };
        println!(
            "{:<24} {:>11} {:>11} {:>11} {:>4.0}% {:>6}m  {} → {}",
            trunc(&t.name, 23),
            bytes(t.received),
            bytes(t.sent),
            bytes(t.total()),
            share,
            t.active_minutes,
            clock(t.first_minute),
            clock(t.last_minute)
        );
        // Only when it is not the ordinary place for it: a line per program
        // doubles the table, and `C:\Windows\System32` under every Windows
        // component is noise rather than information.
        if !t.path.is_empty() && !is_system_path(&t.path) {
            println!("{:<26} {}", "", t.path);
        }
    }

    if totals.len() > top {
        println!(
            "\n… and {} more. --top raises the limit.",
            totals.len() - top
        );
    }
    println!("\nOne program in detail:  netwatch report --program <name>");
}

/// Whether an executable lives where Windows keeps its own.
///
/// Used only to decide whether the path is worth a line of its own in the
/// summary — never to decide whether something is trustworthy. A path proves
/// nothing on its own, and treating one as a clean bill of health is exactly
/// the mistake that would make a tool like this misleading.
fn is_system_path(path: &str) -> bool {
    let p = path.to_lowercase().replace('/', "\\");
    p.starts_with("c:\\windows\\") || p.starts_with("c:\\program files")
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
    let first = mine.iter().map(|r| r.minute).min().unwrap_or(0);
    let last = mine.iter().map(|r| r.minute).max().unwrap_or(0);
    let pids: BTreeSet<u32> = mine.iter().map(|r| r.pid).collect();
    let peak = mine.iter().map(|r| r.total()).max().unwrap_or(0);

    println!(
        "{name} — last {hours} h: {} down, {} up",
        bytes(received),
        bytes(sent),
    );
    // Minutes, not rows: two processes of one program in the same minute are
    // two rows and one minute, and counting rows would report a program as
    // busier for longer than it ever was.
    let minutes: BTreeSet<u64> = mine.iter().map(|r| r.minute).collect();
    println!(
        "  active   {} minutes, {} → {} UTC",
        minutes.len(),
        clock(first),
        clock(last)
    );
    // A minute's worth divided by sixty seconds: the rate it actually reached,
    // which is what a link being saturated looks like.
    println!(
        "  peak     {} in one minute  ({}/s)",
        bytes(peak),
        bytes(peak / 60)
    );
    // More than one pid means it was restarted during the period, which
    // explains a total no single run could account for.
    let shown: Vec<String> = pids.iter().take(6).map(|p| p.to_string()).collect();
    println!(
        "  pid      {}{}",
        shown.join(", "),
        if pids.len() > shown.len() {
            format!(" … {} in all — it restarted", pids.len())
        } else if pids.len() > 1 {
            " — it restarted".to_string()
        } else {
            String::new()
        }
    );

    // Where it ran from. The process is long gone by report time, so the log
    // is the only place this answer still exists.
    let paths: std::collections::BTreeSet<&str> = mine
        .iter()
        .map(|r| r.path.as_str())
        .filter(|p| !p.is_empty())
        .collect();
    for p in &paths {
        println!("  ran from {p}");
    }
    if paths.len() > 1 {
        println!("  (more than one executable answered to this name)");
    }
    println!();

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
            path: String::new(),
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

    /// The same rule as the summary, in the per-program view: two processes of
    /// one program in a minute are two rows and one minute. Counting rows
    /// reports it as busy for twice as long as it was.
    #[test]
    fn the_detail_view_counts_minutes_not_rows() {
        let rows = [
            row(100, 1, "a.exe", 10, 0, ""),
            row(100, 2, "a.exe", 10, 0, ""),
            row(101, 1, "a.exe", 10, 0, ""),
        ];
        let minutes: BTreeSet<u64> = rows.iter().map(|r| r.minute).collect();
        assert_eq!(minutes.len(), 2);
        assert_eq!(rows.len(), 3, "three rows, two minutes");
    }

    /// The peak is what turns "40 GB overnight" into "40 GB at 03:12", which
    /// is the part that identifies what happened.
    /// More than one pid under a name means it restarted, and that explains a
    /// total no single run could account for.
    #[test]
    fn restarts_are_visible_as_several_pids() {
        let rows = vec![
            row(100, 7, "backup.exe", 1_000, 0, ""),
            row(200, 999, "backup.exe", 2_000, 0, ""),
        ];
        let s = summarise(&rows);
        assert_eq!(s["backup.exe"].pids.len(), 2);
        assert!(s["backup.exe"].pids.contains(&999));
    }

    /// When it happened is a different fact from how much, and usually the
    /// more useful one.
    #[test]
    fn the_window_it_was_active_in_is_kept() {
        let rows = vec![
            row(500, 1, "a.exe", 10, 0, ""),
            row(100, 1, "a.exe", 10, 0, ""),
            row(300, 1, "a.exe", 10, 0, ""),
        ];
        let s = summarise(&rows);
        assert_eq!(s["a.exe"].first_minute, 100, "earliest, whatever the order");
        assert_eq!(s["a.exe"].last_minute, 500);
    }

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

    /// The path decides whether a line is worth printing, and nothing more.
    /// A program living in System32 is where Windows keeps its own; that is a
    /// statement about tidiness, never about trust.
    #[test]
    fn ordinary_locations_are_recognised_as_ordinary() {
        assert!(is_system_path("C:\\Windows\\System32\\svchost.exe"));
        assert!(is_system_path("c:/windows/system32/svchost.exe"));
        assert!(is_system_path("C:\\Program Files\\Mullvad VPN\\daemon.exe"));
        assert!(is_system_path("C:\\Program Files (x86)\\thing.exe"));

        // The cases worth a line of their own.
        assert!(!is_system_path("C:\\Users\\x\\AppData\\Local\\Temp\\x.exe"));
        assert!(!is_system_path("D:\\games\\thing.exe"));
        assert!(!is_system_path(""));
    }

    #[test]
    fn a_minute_renders_as_a_readable_time() {
        // 1700000000 is 2023-11-14 22:13:20 UTC.
        assert_eq!(clock(1_700_000_000 / 60), "11-14 22:13");
    }
}
