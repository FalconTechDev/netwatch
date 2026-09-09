//! netwatch — which program is using your connection, and how much.
//!
//! Windows will not tell you this. Task Manager shows a total, Resource
//! Monitor shows a snapshot that forgets itself, and the tools that do it
//! properly are paid. The answer is available: the kernel reports every
//! transfer against the process that caused it, and this reads that.

mod dns;
mod etw;
mod hidden;
mod log;
mod procs;
mod report;
mod service;
mod state;
mod tui;

use std::sync::mpsc;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};

use state::State;

#[derive(Parser)]
#[command(
    name = "netwatch",
    about = "See which program is using your connection, live",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Watch live, in a full-screen view. The default.
    Live,
    /// Record to disk, forever. What the background service runs.
    Record {
        /// Where the log lives. Defaults to ProgramData\\netwatch.
        #[arg(long)]
        dir: Option<std::path::PathBuf>,
        /// Delete day files older than this.
        #[arg(long, default_value_t = 30)]
        keep_days: u64,
    },
    /// What the record says: who used the connection, and when.
    Report {
        /// How far back to look.
        #[arg(long, default_value_t = 24)]
        hours: u64,
        /// One program in detail, with where its traffic went.
        #[arg(long)]
        program: Option<String>,
        /// How many programs to list.
        #[arg(long, default_value_t = 15)]
        top: usize,
        #[arg(long)]
        dir: Option<std::path::PathBuf>,
    },
    /// Programs kept out of the live view — still recorded, still in reports.
    Hidden {
        /// Show every program again.
        #[arg(long)]
        clear: bool,
    },
    /// Start recording at boot, or stop doing so.
    Service {
        #[command(subcommand)]
        action: service::Action,
    },
    /// Watch for a fixed time, then print what happened and exit.
    Top {
        /// How long to watch.
        #[arg(long, default_value_t = 10)]
        seconds: u64,
        /// Rank by what moved most in total rather than by what is busiest now.
        #[arg(long)]
        by_total: bool,
    },
}

fn main() -> Result<(), String> {
    match Cli::parse().cmd.unwrap_or(Cmd::Live) {
        Cmd::Live => tui::run(),
        Cmd::Top { seconds, by_total } => top(seconds, by_total),
        Cmd::Record { dir, keep_days } => record(dir.unwrap_or_else(log::default_dir), keep_days),
        Cmd::Report {
            hours,
            program,
            top,
            dir,
        } => report::run(&dir.unwrap_or_else(log::default_dir), hours, program, top),
        Cmd::Hidden { clear } => hidden_list(clear),
        Cmd::Service { action } => service::run(action),
    }
}

/// Watch for a while and print the result once. Useful on its own, and the
/// thing to reach for when the full-screen view cannot be used — over SSH, in
/// a script, or piped into a file.
fn top(seconds: u64, by_total: bool) -> Result<(), String> {
    let (tx, rx) = mpsc::channel();
    let trace = etw::start(tx)?;

    println!("Watching for {seconds} s…\n");
    let started = Instant::now();
    let mut st = State::new();
    let mut last_tick = Instant::now();

    while started.elapsed() < Duration::from_secs(seconds) {
        // Drain whatever has arrived, then tick the rates on a fixed cadence.
        while let Ok(ev) = rx.try_recv() {
            st.apply(ev);
        }
        if last_tick.elapsed() >= Duration::from_secs(1) {
            st.tick(last_tick.elapsed().as_secs_f64());
            last_tick = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = trace.stop();
    while let Ok(ev) = rx.try_recv() {
        st.apply(ev);
    }

    let ranked = st.ranked(!by_total);
    if ranked.is_empty() {
        println!("Nothing moved in that time.");
        return Ok(());
    }

    println!(
        "{:<26} {:>7} {:>11} {:>11} {:>11}  PEERS",
        "PROCESS", "PID", "DOWN", "UP", "TOTAL"
    );
    for p in ranked.iter().take(20) {
        println!(
            "{:<26} {:>7} {:>11} {:>11} {:>11}  {}",
            trunc(&p.name, 25),
            p.pid,
            bytes(p.traffic.received),
            bytes(p.traffic.sent),
            bytes(p.traffic.total()),
            p.peers.len()
        );
    }

    println!(
        "\n{} processes moved {} in {:.0} s ({} events)",
        ranked.len(),
        bytes(st.total.total()),
        started.elapsed().as_secs_f64(),
        st.events
    );
    Ok(())
}

/// What the live view is leaving out, and where that is written down.
fn hidden_list(clear: bool) -> Result<(), String> {
    let path = hidden::default_path();
    let mut h = hidden::Hidden::load(path.clone());

    if clear {
        let n = h.len();
        h.clear();
        println!("Showing all {n} again.");
        return Ok(());
    }

    if h.is_empty() {
        println!("Nothing is hidden.");
        println!();
        println!("In the live view, `h` hides the selected program. It keeps");
        println!("being recorded either way — hiding only changes the screen.");
        return Ok(());
    }

    println!("Hidden from the live view ({}):", h.len());
    for name in h.names() {
        println!("  {name}");
    }
    println!();
    println!("Still recorded, and still in every report.");
    println!("Kept in {}", path.display());
    println!("Show them all again:  netwatch hidden --clear");
    Ok(())
}

/// Record until stopped. This is the mode that answers the question netwatch
/// exists for — what was downloading while nobody was watching — and it is the
/// only mode that can, because it is the only one running at the time.
fn record(dir: std::path::PathBuf, keep_days: u64) -> Result<(), String> {
    let (tx, rx) = mpsc::channel();
    let _trace = etw::start(tx)?;

    let mut st = State::new();
    let mut writer = log::Writer::new(dir.clone());
    let mut last_minute = log::now_secs() / 60;
    let mut last_prune_day = 0u64;

    eprintln!("netwatch is recording to {}", dir.display());

    loop {
        // Drain without blocking, so a burst of traffic cannot make the writer
        // fall behind the kernel's buffers.
        while let Ok(ev) = rx.try_recv() {
            st.apply(ev);
        }

        let now = log::now_secs();
        let minute = now / 60;
        if minute > last_minute {
            let rows: Vec<log::Row> = st
                .take_minute(3)
                .into_iter()
                .map(|r| log::Row {
                    // Stamped with the minute that just ended, not the one
                    // starting, so a row is filed under the time it describes.
                    minute: last_minute,
                    pid: r.pid,
                    name: r.name,
                    sent: r.sent,
                    received: r.received,
                    peers: r.peers,
                    path: r.path,
                })
                .collect();
            let moved: u64 = rows.iter().map(|r| r.sent + r.received).sum();
            if let Err(e) = writer.append(last_minute * 60, &rows) {
                eprintln!("could not write the log: {e}");
            }
            // A line a minute, so a service that is running but recording
            // nothing looks different from one that is not running at all.
            eprintln!(
                "minute {last_minute}: {} programs, {} ({} events so far)",
                rows.len(),
                bytes(moved),
                st.events
            );
            last_minute = minute;

            let day = now / 86_400;
            if day != last_prune_day {
                last_prune_day = day;
                log::prune(&dir, keep_days, now);
            }
        }

        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Byte counts are compared, not read digit by digit.
pub fn bytes(v: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut f = v as f64;
    let mut u = 0;
    while f >= 1024.0 && u < UNITS.len() - 1 {
        f /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{f:.0} B")
    } else {
        format!("{f:.1} {}", UNITS[u])
    }
}

/// Bytes per second, said the way people say it.
pub fn rate(v: f64) -> String {
    if v < 1.0 {
        return "—".into();
    }
    format!("{}/s", bytes(v as u64))
}

pub fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n - 1).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_counts_are_scaled() {
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(2048), "2.0 KB");
        assert_eq!(bytes(1_073_741_824), "1.0 GB");
    }

    /// A rate of nearly nothing should read as nothing, not as "0 B/s", which
    /// looks like a measurement rather than an absence of one.
    #[test]
    fn a_silent_process_shows_no_rate() {
        assert_eq!(rate(0.0), "—");
        assert_eq!(rate(0.4), "—");
        assert_eq!(rate(2048.0), "2.0 KB/s");
    }

    #[test]
    fn long_names_are_cut_with_a_mark() {
        assert_eq!(trunc("chrome.exe", 20), "chrome.exe");
        assert_eq!(trunc("a-very-long-process-name.exe", 10), "a-very-lo…");
    }
}
