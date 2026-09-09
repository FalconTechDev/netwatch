//! netwatch — which program is using your connection, and how much.
//!
//! Windows will not tell you this. Task Manager shows a total, Resource
//! Monitor shows a snapshot that forgets itself, and the tools that do it
//! properly are paid. The answer is available: the kernel reports every
//! transfer against the process that caused it, and this reads that.

mod etw;
mod procs;
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
