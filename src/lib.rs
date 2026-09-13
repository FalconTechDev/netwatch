//! netwatch's internals, shared by its two binaries.
//!
//! There are two because Windows decides whether a program gets a console
//! window from a flag baked into the executable, not from how it is launched.
//! `netwatch.exe` is a console program: run from a terminal it shows its
//! output there, as it should. The tray is the opposite — it must never put a
//! black window on the screen, least of all one that stays for as long as it
//! runs — so it is a second executable built for the windows subsystem, and
//! everything it needs lives here where both can reach it.

pub mod dns;
pub mod event;
pub mod hidden;
pub mod log;
pub mod procs;
pub mod report;
pub mod state;
pub mod tui;

// The data source, and only the data source, is what differs between systems.
// Each of these produces the same `event::Event` stream; everything above them
// is the same code on both.
#[cfg(target_os = "linux")]
pub mod ebpf;
#[cfg(windows)]
pub mod etw;

// The source for this platform, under one name, so callers need no `cfg` of
// their own.
#[cfg(target_os = "linux")]
pub use ebpf as source;
#[cfg(windows)]
pub use etw as source;

/// How to start recording on this system, wherever that is suggested.
///
/// Windows registers a scheduled task that runs from every boot. Linux has no
/// equivalent here yet, and naming one would send someone to a subcommand that
/// does not exist on their machine — so what is offered there is the thing
/// that does work today. A wrong instruction is worse than a modest one: it
/// costs the reader the time to find out it was wrong.
#[cfg(windows)]
pub const HOW_TO_RECORD: &str = "netwatch service install";
#[cfg(not(windows))]
pub const HOW_TO_RECORD: &str = "netwatch record";

// Starting at boot and sitting in the tray are both done the way Windows does
// them — a scheduled task and a notification icon. Linux has its own answers
// (a systemd unit, a StatusNotifierItem), which are not written yet.
#[cfg(windows)]
pub mod service;
#[cfg(windows)]
pub mod tray;

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
