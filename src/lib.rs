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
pub mod etw;
pub mod hidden;
pub mod log;
pub mod procs;
pub mod report;
pub mod service;
pub mod state;
pub mod tray;
pub mod tui;

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
