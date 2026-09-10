//! The record on disk.
//!
//! Without this netwatch can only answer "what is happening while I watch",
//! which is the opposite of the question people actually have — what was
//! downloading overnight, what has been quietly uploading all week. So a
//! background run appends a line a minute per program, and the reports read it
//! back.
//!
//! The format is tab-separated text, one file a day. That is deliberate: it can
//! be read by anything, tailed while it is being written, and truncated with a
//! text editor. A binary format would be smaller and would make the data
//! hostage to this program still existing and still being able to parse it.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// One program's traffic over one minute.
#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    /// Minutes since the epoch — the bucket, not the moment.
    pub minute: u64,
    pub pid: u32,
    pub name: String,
    pub sent: u64,
    pub received: u64,
    /// Where most of it went, as `addr:port=bytes`, biggest first. Capped, so
    /// one chatty program cannot make a line unbounded.
    pub peers: String,
    /// The executable on disk. Worth a column of its own: a name tells you
    /// nothing, and by the time anyone reads the log the process is long gone
    /// and cannot be asked.
    pub path: String,
}

impl Row {
    pub fn total(&self) -> u64 {
        self.sent + self.received
    }
}

const HEADER: &str = "# minute\tpid\tname\tsent\treceived\tpeers\tpath";

/// Where the record lives.
///
/// `ProgramData` rather than a user profile, because the background run is a
/// machine-wide service: it starts before anyone logs in and records traffic
/// for every account. Users can read it; only an administrator can write it,
/// which is the right way round for a log that is evidence.
pub fn default_dir() -> PathBuf {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| ".".into());
    Path::new(&base).join("netwatch")
}

/// When this machine last started, as a unix timestamp.
///
/// Taken from how long it has been up rather than from any recorded event,
/// because that is the one number that is true regardless of what was running
/// at the time — including netwatch itself.
#[cfg(windows)]
pub fn boot_secs() -> u64 {
    // SAFETY: GetTickCount64 takes nothing and returns milliseconds since
    // boot; there is no failure mode and nothing to free.
    let uptime_ms = unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() };
    now_secs().saturating_sub(uptime_ms / 1_000)
}

#[cfg(not(windows))]
pub fn boot_secs() -> u64 {
    now_secs()
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Civil date from a unix timestamp, UTC.
///
/// Written out rather than pulled in as a dependency: it is the one piece of
/// calendar arithmetic needed, it is exactly testable, and a wrong answer here
/// would file a day's traffic under the wrong day — which nothing else would
/// catch. The algorithm is Howard Hinnant's `civil_from_days`.
pub fn civil_from_secs(secs: u64) -> (i64, u32, u32) {
    let days = (secs / 86_400) as i64;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn day_key(secs: u64) -> String {
    let (y, m, d) = civil_from_secs(secs);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Appends rows, rolling over at midnight.
pub struct Writer {
    dir: PathBuf,
    open_day: String,
    file: Option<File>,
}

impl Writer {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            open_day: String::new(),
            file: None,
        }
    }

    fn file_for(&mut self, secs: u64) -> std::io::Result<&mut File> {
        let day = day_key(secs);
        if self.file.is_none() || self.open_day != day {
            fs::create_dir_all(&self.dir)?;
            let path = self.dir.join(format!("netwatch-{day}.tsv"));
            let fresh = !path.exists();
            let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
            if fresh {
                writeln!(f, "{HEADER}")?;
            }
            self.file = Some(f);
            self.open_day = day;
        }
        Ok(self.file.as_mut().expect("just set"))
    }

    /// Write one minute's worth. Flushed immediately: a log that loses the last
    /// minutes to a buffer is exactly the log you wanted after a crash or a
    /// power cut.
    pub fn append(&mut self, secs: u64, rows: &[Row]) -> std::io::Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let f = self.file_for(secs)?;
        for r in rows {
            writeln!(
                f,
                "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                r.minute,
                r.pid,
                sanitise(&r.name),
                r.sent,
                r.received,
                sanitise(&r.peers),
                sanitise(&r.path)
            )?;
        }
        f.flush()
    }
}

/// A tab or a newline in a field would split the row into different fields, so
/// a program named with one cannot be allowed to corrupt every later read.
fn sanitise(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '\t' || c == '\n' || c == '\r' {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// Read every row in the directory whose minute falls in `[from, to]`.
///
/// Unreadable lines are skipped rather than fatal: a log truncated by a power
/// cut mid-write should still answer questions about the days around it.
pub fn read_range(dir: &Path, from: u64, to: u64) -> Vec<Row> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("netwatch-") && n.ends_with(".tsv"))
        })
        .collect();
    files.sort();

    for path in files {
        let Ok(f) = File::open(&path) else { continue };
        for line in BufReader::new(f).lines().map_while(Result::ok) {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            if let Some(row) = parse(&line)
                && row.minute >= from
                && row.minute <= to
            {
                out.push(row);
            }
        }
    }
    out
}

fn parse(line: &str) -> Option<Row> {
    let mut f = line.split('\t');
    let row = Row {
        minute: f.next()?.parse().ok()?,
        pid: f.next()?.parse().ok()?,
        name: f.next()?.to_string(),
        sent: f.next()?.parse().ok()?,
        received: f.next()?.parse().ok()?,
        peers: f.next().unwrap_or("").to_string(),
        // Absent in files written before paths were recorded. Those rows are
        // still perfectly good rows, so a missing column reads as empty rather
        // than as a parse failure that would discard the whole day.
        path: f.next().unwrap_or("").to_string(),
    };
    Some(row)
}

/// Delete day files older than `days`. A log nobody prunes eventually fills a
/// disk, which is a worse failure than losing last month's numbers.
pub fn prune(dir: &Path, days: u64, now: u64) -> usize {
    let cutoff = now.saturating_sub(days * 86_400);
    let keep_from = day_key(cutoff);
    let mut removed = 0;
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    for path in entries.flatten().map(|e| e.path()) {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(day) = name
            .strip_prefix("netwatch-")
            .and_then(|n| n.strip_suffix(".tsv"))
        else {
            continue;
        };
        // Dates in this format sort the same as they order, so a string
        // comparison is the date comparison.
        if day < keep_from.as_str() && fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Getting this wrong files a day's traffic under the wrong day, and
    /// nothing downstream would notice.
    #[test]
    fn dates_come_out_right() {
        assert_eq!(civil_from_secs(0), (1970, 1, 1));
        assert_eq!(civil_from_secs(1_700_000_000), (2023, 11, 14));
        // A leap day, and the day after it.
        assert_eq!(civil_from_secs(1_709_164_800), (2024, 2, 29));
        assert_eq!(civil_from_secs(1_709_251_200), (2024, 3, 1));
        // A century that is not a leap year, and one that is.
        assert_eq!(civil_from_secs(4_107_542_400), (2100, 3, 1));
        assert_eq!(day_key(1_700_000_000), "2023-11-14");
    }

    #[test]
    fn a_day_boundary_moves_to_the_next_file() {
        assert_eq!(day_key(1_699_999_999), "2023-11-14");
        assert_ne!(day_key(1_700_006_400), day_key(1_699_900_000));
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("netwatch_log_test_{name}"));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn row(minute: u64, pid: u32, name: &str, sent: u64, received: u64) -> Row {
        Row {
            minute,
            pid,
            name: name.into(),
            sent,
            received,
            peers: "1.2.3.4:443=100".into(),
            path: "C:/app/thing.exe".into(),
        }
    }

    #[test]
    fn what_was_written_is_what_comes_back() {
        let dir = tmp("roundtrip");
        let mut w = Writer::new(dir.clone());
        let secs = 1_700_000_000;
        let rows = vec![
            row(secs / 60, 100, "firefox.exe", 1_000, 9_000),
            row(secs / 60, 200, "backup.exe", 50_000, 12),
        ];
        w.append(secs, &rows).unwrap();

        let back = read_range(&dir, 0, u64::MAX);
        assert_eq!(back.len(), 2);
        assert_eq!(back[0], rows[0]);
        assert_eq!(back[1].sent, 50_000);
    }

    #[test]
    fn the_range_is_respected() {
        let dir = tmp("range");
        let mut w = Writer::new(dir.clone());
        let base = 1_700_000_000u64;
        for i in 0..5u64 {
            w.append(base + i * 60, &[row((base / 60) + i, 1, "a.exe", 10, 10)])
                .unwrap();
        }
        let m = base / 60;
        assert_eq!(read_range(&dir, m + 1, m + 3).len(), 3);
        assert_eq!(read_range(&dir, m + 99, u64::MAX).len(), 0);
    }

    /// A program is free to have a tab in its name; the log is not free to be
    /// corrupted by it.
    #[test]
    fn a_field_cannot_break_the_row() {
        let dir = tmp("sanitise");
        let mut w = Writer::new(dir.clone());
        let secs = 1_700_000_000;
        let mut r = row(secs / 60, 7, "bad\tname\nhere", 1, 2);
        r.peers = "x\ty".into();
        w.append(secs, &[r]).unwrap();

        let back = read_range(&dir, 0, u64::MAX);
        assert_eq!(back.len(), 1, "one row, not three");
        assert_eq!(back[0].name, "bad name here");
        assert_eq!(back[0].sent, 1, "fields did not shift");
    }

    /// A log truncated by a power cut must not make the days around it
    /// unreadable.
    #[test]
    fn a_broken_line_is_skipped_not_fatal() {
        let dir = tmp("broken");
        let path = dir.join("netwatch-2023-11-14.tsv");
        fs::write(
            &path,
            "# minute\tpid\tname\tsent\treceived\tpeers\n\
             28333333\t1\tgood.exe\t10\t20\tp\n\
             this line is nonsense\n\
             28333334\t2\talso-good.exe\tNOT_A_NUMBER\t20\tp\n\
             28333335\t3\tthird.exe\t30\t40\tp\n",
        )
        .unwrap();
        let back = read_range(&dir, 0, u64::MAX);
        assert_eq!(back.len(), 2, "the two intact rows survive");
        assert_eq!(back[1].name, "third.exe");
    }

    /// A log written before paths were recorded is still a log. Discarding
    /// those days because a column is missing would throw away exactly the
    /// history the tool exists to keep.
    #[test]
    fn rows_without_a_path_still_read() {
        let dir = tmp("oldformat");
        let header = "# minute\tpid\tname\tsent\treceived\tpeers\n";
        let data = "28333333\t1\told.exe\t10\t20\t1.2.3.4:443=30\n";
        let old = format!("{header}{data}");
        fs::write(dir.join("netwatch-2023-11-14.tsv"), old).unwrap();

        let back = read_range(&dir, 0, u64::MAX);
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].name, "old.exe");
        assert_eq!(back[0].received, 20, "the columns did not shift");
        assert_eq!(back[0].path, "", "a missing path is empty, not a failure");
    }

    #[test]
    fn old_days_are_pruned_and_recent_ones_kept() {
        let dir = tmp("prune");
        let now = 1_700_000_000u64;
        for day in ["2023-09-01", "2023-11-01", "2023-11-14"] {
            fs::write(dir.join(format!("netwatch-{day}.tsv")), "#\n").unwrap();
        }
        // Something else in the directory must be left alone.
        fs::write(dir.join("notes.txt"), "keep me").unwrap();

        let removed = prune(&dir, 30, now);
        assert_eq!(removed, 1, "only the September file is old enough");
        assert!(dir.join("netwatch-2023-11-14.tsv").exists());
        assert!(dir.join("notes.txt").exists(), "unrelated files untouched");
    }
}
