//! Programs kept out of the view.
//!
//! A machine has a dozen programs that talk constantly and tell you nothing —
//! the update service, the sync client, whatever the vendor put on it. Once
//! they are on screen every time, the screen stops being read.
//!
//! Hiding is a property of the *view*, never of the record. A hidden program is
//! still measured, still written to the log, and still in every report: this
//! only decides what the live list shows. That distinction is the whole point —
//! a filter that quietly stopped recording would turn "I did not want to look
//! at it" into "I have no idea what it did", which is the opposite of what this
//! program is for.
//!
//! Kept by name rather than by pid, because a program restarted is the same
//! program and hiding it once should mean hiding it.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Default)]
pub struct Hidden {
    names: BTreeSet<String>,
    path: PathBuf,
}

/// A per-user file, not a machine-wide one: the recorder runs as SYSTEM for
/// everybody, but what one person wants to look at is theirs alone.
pub fn default_path() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".into());
    Path::new(&base).join("netwatch").join("hidden.txt")
}

impl Hidden {
    pub fn load(path: PathBuf) -> Self {
        let names = fs::read_to_string(&path)
            .unwrap_or_default()
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.to_lowercase())
            .collect();
        Self { names, path }
    }

    pub fn is_hidden(&self, name: &str) -> bool {
        self.names.contains(&name.to_lowercase())
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    pub fn names(&self) -> impl Iterator<Item = &String> {
        self.names.iter()
    }

    /// Hide or show a program. Returns true when it is now hidden.
    pub fn toggle(&mut self, name: &str) -> bool {
        let key = name.to_lowercase();
        let now_hidden = if self.names.contains(&key) {
            self.names.remove(&key);
            false
        } else {
            self.names.insert(key);
            true
        };
        self.save();
        now_hidden
    }

    pub fn clear(&mut self) {
        self.names.clear();
        self.save();
    }

    /// Written immediately, so the list survives a crash and a reboot without
    /// anyone having to quit cleanly first. Failure is not reported: not being
    /// able to remember a display preference is not worth interrupting for.
    fn save(&self) {
        if let Some(dir) = self.path.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let mut out = String::from(
            "# Programs netwatch does not show in the live view.\n\
             # They are still recorded, and still appear in every report.\n\
             # One name per line; delete a line to see it again.\n",
        );
        for n in &self.names {
            out.push_str(n);
            out.push('\n');
        }
        let _ = fs::write(&self.path, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("netwatch_hidden_{name}"));
        let _ = fs::remove_dir_all(&d);
        d.join("hidden.txt")
    }

    #[test]
    fn hiding_survives_a_restart() {
        let path = tmp("persist");
        let mut h = Hidden::load(path.clone());
        assert!(h.toggle("Updater.exe"));
        assert!(h.is_hidden("updater.exe"));

        // A second run reads the same file.
        let again = Hidden::load(path);
        assert!(
            again.is_hidden("UPDATER.EXE"),
            "matching is case-insensitive"
        );
        assert_eq!(again.len(), 1);
    }

    #[test]
    fn hiding_twice_shows_it_again() {
        let mut h = Hidden::load(tmp("toggle"));
        assert!(h.toggle("a.exe"));
        assert!(!h.toggle("a.exe"));
        assert!(!h.is_hidden("a.exe"));
        assert!(h.is_empty());
    }

    /// The file is meant to be edited by hand, so its own comments must not
    /// come back as program names.
    #[test]
    fn comments_and_blank_lines_are_not_programs() {
        let path = tmp("comments");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "# a comment\n\n  spaced.exe  \n\n# another\n").unwrap();

        let h = Hidden::load(path);
        assert_eq!(h.len(), 1);
        assert!(h.is_hidden("spaced.exe"), "surrounding spaces are trimmed");
    }

    #[test]
    fn a_missing_file_means_nothing_is_hidden() {
        let h = Hidden::load(tmp("absent"));
        assert!(h.is_empty());
        assert!(!h.is_hidden("anything.exe"));
    }

    #[test]
    fn everything_can_be_shown_again_at_once() {
        let mut h = Hidden::load(tmp("clear"));
        h.toggle("a.exe");
        h.toggle("b.exe");
        assert_eq!(h.len(), 2);
        h.clear();
        assert!(h.is_empty());
        assert!(Hidden::load(tmp("clear")).is_empty());
    }
}
