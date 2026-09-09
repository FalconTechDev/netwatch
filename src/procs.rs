//! Process ids -> names.
//!
//! The kernel reports traffic against a pid, and a pid means nothing to a
//! person. Names are cached because the lookup walks every process on the
//! machine, and the answer for a given pid does not change while it lives.

use std::collections::HashMap;

/// A pid that has gone away keeps its name here, which is deliberate: traffic
/// attributed to a short-lived process should still say what it was, not
/// become an anonymous number the moment the process exits.
#[derive(Default)]
pub struct Names {
    cache: HashMap<u32, String>,
}

impl Names {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&mut self, pid: u32) -> &str {
        if !self.cache.contains_key(&pid) {
            // A miss means a process we have not seen, which usually means one
            // that started since the last sweep — so sweep again rather than
            // giving up on it.
            self.refresh();
            self.cache
                .entry(pid)
                .or_insert_with(|| format!("pid {pid}"));
        }
        self.cache.get(&pid).map(String::as_str).unwrap_or("?")
    }

    #[cfg(windows)]
    fn refresh(&mut self) {
        use std::mem::size_of;
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        };

        // SAFETY: the snapshot handle is checked before use and closed on
        // every path out.
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap.is_null() || snap as isize == -1 {
                return;
            }
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
            if Process32FirstW(snap, &mut entry) != 0 {
                loop {
                    let end = entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len());
                    let name = String::from_utf16_lossy(&entry.szExeFile[..end]);
                    self.cache.insert(entry.th32ProcessID, name);
                    if Process32NextW(snap, &mut entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
        }
    }

    #[cfg(not(windows))]
    fn refresh(&mut self) {
        // netwatch reads a Windows kernel provider; there is nothing to sweep
        // anywhere else, and pretending otherwise would hide that.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_known_process_resolves_to_a_name() {
        let mut names = Names::new();
        let me = std::process::id();
        let name = names.get(me).to_string();
        assert!(
            name.ends_with(".exe") || name.starts_with("pid "),
            "unexpected name for our own process: {name}"
        );
        // On Windows our own process must be found by name, not fall back.
        if cfg!(windows) {
            assert!(name.contains("netwatch"), "own name not found: {name}");
        }
    }

    /// A pid that does not exist must still produce something printable rather
    /// than an empty cell that reads as a bug.
    #[test]
    fn an_unknown_pid_still_gets_a_label() {
        let mut names = Names::new();
        assert_eq!(names.get(0xFFFF_FFF0), "pid 4294967280");
    }

    /// The name of a process that has exited is kept: traffic it caused is
    /// still worth attributing.
    #[test]
    fn a_name_survives_in_the_cache() {
        let mut names = Names::new();
        names.cache.insert(4242, "gone.exe".into());
        assert_eq!(names.get(4242), "gone.exe");
    }
}
