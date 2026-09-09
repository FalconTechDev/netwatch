//! Process ids -> what is actually running.
//!
//! A name on its own answers very little. `svchost.exe` from
//! `C:\Windows\System32`, signed by Microsoft, is the operating system;
//! `svchost.exe` from a temp directory with no version information at all is
//! the single most useful thing this program could tell you. So the name comes
//! with where it lives and who says they wrote it.
//!
//! All of it is cached: the answer for a pid does not change while it lives,
//! and the lookups are not free.

use std::collections::HashMap;

/// What is known about one process.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Info {
    /// Executable file name, e.g. `firefox.exe`.
    pub name: String,
    /// Full path on disk, when it could be read. Empty for processes this
    /// session is not allowed to open — the kernel's own, mostly.
    pub path: String,
    /// The friendly name from the file's version resource, e.g. "Mozilla
    /// Firefox". This is what Task Manager shows as the description.
    pub description: String,
    /// Who the version resource says wrote it. Absent is itself informative.
    pub company: String,
}

impl Info {
    /// The clearest label available: a description if the file carries one,
    /// otherwise the file name.
    pub fn label(&self) -> &str {
        if self.description.is_empty() {
            &self.name
        } else {
            &self.description
        }
    }
}

/// A pid that has gone away keeps its entry, deliberately: traffic caused by a
/// short-lived process should still say what it was, not become an anonymous
/// number the moment the process exits.
#[derive(Default)]
pub struct Names {
    cache: HashMap<u32, Info>,
}

impl Names {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&mut self, pid: u32) -> &Info {
        if !self.cache.contains_key(&pid) {
            // A miss usually means a process started since the last sweep, so
            // sweep again rather than giving up on it.
            self.refresh();
            self.cache.entry(pid).or_insert_with(|| Info {
                name: format!("pid {pid}"),
                ..Info::default()
            });
        }
        self.cache.get(&pid).expect("just inserted")
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
                    let pid = entry.th32ProcessID;
                    // Only unseen pids are looked up: opening a process and
                    // reading its version resource is not free, and the answer
                    // does not change while the process lives.
                    self.cache.entry(pid).or_insert_with(|| {
                        let end = entry
                            .szExeFile
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(entry.szExeFile.len());
                        let name = String::from_utf16_lossy(&entry.szExeFile[..end]);
                        let path = image_path(pid);
                        let (description, company) = version_info(&path);
                        Info {
                            name,
                            path,
                            description,
                            company,
                        }
                    });
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

/// The executable's full path, or empty when it cannot be read.
///
/// Opened with `PROCESS_QUERY_LIMITED_INFORMATION`, which is the least right
/// that answers the question — asking for more would fail on more processes
/// for no gain.
#[cfg(windows)]
fn image_path(pid: u32) -> String {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
    };

    // SAFETY: the handle is checked, closed on every path, and the buffer is
    // written with its own length passed by the API.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return String::new();
        }
        let mut buf = [0u16; 32_768];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        if ok == 0 {
            return String::new();
        }
        String::from_utf16_lossy(&buf[..len as usize])
    }
}

#[cfg(not(windows))]
fn image_path(_pid: u32) -> String {
    String::new()
}

/// `FileDescription` and `CompanyName` from the file's version resource.
///
/// Both are strings the author chose to put there and neither is verified by
/// anything — they say what the file claims about itself, which is worth
/// knowing precisely because an unsigned copy in a temp directory usually
/// claims nothing at all.
#[cfg(windows)]
fn version_info(path: &str) -> (String, String) {
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
    };

    if path.is_empty() {
        return (String::new(), String::new());
    }
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

    // SAFETY: every pointer written by these calls is checked before it is
    // read, and every length comes from the API rather than from a guess.
    unsafe {
        let mut handle = 0u32;
        let size = GetFileVersionInfoSizeW(wide.as_ptr(), &mut handle);
        if size == 0 {
            return (String::new(), String::new());
        }
        let mut data = vec![0u8; size as usize];
        if GetFileVersionInfoW(wide.as_ptr(), 0, size, data.as_mut_ptr().cast()) == 0 {
            return (String::new(), String::new());
        }

        // Which language the strings are in is itself a lookup: a file may
        // carry several, and the first is the one to read.
        let key: Vec<u16> = "\\VarFileInfo\\Translation"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut ptr = std::ptr::null_mut();
        let mut len = 0u32;
        if VerQueryValueW(data.as_ptr().cast(), key.as_ptr(), &mut ptr, &mut len) == 0
            || len < 4
            || ptr.is_null()
        {
            return (String::new(), String::new());
        }
        let lang = *(ptr as *const u16);
        let codepage = *(ptr as *const u16).add(1);

        let read = |field: &str| -> String {
            let q: Vec<u16> = format!("\\StringFileInfo\\{lang:04x}{codepage:04x}\\{field}")
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let mut p = std::ptr::null_mut();
            let mut n = 0u32;
            if VerQueryValueW(data.as_ptr().cast(), q.as_ptr(), &mut p, &mut n) == 0
                || p.is_null()
                || n == 0
            {
                return String::new();
            }
            // `n` counts characters including the terminator.
            let slice = std::slice::from_raw_parts(p as *const u16, n as usize);
            String::from_utf16_lossy(slice)
                .trim_end_matches('\0')
                .trim()
                .to_string()
        };

        (read("FileDescription"), read("CompanyName"))
    }
}

#[cfg(not(windows))]
fn version_info(_path: &str) -> (String, String) {
    (String::new(), String::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn our_own_process_is_described() {
        let mut names = Names::new();
        let info = names.get(std::process::id()).clone();
        if cfg!(windows) {
            assert!(info.name.contains("netwatch"), "name: {}", info.name);
            assert!(
                info.path.to_lowercase().ends_with(".exe"),
                "path should be the executable: {}",
                info.path
            );
            assert!(
                info.path.len() > info.name.len(),
                "path should be more than the file name: {}",
                info.path
            );
        }
    }

    /// A pid that does not exist must still produce something printable rather
    /// than an empty cell that reads as a bug.
    #[test]
    fn an_unknown_pid_still_gets_a_label() {
        let mut names = Names::new();
        let info = names.get(0xFFFF_FFF0).clone();
        assert_eq!(info.name, "pid 4294967280");
        assert_eq!(info.path, "", "no path can be invented for it");
    }

    /// The description is what a person recognises; the file name is the
    /// fallback, not the other way round.
    #[test]
    fn the_label_prefers_the_description() {
        let with = Info {
            name: "chrome.exe".into(),
            description: "Google Chrome".into(),
            ..Info::default()
        };
        assert_eq!(with.label(), "Google Chrome");

        let without = Info {
            name: "mystery.exe".into(),
            ..Info::default()
        };
        assert_eq!(without.label(), "mystery.exe");
    }

    #[test]
    fn a_cached_entry_survives_the_process() {
        let mut names = Names::new();
        names.cache.insert(
            4242,
            Info {
                name: "gone.exe".into(),
                path: "C:/tmp/gone.exe".into(),
                ..Info::default()
            },
        );
        assert_eq!(names.get(4242).path, "C:/tmp/gone.exe");
    }

    /// Version information is optional in a PE file and absent from plenty of
    /// real ones, so its absence must be ordinary rather than an error.
    #[test]
    fn a_file_without_version_information_is_not_a_failure() {
        assert_eq!(version_info(""), (String::new(), String::new()));
        assert_eq!(
            version_info("C:/definitely/not/here.exe"),
            (String::new(), String::new())
        );
    }
}
