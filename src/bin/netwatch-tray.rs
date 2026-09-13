//! The tray icon, as a program that can never show a console window.
//!
//! `windows_subsystem = "windows"` is the whole point of this file existing:
//! it tells Windows not to give the process a console, so nothing appears on
//! the screen when the logon task starts it — no black window, no flash, and
//! nothing to close. Everything it does lives in the library; this is only the
//! flag and an entry point.
#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    if let Err(e) = netwatch::tray::run() {
        // There is no console to print to, by design. A failure here is rare
        // and not urgent — recording is a separate program and unaffected — so
        // it is left where it can be found rather than shown: a line in the
        // temp folder, next to nothing else that matters.
        let path = std::env::temp_dir().join("netwatch-tray-error.txt");
        let _ = std::fs::write(path, format!("netwatch tray could not start: {e}\n"));
    }
}
