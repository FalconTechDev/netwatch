//! Recording from every boot.
//!
//! Recording only helps if it was running when the thing you want to know
//! about happened, which means starting without being asked — before anyone
//! logs in, and without a window.
//!
//! Both systems can be told to do that; neither is told in the same way. A
//! scheduled task and a systemd unit have nothing in common but the intent, so
//! each lives in its own file and this one only says what the intent is.

use clap::Subcommand;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
use linux as sys;
#[cfg(windows)]
use windows as sys;

#[derive(Subcommand)]
pub enum Action {
    /// Record from every boot, in the background.
    Install {
        /// Delete day files older than this.
        #[arg(long, default_value_t = 30)]
        keep_days: u64,
        /// Register it but wait for the next boot to start recording.
        #[arg(long)]
        later: bool,
    },
    /// Stop recording at boot, and remove it.
    Uninstall,
    /// Whether it is installed, and when it last ran.
    Status,
}

pub fn run(action: Action) -> Result<(), String> {
    match action {
        Action::Install { keep_days, later } => sys::install(keep_days, later),
        Action::Uninstall => sys::uninstall(),
        Action::Status => sys::status(),
    }
}

/// Neither system is supported here, so nothing can be arranged. Saying so is
/// better than a command that appears to work.
#[cfg(not(any(windows, target_os = "linux")))]
mod sys {
    pub fn install(_keep_days: u64, _later: bool) -> Result<(), String> {
        Err("netwatch cannot arrange background recording on this system yet.".into())
    }
    pub fn uninstall() -> Result<(), String> {
        install(0, false)
    }
    pub fn status() -> Result<(), String> {
        install(0, false)
    }
}
