//! Starting at boot.
//!
//! Recording only helps if it was running when the thing you want to know
//! about happened, which means it has to start without being asked — before
//! anyone logs in, and without a window.
//!
//! A scheduled task rather than a Run key: the Run key starts programs after
//! login, unelevated, in the user's session. netwatch needs to be running
//! before that and needs to be elevated, and a task set to run as SYSTEM at
//! startup is exactly that — no window to hide, because session 0 has no
//! desktop to put one on.
//!
//! Nothing here installs anything on its own. Each of these is a deliberate
//! command, because a program that quietly arranges to run forever on someone's
//! machine is the behaviour of something else entirely.

use std::process::Command;

use clap::Subcommand;

const TASK: &str = "netwatch";

#[derive(Subcommand)]
pub enum Action {
    /// Record from every boot, as a scheduled task running under SYSTEM.
    Install {
        /// Delete day files older than this.
        #[arg(long, default_value_t = 30)]
        keep_days: u64,
    },
    /// Stop recording at boot and remove the task.
    Uninstall,
    /// Whether the task exists, and when it last ran.
    Status,
}

pub fn run(action: Action) -> Result<(), String> {
    match action {
        Action::Install { keep_days } => install(keep_days),
        Action::Uninstall => uninstall(),
        Action::Status => status(),
    }
}

fn schtasks(args: &[&str]) -> Result<String, String> {
    let out = Command::new("schtasks")
        .args(args)
        .output()
        .map_err(|e| format!("could not run schtasks: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        Ok(text)
    } else {
        // schtasks reports some failures on stdout and some on stderr, so
        // whichever one actually said something is the message.
        let err = String::from_utf8_lossy(&out.stderr);
        Err(if err.trim().is_empty() {
            text.trim().to_string()
        } else {
            err.trim().to_string()
        })
    }
}

fn install(keep_days: u64) -> Result<(), String> {
    let exe =
        std::env::current_exe().map_err(|e| format!("could not find this executable: {e}"))?;

    // The task runs the binary where it stands. Moving or deleting it later
    // breaks the task, so the path is printed rather than left implicit.
    let command = format!("\"{}\" record --keep-days {keep_days}", exe.display());

    schtasks(&[
        "/create", "/tn", TASK, "/sc", "onstart", "/ru", "SYSTEM", "/rl", "HIGHEST", "/tr",
        &command, "/f",
    ])
    .map_err(|e| {
        format!(
            "{e}\n\nCreating a startup task needs an elevated terminal. \
             Run this from one opened as Administrator."
        )
    })?;

    println!("Installed. netwatch will record from every boot.");
    println!("  task:    {TASK}");
    println!("  runs:    {command}");
    println!("  as:      SYSTEM, at startup, with no window");
    println!();
    println!("It is not running yet — it starts at the next boot, or now with:");
    println!("    schtasks /run /tn {TASK}");
    println!();
    println!("Then, any time after:  netwatch report --hours 12");
    println!("To stop recording:     netwatch service uninstall");
    Ok(())
}

fn uninstall() -> Result<(), String> {
    schtasks(&["/delete", "/tn", TASK, "/f"]).map_err(|e| {
        format!(
            "{e}\n\nRemoving the task needs an elevated terminal, \
             and it has to exist to be removed."
        )
    })?;
    println!("Removed. netwatch no longer records at boot.");
    println!("The log it already wrote is untouched — delete it yourself if you want it gone.");
    Ok(())
}

fn status() -> Result<(), String> {
    match schtasks(&["/query", "/tn", TASK, "/v", "/fo", "LIST"]) {
        Ok(text) => {
            // The full listing is forty lines of which four matter.
            let wanted = [
                "Status",
                "Last Run Time",
                "Last Result",
                "Next Run Time",
                "Task To Run",
                "Состояние",
                "Время прошлого запуска",
                "Прошлый результат",
                "Время следующего запуска",
                "Задача для выполнения",
            ];
            for line in text.lines() {
                if wanted.iter().any(|w| line.trim_start().starts_with(w)) {
                    println!("{}", line.trim_end());
                }
            }
            Ok(())
        }
        Err(_) => {
            println!("Not installed — netwatch is not recording at boot.");
            println!();
            println!("To start, from an elevated terminal:");
            println!("    netwatch service install");
            Ok(())
        }
    }
}
