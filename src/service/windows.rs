//! Recording from every boot, the way Windows arranges it.
//!
//! A scheduled task rather than a Run key: the Run key starts programs after
//! login, unelevated, in the user's session. netwatch needs to be running
//! before that and needs the rights. Session 0 has no desktop, so there is no
//! window to hide.
//!
//! The task is registered from XML rather than from `schtasks` switches,
//! because three of its defaults are wrong for something meant to run forever:
//! a task is killed after 72 hours, will not start while the machine is on
//! battery, and stops if it goes onto battery. On a laptop the first two mean
//! the recorder is quietly not running for most of the time somebody wanted it
//! recording, and nothing anywhere would say so.

use std::process::Command;

const TASK: &str = "netwatch";
const TRAY_TASK: &str = "netwatch-tray";

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

/// The task definition, with every setting that matters stated rather than
/// inherited.
///
/// `S-1-5-18` is SYSTEM by SID rather than by name, because the name is
/// localised and this has to install on a Russian or a German Windows too.
fn task_xml(exe: &str, keep_days: u64) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Records which program uses the network, so it can be asked about afterwards.</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{exe}</Command>
      <Arguments>record --keep-days {keep_days}</Arguments>
    </Exec>
  </Actions>
</Task>
"#,
        exe = escape(exe),
    )
}

/// A path may contain `&`, and one unescaped character would make the whole
/// definition unparseable — with an error about XML rather than about the path.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The account of whoever is installing, as `DOMAIN\\USER`. The tray task is
/// registered for this person specifically, because the icon belongs in a
/// desktop session and this is the desktop it will appear in.
fn who() -> Result<String, String> {
    let domain = std::env::var("USERDOMAIN").unwrap_or_default();
    let user =
        std::env::var("USERNAME").map_err(|_| "could not tell who is installing".to_string())?;
    Ok(if domain.is_empty() {
        user
    } else {
        format!("{domain}\\{user}")
    })
}

/// The tray task: it runs in the person's own session, at logon, unelevated,
/// with no time limit and no battery restrictions — an icon that vanished on
/// battery would be a bug nobody could explain.
///
/// It is a separate task from the recorder because it is a separate program in
/// a separate session: the recorder is SYSTEM in session 0, which has no
/// desktop and so can show nothing; this is the interactive user, who can.
fn tray_task_xml(tray_exe: &str, user: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Shows the netwatch icon by the clock, reading the recorder's log.</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{exe}</Command>
    </Exec>
  </Actions>
</Task>
"#,
        exe = escape(tray_exe),
        user = escape(user),
    )
}

/// Register a task from XML through schtasks, which reads the definition as
/// UTF-16 — handed UTF-8 it fails with a parse error that names neither the
/// encoding nor the cause.
fn register(name: &str, xml: &str) -> Result<(), String> {
    let path = std::env::temp_dir().join(format!("{name}-{}.xml", std::process::id()));
    let mut bytes = vec![0xFF, 0xFE];
    for unit in xml.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    std::fs::write(&path, bytes)
        .map_err(|e| format!("could not write the task definition: {e}"))?;
    let result = schtasks(&[
        "/create",
        "/tn",
        name,
        "/xml",
        &path.display().to_string(),
        "/f",
    ]);
    let _ = std::fs::remove_file(&path);
    result.map(|_| ())
}

pub fn install(keep_days: u64, later: bool) -> Result<(), String> {
    let exe =
        std::env::current_exe().map_err(|e| format!("could not find this executable: {e}"))?;
    let exe = exe.display().to_string();

    register(TASK, &task_xml(&exe, keep_days)).map_err(|e| {
        format!(
            "{e}\n\nCreating a startup task needs an elevated terminal. \
             Run this from one opened as Administrator."
        )
    })?;

    // The tray icon, at logon, for whoever is installing. Failing to register
    // it must not fail the install: the recording is the point, and the icon
    // is only how you glance at it. It is the windowless second executable,
    // sitting next to this one, so nothing appears on screen when it starts.
    let tray_exe = std::path::Path::new(&exe)
        .with_file_name("netwatch-tray.exe")
        .display()
        .to_string();
    let tray = who().and_then(|user| register(TRAY_TASK, &tray_task_xml(&tray_exe, &user)));

    println!("Recording at every boot.");
    println!("  task     {TASK}, as SYSTEM, with no window");
    println!("  runs     {exe} record --keep-days {keep_days}");
    println!("  log      one file a day, {keep_days} days kept");
    println!();
    println!("It keeps running on battery and has no time limit. Both defaults");
    println!("would have stopped it on a laptop, without saying so.");
    println!();
    match &tray {
        Ok(_) => {
            println!("  tray     an icon by the clock at every logon, showing the totals");
            // Start it in this session too, so it appears without logging out.
            let _ = schtasks(&["/run", "/tn", TRAY_TASK]);
        }
        Err(e) => println!("  tray     could not register the icon ({e}); recording is unaffected"),
    }
    println!();

    if later {
        println!("Not started yet; it begins at the next boot.");
    } else {
        match schtasks(&["/run", "/tn", TASK]) {
            Ok(_) => println!("Started now, so there is no need to reboot first."),
            Err(e) => println!("Registered, but could not start it now: {e}"),
        }
    }
    println!();
    println!("Any time after:     netwatch report --hours 12");
    println!("To stop recording:  netwatch service uninstall");
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    // The tray first, and quietly: it may not be there, and its absence is not
    // a reason to refuse to remove the recorder.
    let _ = schtasks(&["/delete", "/tn", TRAY_TASK, "/f"]);
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

pub fn status() -> Result<(), String> {
    match schtasks(&["/query", "/tn", TASK, "/v", "/fo", "LIST"]) {
        Ok(text) => {
            // The full listing is forty lines of which five matter, and the
            // labels are localised, so both spellings are looked for.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The three defaults that would quietly stop a recorder have to be
    /// overridden. Each of them fails silently: nothing anywhere reports a
    /// task that did not start because the machine was on battery.
    #[test]
    fn the_settings_that_would_stop_it_are_overridden() {
        let xml = task_xml(r"C:\Program Files\netwatch\netwatch.exe", 30);

        assert!(
            xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"),
            "without this the task is killed after 72 hours"
        );
        assert!(
            xml.contains("<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"),
            "the default refuses to start on battery"
        );
        assert!(
            xml.contains("<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"),
            "the default stops when the machine goes onto battery"
        );
    }

    /// SYSTEM by SID, because the account name is localised and a task
    /// registered by name would fail to install on a non-English Windows.
    #[test]
    fn the_account_is_named_by_sid() {
        let xml = task_xml("x.exe", 1);
        assert!(xml.contains("<UserId>S-1-5-18</UserId>"));
        assert!(!xml.contains("<UserId>SYSTEM</UserId>"));
    }

    /// Command and arguments as separate elements, which is the whole reason
    /// for using XML: a path with spaces needs no quoting and cannot be
    /// mis-split back into an argument.
    #[test]
    fn the_command_and_its_arguments_are_separate() {
        let xml = task_xml(r"C:\Program Files\netwatch\netwatch.exe", 7);
        assert!(xml.contains(r"<Command>C:\Program Files\netwatch\netwatch.exe</Command>"));
        assert!(xml.contains("<Arguments>record --keep-days 7</Arguments>"));
    }

    /// The tray runs in the person's own session at logon, unelevated. If it
    /// asked for elevation it would prompt at every login; if it were killed on
    /// battery the icon would silently disappear on a laptop.
    #[test]
    fn the_tray_runs_at_logon_for_the_user_without_elevation() {
        let xml = tray_task_xml(r"C:\Program Files\netwatch\netwatch-tray.exe", r"HOME\user");
        assert!(xml.contains("<LogonTrigger>"), "it starts at logon");
        assert!(
            xml.contains(r"<UserId>HOME\user</UserId>"),
            "for this user: {xml}"
        );
        assert!(
            xml.contains("<RunLevel>LeastPrivilege</RunLevel>"),
            "no elevation"
        );
        assert!(
            xml.contains(r"<Command>C:\Program Files\netwatch\netwatch-tray.exe</Command>"),
            "it runs the windowless tray executable: {xml}"
        );
        assert!(
            !xml.contains("<Arguments>"),
            "the tray executable needs no subcommand"
        );
        assert!(xml.contains("<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"));
        assert!(!xml.contains("BootTrigger"), "the tray is not a boot task");
    }

    /// One unescaped character in a path would break the whole definition,
    /// with an error about XML rather than about the path.
    #[test]
    fn a_path_cannot_break_the_definition() {
        let xml = task_xml(r"C:\Tools & Things\netwatch.exe", 30);
        assert!(xml.contains("Tools &amp; Things"), "{xml}");
        assert!(!xml.contains("Tools & Things"));
    }
}
