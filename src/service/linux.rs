//! Recording from every boot, the way Linux arranges it.
//!
//! A systemd unit, which is what runs things before anyone logs in on every
//! distribution that matters. The unit asks for the two capabilities the
//! recorder needs rather than running as root outright: loading an eBPF
//! program needs `CAP_BPF` and attaching it to a kprobe needs `CAP_PERFMON`,
//! and nothing here needs the rest of what root carries.
//!
//! `Restart=always` is deliberate. A recorder that died quietly at three in
//! the morning leaves exactly the gap the person will later want to look at,
//! and nothing anywhere would say why the log stops.

use std::path::Path;
use std::process::Command;

const UNIT: &str = "netwatch.service";
const UNIT_PATH: &str = "/etc/systemd/system/netwatch.service";

/// The unit definition, with every setting that matters stated rather than
/// inherited.
fn unit(exe: &str, keep_days: u64) -> String {
    format!(
        "[Unit]\n\
         Description=Records which program uses the network, so it can be asked about afterwards\n\
         Documentation=https://github.com/FalconTechDev/netwatch\n\
         After=network.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exe} record --keep-days {keep_days}\n\
         # A recorder that died in the night leaves a gap exactly where the\n\
         # answer should be, so it is always brought back.\n\
         Restart=always\n\
         RestartSec=5\n\
         # The two rights an eBPF program needs, and nothing else root has.\n\
         AmbientCapabilities=CAP_BPF CAP_PERFMON\n\
         CapabilityBoundingSet=CAP_BPF CAP_PERFMON\n\
         NoNewPrivileges=yes\n\
         ProtectSystem=strict\n\
         ProtectHome=yes\n\
         PrivateTmp=yes\n\
         # systemd creates this under /var/log and hands it to the service.\n\
         # That matters because the bounding set above takes CAP_DAC_OVERRIDE\n\
         # away from root: it can no longer write where it does not own, so a\n\
         # directory belonging to anyone else fails with nothing to show for\n\
         # it but a permission error once a minute in the journal.\n\
         LogsDirectory=netwatch\n\
         LogsDirectoryMode=0755\n\
         ReadWritePaths=/var/log/netwatch\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

fn systemctl(args: &[&str]) -> Result<String, String> {
    let out = Command::new("systemctl")
        .args(args)
        .output()
        .map_err(|e| format!("could not run systemctl: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        Ok(text)
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        Err(if err.trim().is_empty() {
            text.trim().to_string()
        } else {
            err.trim().to_string()
        })
    }
}

pub fn install(keep_days: u64, later: bool) -> Result<(), String> {
    if !Path::new("/run/systemd/system").exists() {
        return Err(
            "this system does not run systemd, so there is no unit to install.\n\n\
                    Start the recorder yourself with:  netwatch record"
                .into(),
        );
    }

    let exe = std::env::current_exe()
        .map_err(|e| format!("could not find this executable: {e}"))?
        .display()
        .to_string();

    let dir = crate::log::default_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    // The service runs without CAP_DAC_OVERRIDE, so it can only write a
    // directory it owns. One left over from an earlier unprivileged run
    // belongs to that person, and the recorder would start, report itself
    // healthy, and write nothing at all.
    if let Err(e) = std::os::unix::fs::chown(&dir, Some(0), Some(0)) {
        eprintln!(
            "warning: could not give {} to root ({e}); the recorder may not be \
             able to write there.",
            dir.display()
        );
    }

    std::fs::write(UNIT_PATH, unit(&exe, keep_days)).map_err(|e| {
        format!(
            "could not write {UNIT_PATH}: {e}\n\n\
             Installing a boot service needs root. Run this with sudo."
        )
    })?;

    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", UNIT])?;

    println!("Recording at every boot.");
    println!("  unit     {UNIT}");
    println!("  runs     {exe} record --keep-days {keep_days}");
    println!(
        "  log      one file a day, {keep_days} days kept, in {}",
        dir.display()
    );
    println!();
    println!("It asks for CAP_BPF and CAP_PERFMON rather than running as root,");
    println!("and is restarted if it ever stops — a gap in the log is the one");
    println!("thing a recorder must not have.");
    println!();

    if later {
        println!("Not started yet; it begins at the next boot.");
    } else {
        match systemctl(&["start", UNIT]) {
            Ok(_) => println!("Started now, so there is no need to reboot first."),
            Err(e) => println!("Enabled, but could not start it now: {e}"),
        }
    }
    println!();
    println!("Any time after:     netwatch report --hours 12");
    println!("To stop recording:  netwatch service uninstall");
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    // Stopping and disabling may each fail because it was never running or
    // never enabled, which is not a reason to refuse to remove the rest.
    let _ = systemctl(&["stop", UNIT]);
    let _ = systemctl(&["disable", UNIT]);

    match std::fs::remove_file(UNIT_PATH) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err("netwatch is not installed as a service.".into());
        }
        Err(e) => {
            return Err(format!(
                "could not remove {UNIT_PATH}: {e}\n\nThis needs root; run it with sudo."
            ));
        }
    }
    let _ = systemctl(&["daemon-reload"]);

    println!("Removed. netwatch no longer records at boot.");
    println!("The log it already wrote is untouched — delete it yourself if you want it gone.");
    Ok(())
}

pub fn status() -> Result<(), String> {
    if !Path::new(UNIT_PATH).exists() {
        println!("Not installed — netwatch is not recording at boot.");
        println!();
        println!("To start, as root:");
        println!("    netwatch service install");
        return Ok(());
    }

    // `is-active` and `is-enabled` answer with a word and a non-zero exit when
    // the answer is "no", which is an answer rather than a failure.
    let active = systemctl(&["is-active", UNIT]).unwrap_or_else(|e| e);
    let enabled = systemctl(&["is-enabled", UNIT]).unwrap_or_else(|e| e);
    println!("unit     {UNIT}");
    println!("active   {}", active.trim());
    println!("at boot  {}", enabled.trim());

    if let Ok(text) = systemctl(&["show", UNIT, "--property=ExecMainStartTimestamp"])
        && let Some(v) = text.split_once('=')
    {
        let when = v.1.trim();
        if !when.is_empty() {
            println!("started  {when}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The unit has to ask for the rights the recorder actually needs. Without
    /// them it starts and then fails to load its program, which looks like a
    /// netwatch bug rather than a missing capability.
    #[test]
    fn the_unit_asks_for_the_rights_ebpf_needs() {
        let u = unit("/usr/local/bin/netwatch", 30);
        assert!(u.contains("AmbientCapabilities=CAP_BPF CAP_PERFMON"), "{u}");
        assert!(u.contains("CapabilityBoundingSet=CAP_BPF CAP_PERFMON"));
        assert!(
            !u.contains("User="),
            "it runs as root's capabilities, not as a named user"
        );
    }

    /// A recorder that stops and stays stopped leaves a gap precisely where
    /// someone will later look, so it must come back on its own.
    #[test]
    fn the_recorder_is_restarted_if_it_stops() {
        let u = unit("/usr/local/bin/netwatch", 30);
        assert!(u.contains("Restart=always"));
        assert!(u.contains("RestartSec="));
    }

    /// It is confined, but not so far that it cannot write the one thing it
    /// exists to write.
    ///
    /// This is not hypothetical. With the bounding set above, root loses
    /// CAP_DAC_OVERRIDE and cannot write a directory owned by anyone else. The
    /// first version of this unit started, reported itself active and enabled,
    /// and logged "Permission denied" once a minute while recording nothing.
    #[test]
    fn it_can_still_write_its_log() {
        let u = unit("/usr/local/bin/netwatch", 7);
        assert!(u.contains("ProtectSystem=strict"));
        assert!(
            u.contains("LogsDirectory=netwatch"),
            "systemd has to make the directory and hand it to the service: {u}"
        );
        assert!(
            u.contains("ReadWritePaths=/var/log/netwatch"),
            "strict protection without this would silently stop the log: {u}"
        );
    }

    #[test]
    fn the_command_carries_the_retention_it_was_given() {
        assert!(
            unit("/opt/nw/netwatch", 7).contains("ExecStart=/opt/nw/netwatch record --keep-days 7")
        );
    }

    /// A unit file is parsed line by line; a stray blank or missing section
    /// header makes systemd reject the whole thing.
    #[test]
    fn it_has_the_three_sections_systemd_expects() {
        let u = unit("/usr/local/bin/netwatch", 30);
        assert!(u.starts_with("[Unit]\n"));
        assert!(u.contains("\n[Service]\n"));
        assert!(u.contains("\n[Install]\n"));
        assert!(u.ends_with('\n'), "systemd wants a final newline");
    }
}
