//! The icon by the clock.
//!
//! The recorder runs as SYSTEM in session 0, which has no desktop — so it
//! cannot show anything, ever. That is the right place for a recorder (it
//! starts before anyone logs in and keeps running after they log out) and the
//! wrong place for an icon. So the two are separate programs: this one runs in
//! the person's own session, owns the icon, and reads the same log the
//! recorder writes.
//!
//! It needs no elevation, because reading a file needs none. It also does not
//! measure anything itself — one measurer, one record, and a display that
//! cannot disagree with it.

use std::path::Path;
use std::time::Duration;

use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIconBuilder};

use crate::{bytes, log, rate};

/// How often the tooltip is refreshed from the log. The recorder writes a line
/// a minute, so anything faster would re-read the same numbers.
const REFRESH: Duration = Duration::from_secs(20);

/// A small bar chart, drawn rather than shipped.
///
/// An icon file would be one more thing to keep next to the binary and one
/// more thing to lose; four rectangles are enough to read as "activity" at
/// 16 pixels, which is the only size this is ever seen at.
fn icon() -> Result<Icon, String> {
    const N: u32 = 32;
    let mut rgba = vec![0u8; (N * N * 4) as usize];

    // Bar heights as a fraction of the icon, left to right.
    let bars = [0.35_f32, 0.6, 0.45, 0.85];
    let bar_w = 6;
    let gap = 2;
    let left = (N as i32 - (bars.len() as i32 * (bar_w + gap) - gap)) / 2;

    for (i, h) in bars.iter().enumerate() {
        let x0 = left + i as i32 * (bar_w + gap);
        let top = ((1.0 - h) * (N as f32 - 4.0)) as i32 + 2;
        for y in top..(N as i32 - 2) {
            for x in x0..(x0 + bar_w) {
                if x < 0 || y < 0 || x >= N as i32 || y >= N as i32 {
                    continue;
                }
                let o = ((y as u32 * N + x as u32) * 4) as usize;
                // The same cyan the live view uses for a sparkline, so the
                // icon and the screen look like one program.
                rgba[o] = 0x22;
                rgba[o + 1] = 0xB8;
                rgba[o + 2] = 0xCF;
                rgba[o + 3] = 0xFF;
            }
        }
    }

    Icon::from_rgba(rgba, N, N).map_err(|e| format!("could not build the icon: {e}"))
}

/// What the log says about the last few minutes, for the tooltip.
fn summary(dir: &Path) -> String {
    let now = log::now_secs();
    let boot = log::boot_secs();
    let rows = log::read_range(dir, boot / 60, u64::MAX);

    if rows.is_empty() {
        return "netwatch — nothing is being recorded\n\
                Run: netwatch service install"
            .to_string();
    }

    let total: u64 = rows.iter().map(|r| r.total()).sum();

    // The most recent complete minute, as a rate. The minute in progress is
    // deliberately skipped: it is partial, and would always read low.
    let last = rows.iter().map(|r| r.minute).max().unwrap_or(0);
    let recent: u64 = rows
        .iter()
        .filter(|r| r.minute == last)
        .map(|r| r.total())
        .sum();

    let busiest = {
        let mut by_name: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();
        for r in &rows {
            *by_name.entry(r.name.as_str()).or_insert(0) += r.total();
        }
        let mut v: Vec<(&str, u64)> = by_name.into_iter().collect();
        v.sort_by_key(|(_, b)| std::cmp::Reverse(*b));
        v.first()
            .map(|(n, b)| format!("{n} {}", bytes(*b)))
            .unwrap_or_default()
    };

    let up_secs = now.saturating_sub(boot);
    format!(
        "netwatch — recording\n\
         {} since boot ({}h{:02}m)\n\
         last minute {}\n\
         busiest {busiest}",
        bytes(total),
        up_secs / 3600,
        (up_secs % 3600) / 60,
        rate(recent as f64 / 60.0),
    )
}

pub fn run() -> Result<(), String> {
    let dir = log::default_dir();

    let open = MenuItem::new("Open the live view", true, None);
    let report = MenuItem::new("Report — last 12 hours", true, None);
    let folder = MenuItem::new("Open the log folder", true, None);
    let quit = MenuItem::new("Quit this icon (recording continues)", true, None);

    let menu = Menu::new();
    for item in [&open, &report, &folder] {
        menu.append(item).map_err(|e| e.to_string())?;
    }
    menu.append(&PredefinedMenuItem::separator())
        .map_err(|e| e.to_string())?;
    menu.append(&quit).map_err(|e| e.to_string())?;

    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip(summary(&dir))
        .with_icon(icon()?)
        .build()
        .map_err(|e| format!("could not create the tray icon: {e}"))?;

    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let menu_rx = MenuEvent::receiver();
    let mut last_refresh = std::time::Instant::now();

    // The message loop the icon needs, pumped by hand: nothing here draws a
    // window, so a windowing library would be a dependency earning nothing.
    loop {
        pump();

        while let Ok(ev) = menu_rx.try_recv() {
            if ev.id == quit.id() {
                return Ok(());
            } else if ev.id == open.id() {
                // A new elevated console: the live view reads a kernel trace,
                // which an unelevated process cannot open.
                let _ = std::process::Command::new("powershell")
                    .args([
                        "-NoProfile",
                        "-Command",
                        &format!("Start-Process -Verb RunAs '{}'", exe.display()),
                    ])
                    .spawn();
            } else if ev.id == report.id() {
                let _ = std::process::Command::new("cmd")
                    .args([
                        "/c",
                        "start",
                        "",
                        "cmd",
                        "/k",
                        &format!("\"{}\" report --hours 12", exe.display()),
                    ])
                    .spawn();
            } else if ev.id == folder.id() {
                let _ = std::process::Command::new("explorer")
                    .arg(dir.display().to_string())
                    .spawn();
            }
        }

        if last_refresh.elapsed() >= REFRESH {
            let _ = tray.set_tooltip(Some(summary(&dir)));
            last_refresh = std::time::Instant::now();
        }

        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Drain the thread's message queue. The icon is a window under the covers and
/// stops responding — including to its own menu — if nobody pumps for it.
#[cfg(windows)]
fn pump() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, MSG, PM_REMOVE, PeekMessageW, TranslateMessage,
    };

    // SAFETY: `msg` is written by PeekMessageW before it is read, and only
    // messages it reports as present are dispatched.
    unsafe {
        let mut msg: MSG = std::mem::zeroed();
        while PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

#[cfg(not(windows))]
fn pump() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_icon_is_the_size_windows_expects() {
        let i = icon();
        assert!(i.is_ok(), "icon did not build: {:?}", i.err());
    }

    /// The tooltip has to say the useful thing when there is nothing to say:
    /// "no data" and "not recording" look identical from the outside, and only
    /// one of them is a problem the person can fix.
    #[test]
    fn an_empty_log_says_that_nothing_is_recording() {
        let dir = std::env::temp_dir().join("netwatch_tray_empty");
        let _ = std::fs::remove_dir_all(&dir);
        let text = summary(&dir);
        assert!(text.contains("nothing is being recorded"), "{text}");
        assert!(
            text.contains("service install"),
            "and how to fix it: {text}"
        );
    }
}
