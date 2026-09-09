//! The live view.
//!
//! One row per program, busiest first, updating every second. The question it
//! answers is "what is using my connection right now", so the default sort is
//! by rate rather than by total — a process that downloaded a gigabyte an hour
//! ago is not the answer to that question, and pushing it to the top would
//! bury the one that is.

use std::io;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{self, Event as TermEvent, KeyCode, KeyEventKind};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::prelude::*;
use ratatui::widgets::{
    Block, Borders, Cell, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState,
    Table, TableState,
};

use crate::hidden::Hidden;
use crate::procs;
use crate::state::{Process, State};
use crate::{bytes, etw, rate, trunc};

/// A question the screen is waiting on before doing something irreversible.
struct Confirm {
    pid: u32,
    name: String,
    path: String,
    critical: bool,
}

struct App {
    state: State,
    table: TableState,
    /// Rank by what is moving now, rather than by what has moved in total.
    by_rate: bool,
    /// The process whose peers are open, if any.
    expanded: Option<u32>,
    /// Programs kept out of the list. Still recorded — this is the view only.
    hidden: Hidden,
    /// Show the hidden ones anyway, to remember what was hidden and undo it.
    show_hidden: bool,
    /// Set while a stop is waiting to be confirmed.
    confirm: Option<Confirm>,
    /// The last thing that happened, said once in the header.
    status: String,
    started: Instant,
}

impl App {
    /// The list as it is shown: ranked, then filtered by what is hidden.
    ///
    /// Filtering happens here rather than in `State` on purpose — the record
    /// must not know about it, or hiding something would stop it being
    /// measured.
    fn visible(&self) -> Vec<&Process> {
        self.state
            .ranked(self.by_rate)
            .into_iter()
            .filter(|p| self.show_hidden || !self.hidden.is_hidden(&p.name))
            .collect()
    }

    fn selected(&self) -> Option<(u32, String, String)> {
        self.visible()
            .get(self.table.selected().unwrap_or(0))
            .map(|p| (p.pid, p.name.clone(), p.info.path.clone()))
    }
}

pub fn run() -> Result<(), String> {
    let (tx, rx) = mpsc::channel();
    let trace = etw::start(tx)?;

    let mut app = App {
        state: State::new(),
        table: TableState::default().with_selected(0),
        by_rate: true,
        expanded: None,
        hidden: Hidden::load(crate::hidden::default_path()),
        show_hidden: false,
        confirm: None,
        status: String::new(),
        started: Instant::now(),
    };

    enable_raw_mode().map_err(|e| e.to_string())?;
    let mut out = io::stdout();
    execute!(out, EnterAlternateScreen).map_err(|e| e.to_string())?;
    let mut term = Terminal::new(CrosstermBackend::new(out)).map_err(|e| e.to_string())?;

    let result = event_loop(&mut term, &mut app, &rx);

    // Put the terminal back whatever happened: leaving someone in raw mode
    // with no echo is worse than any error we could report.
    let _ = disable_raw_mode();
    let _ = execute!(term.backend_mut(), LeaveAlternateScreen);
    let _ = term.show_cursor();
    let _ = trace.stop();
    result
}

fn event_loop<B: Backend>(
    term: &mut Terminal<B>,
    app: &mut App,
    rx: &mpsc::Receiver<etw::Event>,
) -> Result<(), String> {
    let mut last_tick = Instant::now();

    loop {
        // Everything the kernel has said since the last pass. Draining without
        // blocking keeps the screen responsive when traffic is heavy.
        while let Ok(ev) = rx.try_recv() {
            app.state.apply(ev);
        }
        if last_tick.elapsed() >= Duration::from_secs(1) {
            app.state.tick(last_tick.elapsed().as_secs_f64());
            last_tick = Instant::now();
        }

        term.draw(|f| draw(f, app)).map_err(|e| e.to_string())?;

        if !event::poll(Duration::from_millis(200)).map_err(|e| e.to_string())? {
            continue;
        }
        let TermEvent::Key(key) = event::read().map_err(|e| e.to_string())? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        // A pending confirmation owns every key: nothing behind it may move
        // while a question about stopping a process is on screen.
        if let Some(c) = &app.confirm {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    let (pid, name) = (c.pid, c.name.clone());
                    app.status = match procs::terminate(pid) {
                        Ok(()) => format!("stopped {name} (pid {pid})"),
                        Err(e) => format!("could not stop {name}: {e}"),
                    };
                    app.confirm = None;
                }
                _ => {
                    app.confirm = None;
                    app.status = "left it running".into();
                }
            }
            continue;
        }

        let rows = app.visible().len();
        match key.code {
            KeyCode::Char('q') => return Ok(()),
            KeyCode::Esc if app.expanded.is_some() => app.expanded = None,
            KeyCode::Esc => return Ok(()),
            KeyCode::Char('t') => app.by_rate = !app.by_rate,
            // Hiding is per program name, so a restart stays hidden.
            KeyCode::Char('h') => {
                if let Some((_, name, _)) = app.selected() {
                    let now_hidden = app.hidden.toggle(&name);
                    app.status = if now_hidden {
                        format!("hiding {name} — still recorded")
                    } else {
                        format!("showing {name} again")
                    };
                    app.table.select(Some(0));
                }
            }
            KeyCode::Char('H') => {
                app.show_hidden = !app.show_hidden;
                app.table.select(Some(0));
            }
            KeyCode::Char('x') => {
                if let Some((pid, name, path)) = app.selected() {
                    app.confirm = Some(Confirm {
                        pid,
                        critical: procs::is_critical(&name),
                        name,
                        path,
                    });
                }
            }
            KeyCode::Enter => {
                app.expanded = match app.expanded {
                    Some(_) => None,
                    None => app.selected().map(|(pid, _, _)| pid),
                };
            }
            KeyCode::Down | KeyCode::Char('j') => move_by(app, rows, 1),
            KeyCode::Up | KeyCode::Char('k') => move_by(app, rows, -1),
            KeyCode::Home | KeyCode::Char('g') => app.table.select(Some(0)),
            KeyCode::End | KeyCode::Char('G') => app.table.select(Some(rows.saturating_sub(1))),
            _ => {}
        }
    }
}

fn move_by(app: &mut App, rows: usize, delta: isize) {
    if rows == 0 {
        return;
    }
    let cur = app.table.selected().unwrap_or(0) as isize;
    app.table
        .select(Some((cur + delta).clamp(0, rows as isize - 1) as usize));
}

/// Busy rows should catch the eye before quiet ones, without having to read
/// the number first.
fn rate_style(v: f64) -> Style {
    if v >= 1_000_000.0 {
        Style::new().fg(Color::Red).bold()
    } else if v >= 100_000.0 {
        Style::new().fg(Color::Yellow)
    } else if v >= 1.0 {
        Style::new().fg(Color::Green)
    } else {
        Style::new().fg(Color::DarkGray)
    }
}

/// The last minute as a shape, in one cell.
///
/// Scaled to the process's own maximum rather than to the busiest program on
/// screen: the question this answers is "what has this one been doing", and
/// against a global scale every program but the loudest would be a flat line.
///
/// An idle tick draws as the lowest mark rather than as a blank, because a gap
/// reads as missing data when it means the program was quiet.
fn sparkline(history: &std::collections::VecDeque<f64>, width: usize) -> String {
    const MARKS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    if history.is_empty() {
        return String::new();
    }
    let peak = history.iter().cloned().fold(0.0_f64, f64::max);
    let start = history.len().saturating_sub(width);
    history
        .iter()
        .skip(start)
        .map(|v| {
            if peak <= 0.0 {
                MARKS[0]
            } else {
                // The top mark is reserved for the peak itself, so the busiest
                // moment is visible rather than tied with everything near it.
                let idx = ((v / peak) * (MARKS.len() - 1) as f64).round() as usize;
                MARKS[idx.min(MARKS.len() - 1)]
            }
        })
        .collect()
}

fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .split(f.area());

    // Everything that reads the process list is done here, in one block, so
    // the borrow ends before the table needs `&mut app.table` to scroll.
    let (rows, shown, down, up) = {
        let ranked = app.visible();
        let down: f64 = ranked.iter().map(|p| p.received_rate).sum();
        let up: f64 = ranked.iter().map(|p| p.sent_rate).sum();
        let rows: Vec<Row> = ranked
            .iter()
            .map(|p| {
                // A hidden program only appears while they are being shown,
                // and then it should be obvious which ones they are.
                let name = if app.hidden.is_hidden(&p.name) {
                    Cell::from(trunc(&p.name, 26)).style(Style::new().fg(Color::DarkGray).italic())
                } else {
                    Cell::from(trunc(&p.name, 26))
                };
                Row::new(vec![
                    name,
                    Cell::from(Line::from(p.pid.to_string()).right_aligned()),
                    Cell::from(sparkline(&p.history, 20)).style(Style::new().fg(Color::Cyan)),
                    Cell::from(Line::from(rate(p.received_rate)).right_aligned())
                        .style(rate_style(p.received_rate)),
                    Cell::from(Line::from(rate(p.sent_rate)).right_aligned())
                        .style(rate_style(p.sent_rate)),
                    Cell::from(Line::from(bytes(p.traffic.received)).right_aligned()),
                    Cell::from(Line::from(bytes(p.traffic.sent)).right_aligned()),
                    Cell::from(Line::from(p.peers.len().to_string()).right_aligned()),
                ])
            })
            .collect();
        (rows, ranked.len(), down, up)
    };
    let elapsed = app.started.elapsed().as_secs();

    // ── title ───────────────────────────────────────────────────────────────
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                " netwatch ",
                Style::new().bold().bg(Color::Cyan).fg(Color::Black),
            ),
            Span::styled(
                format!(" ↓ {:<12}", rate(down)),
                Style::new().fg(Color::Green).bold(),
            ),
            Span::styled(
                format!("↑ {:<12}", rate(up)),
                Style::new().fg(Color::Blue).bold(),
            ),
            Span::styled(
                format!(
                    "{} programs · {} in {}m{:02}s · by {}",
                    shown,
                    bytes(app.state.total.total()),
                    elapsed / 60,
                    elapsed % 60,
                    if app.by_rate { "rate" } else { "total" }
                ),
                Style::new().fg(Color::DarkGray),
            ),
            // Never filter silently: a list that is quietly incomplete is
            // worse than one that is long.
            Span::styled(
                if app.hidden.is_empty() {
                    String::new()
                } else if app.show_hidden {
                    format!(" · {} hidden, shown", app.hidden.len())
                } else {
                    format!(" · {} hidden", app.hidden.len())
                },
                Style::new().fg(Color::Yellow),
            ),
            Span::styled(
                if app.status.is_empty() {
                    String::new()
                } else {
                    format!("   {}", app.status)
                },
                Style::new().fg(Color::Cyan),
            ),
        ])),
        chunks[0],
    );

    // ── table ───────────────────────────────────────────────────────────────
    let header = Row::new(
        [
            "PROGRAM",
            "PID",
            "LAST MINUTE",
            "DOWN",
            "UP",
            "TOTAL ↓",
            "TOTAL ↑",
            "PEERS",
        ]
        .into_iter()
        .enumerate()
        .map(|(i, t)| {
            let line = Line::from(t);
            // Columns 0 and 2 are a name and a picture; the rest are numbers.
            Cell::from(if i == 0 || i == 2 {
                line
            } else {
                line.right_aligned()
            })
        }),
    )
    .style(Style::new().bold().fg(Color::White));

    let widths = [
        Constraint::Min(18),
        Constraint::Length(8),
        Constraint::Length(20),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(11),
        Constraint::Length(11),
        Constraint::Length(7),
    ];
    f.render_stateful_widget(
        Table::new(rows, widths)
            .header(header)
            .column_spacing(1)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::new().fg(Color::DarkGray)),
            )
            .row_highlight_style(Style::new().bg(Color::Rgb(38, 45, 56)))
            .highlight_symbol("▌"),
        chunks[1],
        &mut app.table,
    );

    let visible = chunks[1].height.saturating_sub(3) as usize;
    if shown > visible {
        let mut sb = ScrollbarState::new(shown).position(app.table.selected().unwrap_or(0));
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None)
                .thumb_style(Style::new().fg(Color::DarkGray)),
            chunks[1].inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut sb,
        );
    }

    // ── keys ────────────────────────────────────────────────────────────────
    let key = Style::new().fg(Color::Cyan).bold();
    let dim = Style::new().fg(Color::DarkGray);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" Enter", key),
            Span::styled(" details   ", dim),
            Span::styled("h", key),
            Span::styled(" hide   ", dim),
            Span::styled("H", key),
            Span::styled(" show hidden   ", dim),
            Span::styled("x", key),
            Span::styled(" stop   ", dim),
            Span::styled("t", key),
            Span::styled(" sort   ", dim),
            Span::styled("j k", key),
            Span::styled(" move   ", dim),
            Span::styled("q", key),
            Span::styled(" quit", dim),
        ])),
        chunks[2],
    );

    if let Some(c) = &app.confirm {
        draw_confirm(f, c);
    }

    if let Some(pid) = app.expanded {
        draw_detail(f, app, pid);
    }
}

/// Which protocols a program is actually speaking, deduplicated.
fn protocols(p: &Process) -> String {
    let mut kinds: Vec<String> = p
        .peers
        .values()
        .map(|peer| format!("{:?}", peer.proto).to_uppercase())
        .collect();
    kinds.sort();
    kinds.dedup();
    kinds.join("/")
}

/// A duration as a person would say it. Seconds below a minute, then minutes,
/// then hours — one unit, because "1h 4m 12s" is read as a number rather than
/// as a length of time.
fn ago(d: Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        format!("{s}s")
    } else if s < 3_600 {
        format!("{}m", s / 60)
    } else {
        format!("{}h{:02}m", s / 3_600, (s % 3_600) / 60)
    }
}

/// The question asked before a process is killed.
///
/// `TerminateProcess` gives the program no chance to save anything and cannot
/// be undone, so it gets a deliberate yes — and when the target is something
/// Windows needs, the warning says what will actually happen rather than
/// leaving "are you sure" to carry it.
fn draw_confirm(f: &mut Frame, c: &Confirm) {
    let area = f.area();
    let w = area.width.saturating_sub(8).clamp(40, 76);
    let h = if c.critical { 12 } else { 10 };
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h.min(area.height),
    };

    let dim = Style::new().fg(Color::DarkGray);
    let mut lines = vec![
        Line::from(vec![
            Span::styled(c.name.clone(), Style::new().bold()),
            Span::styled(format!("  (pid {})", c.pid), dim),
        ]),
        Line::styled(
            if c.path.is_empty() {
                "path could not be read".to_string()
            } else {
                c.path.clone()
            },
            dim,
        ),
        Line::raw(""),
        Line::raw("It will be killed immediately. Anything it had not"),
        Line::raw("saved is lost, and this cannot be undone."),
    ];

    if c.critical {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "This is a core Windows process. Stopping it will",
            Style::new().fg(Color::Red).bold(),
        ));
        lines.push(Line::styled(
            "very likely crash the machine.",
            Style::new().fg(Color::Red).bold(),
        ));
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        Span::styled("  y", Style::new().fg(Color::Red).bold()),
        Span::styled("  stop it        ", dim),
        Span::styled("any other key", Style::new().fg(Color::Green).bold()),
        Span::styled("  leave it alone", dim),
    ]));

    f.render_widget(Clear, popup);
    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::new().fg(if c.critical {
                    Color::Red
                } else {
                    Color::Yellow
                }))
                .title(" Stop this program? "),
        ),
        popup,
    );
}

/// One program in full: what it says it is, where it lives, and where it has
/// been talking.
///
/// The path is the point. `svchost.exe` from `System32` is the operating
/// system; the same name from a temp directory, claiming nothing about itself,
/// is the single most useful thing this screen can show. Peers are addresses
/// only — the transfer events carry no hostname, and inventing one by reverse
/// lookup would attach a name the traffic never mentioned.
fn draw_detail(f: &mut Frame, app: &App, pid: u32) {
    let Some(p) = app.state.get(pid) else { return };

    let area = f.area();
    let w = area.width.saturating_sub(6).clamp(40, 100);
    let h = area.height.saturating_sub(4).clamp(12, 26);
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    };

    let mut peers: Vec<_> = p.peers.values().collect();
    peers.sort_by_key(|p| std::cmp::Reverse(p.traffic.total()));

    f.render_widget(Clear, popup);
    f.render_widget(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::new().fg(Color::Cyan))
            // The friendly name when the file carries one: "Mozilla Firefox"
            // says more than "firefox.exe", and the file name is on the path
            // line just below it either way.
            .title(format!(" {} — Esc closes ", trunc(p.info.label(), 40))),
        popup,
    );

    let inner = popup.inner(Margin {
        vertical: 1,
        horizontal: 1,
    });
    // One row per field, plus the blank line before the peers. Sized from the
    // field list rather than guessed: adding a field and forgetting this is
    // how the last one silently disappeared.
    const FIELDS: u16 = 6;
    let parts = Layout::vertical([Constraint::Length(FIELDS + 1), Constraint::Min(1)]).split(inner);

    let dim = Style::new().fg(Color::DarkGray);
    let unknown = Style::new().fg(Color::Yellow);
    let field = |label: &'static str, value: &str, empty: &'static str| {
        let (text, style) = if value.is_empty() {
            (empty.to_string(), unknown)
        } else {
            (value.to_string(), Style::new())
        };
        Line::from(vec![
            Span::styled(format!("{label:<10}"), dim),
            Span::styled(text, style),
        ])
    };

    f.render_widget(
        Paragraph::new(vec![
            // Identity first, and the pid at the top of it: it is what every
            // other tool on the machine wants in order to talk about this
            // program, and it should not have to be found in the middle of a
            // line of byte counts.
            Line::from(vec![
                Span::styled(format!("{:<10}", "pid"), dim),
                Span::styled(p.pid.to_string(), Style::new().bold()),
                Span::styled(format!("   {} peers, {}", peers.len(), protocols(p)), dim),
            ]),
            field(
                "described",
                &p.info.description,
                "no description in the file",
            ),
            field(
                "publisher",
                &p.info.company,
                "no publisher named in the file",
            ),
            field("path", &p.info.path, "could not be read"),
            Line::from(vec![
                Span::styled(format!("{:<10}", "seen"), dim),
                Span::raw(format!(
                    "{} ago, first {} into this run",
                    ago(p.last_seen.elapsed()),
                    ago(p.first_seen.duration_since(app.started))
                )),
            ]),
            Line::from(vec![
                Span::styled(format!("{:<10}", "traffic"), dim),
                Span::styled(bytes(p.traffic.received), Style::new().fg(Color::Green)),
                Span::styled(" down · ", dim),
                Span::styled(bytes(p.traffic.sent), Style::new().fg(Color::Blue)),
                Span::styled(" up", dim),
            ]),
        ]),
        parts[0],
    );

    let rows: Vec<Row> = peers
        .iter()
        .map(|peer| {
            // Name and address both: the name says who it is, the address is
            // what was actually connected to — and one name often answers
            // with several.
            let who = match &peer.host {
                Some(h) => Line::from(vec![
                    Span::raw(h.clone()),
                    Span::styled(
                        format!("  {}:{}", peer.addr, peer.port),
                        Style::new().fg(Color::DarkGray),
                    ),
                ]),
                None => Line::from(format!("{}:{}", peer.addr, peer.port)),
            };
            Row::new(vec![
                Cell::from(who),
                Cell::from(Line::from(format!("{:?}", peer.proto).to_uppercase()).right_aligned()),
                Cell::from(Line::from(bytes(peer.traffic.received)).right_aligned()),
                Cell::from(Line::from(bytes(peer.traffic.sent)).right_aligned()),
            ])
        })
        .collect();

    f.render_widget(
        Table::new(
            rows,
            [
                Constraint::Min(30),
                Constraint::Length(6),
                Constraint::Length(11),
                Constraint::Length(11),
            ],
        )
        .header(
            Row::new(vec![
                Cell::from("PEER  (address)"),
                Cell::from(Line::from("PROTO").right_aligned()),
                Cell::from(Line::from("DOWN").right_aligned()),
                Cell::from(Line::from("UP").right_aligned()),
            ])
            .style(Style::new().bold()),
        )
        .column_spacing(1),
        parts[1],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::etw::{Dir, Proto};
    use std::net::{IpAddr, Ipv4Addr};

    /// Distinguishes one demo App from another, so their hidden-lists do not
    /// share a file.
    static DEMO_SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    fn demo() -> App {
        let mut state = State::new();
        for (pid, dir, n, peer) in [
            (6124u32, Dir::Received, 641_188u64, [185, 184, 222, 3]),
            (6124, Dir::Sent, 88_120, [185, 184, 222, 3]),
            (6124, Dir::Received, 210_004, [140, 82, 114, 25]),
            (4852, Dir::Received, 33_185, [93, 184, 216, 34]),
            (4852, Dir::Sent, 4_002, [93, 184, 216, 34]),
            (2628, Dir::Sent, 4_574, [84, 17, 53, 155]),
        ] {
            state.apply(crate::etw::Event::Transfer(crate::etw::Transfer {
                pid,
                proto: Proto::Tcp,
                dir,
                bytes: n,
                peer: IpAddr::V4(Ipv4Addr::from(peer)),
                peer_port: 443,
            }));
        }
        // One peer the machine looked up, one it did not: both cases have to
        // render, and the unnamed one must not be left blank.
        state.apply(crate::etw::Event::Named {
            addr: IpAddr::V4(Ipv4Addr::new(140, 82, 114, 25)),
            host: "api.github.com".into(),
        });

        // A minute of history, with shapes that differ: one program ramping
        // up, one steady, one that burst once and stopped. A single tick would
        // draw one block and prove nothing about the drawing.
        for i in 0..24u64 {
            for (pid, peer, n) in [
                (6124u32, [185, 184, 222, 3], 20_000 + i * 26_000),
                (4852, [93, 184, 216, 34], 30_000),
                (2628, [84, 17, 53, 155], if i == 9 { 900_000 } else { 200 }),
            ] {
                state.apply(crate::etw::Event::Transfer(crate::etw::Transfer {
                    pid,
                    proto: Proto::Tcp,
                    dir: Dir::Received,
                    bytes: n,
                    peer: IpAddr::V4(Ipv4Addr::from(peer)),
                    peer_port: 443,
                }));
            }
            state.tick(1.0);
        }

        // Described here rather than read off the machine the test runs on:
        // otherwise these assertions would be about whatever happened to hold
        // pid 6124 today.
        state.set_info(
            6124,
            crate::procs::Info {
                name: "firefox.exe".into(),
                path: "C:/Program Files/Mozilla Firefox/firefox.exe".into(),
                description: "Mozilla Firefox".into(),
                company: "Mozilla Corporation".into(),
            },
        );
        state.set_info(
            4852,
            crate::procs::Info {
                name: "backup-agent.exe".into(),
                path: "C:/Program Files/Backup/backup-agent.exe".into(),
                description: "Backup Agent".into(),
                company: "Acme Ltd".into(),
            },
        );
        // A file that claims nothing about itself: the interesting case.
        state.set_info(
            2628,
            crate::procs::Info {
                name: "mystery.exe".into(),
                path: "C:/Users/x/AppData/Local/Temp/mystery.exe".into(),
                description: String::new(),
                company: String::new(),
            },
        );

        App {
            state,
            table: TableState::default().with_selected(0),
            by_rate: true,
            expanded: None,
            // A fresh file per call, not per process: the tests run in
            // parallel in one binary, and sharing one path made whichever
            // test hid something break whichever test counted rows.
            hidden: Hidden::load(std::env::temp_dir().join("netwatch_tui_test").join(format!(
                "hidden-{}-{}.txt",
                std::process::id(),
                DEMO_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ))),
            show_hidden: false,
            confirm: None,
            status: String::new(),
            started: Instant::now(),
        }
    }

    fn render(app: &mut App, w: u16, h: u16) -> String {
        use ratatui::backend::TestBackend;
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| draw(f, app)).unwrap();
        let buf = term.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn the_live_view_draws_and_fits() {
        let mut app = demo();
        let text = render(&mut app, 108, 12);
        println!("\n{text}");

        for expected in ["netwatch", "PROGRAM", "DOWN", "TOTAL", "PEERS", "quit"] {
            assert!(text.contains(expected), "missing {expected}:\n{text}");
        }
        // Rates are scaled, not printed as raw byte counts.
        assert!(!text.contains("641188"), "raw byte count leaked:\n{text}");
        for line in text.lines() {
            assert!(line.chars().count() <= 108, "line overflows: {line:?}");
        }
    }

    #[test]
    fn the_peers_of_one_program_can_be_opened() {
        let mut app = demo();
        app.expanded = Some(6124);
        let text = render(&mut app, 108, 16);
        println!("\n{text}");

        assert!(text.contains("185.184.222.3:443"), "peer missing:\n{text}");
        assert!(
            text.contains("140.82.114.25:443"),
            "second peer missing:\n{text}"
        );
        assert!(text.contains("2 peers"), "peer count missing:\n{text}");
        // A different program's peer must not appear under this one.
        assert!(
            !text.contains("84.17.53.155"),
            "peers leaked across processes:\n{text}"
        );
    }

    /// The path is the point of the card: a name alone cannot tell System32
    /// from a temp directory.
    #[test]
    fn the_card_shows_what_the_program_is_and_where_it_lives() {
        let mut app = demo();
        app.expanded = Some(6124);
        let text = render(&mut app, 108, 18);
        println!("\n{text}");
        assert!(
            text.contains("Mozilla Firefox"),
            "description missing:\n{text}"
        );
        assert!(
            text.contains("Mozilla Corporation"),
            "publisher missing:\n{text}"
        );
        assert!(text.contains("firefox.exe"), "path missing:\n{text}");

        // The rest of what identifies a program in the moment. The traffic
        // line is asserted because it was the one that silently fell off the
        // bottom when two fields were added above it.
        assert!(text.contains("seen"), "no first-seen line:\n{text}");
        assert!(text.contains("TCP"), "protocol not named:\n{text}");

        // The pid gets a line of its own, at the top. Buried in the middle of
        // a line of byte counts it was missed entirely by the first person to
        // look at this screen.
        let pid_line = text.lines().find(|l| l.contains("pid")).unwrap_or_default();
        assert!(
            pid_line.contains("6124"),
            "pid is not on its own line:\n{text}"
        );

        assert!(
            text.contains("8.1 MB down"),
            "the traffic line went missing:\n{text}"
        );
    }

    /// A file that claims nothing about itself is the interesting case, and an
    /// absence has to read as an absence rather than as a blank line.
    #[test]
    fn a_program_that_says_nothing_about_itself_says_so() {
        let mut app = demo();
        app.expanded = Some(2628);
        let text = render(&mut app, 108, 18);
        println!("\n{text}");
        assert!(
            text.contains("no description in the file"),
            "an empty description must be stated:\n{text}"
        );
        assert!(
            text.contains("no publisher named"),
            "an empty publisher must be stated:\n{text}"
        );
        assert!(
            text.contains("Temp"),
            "the path is what makes this one worth looking at:\n{text}"
        );
    }

    /// The two sorts answer different questions and must not be the same list
    /// by accident.
    /// The promise hiding makes: it changes the view and nothing else. A
    /// filter that quietly stopped recording would turn "I did not want to
    /// look at it" into "I have no idea what it did".
    #[test]
    fn hiding_changes_the_view_and_not_the_record() {
        let mut app = demo();
        assert_eq!(app.visible().len(), 3);

        app.hidden.toggle("mystery.exe");
        assert_eq!(app.visible().len(), 2, "one fewer on screen");
        assert_eq!(
            app.state.ranked(true).len(),
            3,
            "the record still holds all three"
        );

        // And what it measured is untouched.
        let still = app.state.get(2628).expect("still recorded");
        assert!(still.traffic.total() > 0);

        app.hidden.clear();
    }

    #[test]
    fn hidden_programs_can_be_brought_back() {
        let mut app = demo();
        app.hidden.toggle("mystery.exe");
        app.show_hidden = true;

        let text = render(&mut app, 108, 12);
        assert!(
            text.contains("mystery.exe"),
            "showing hidden must show them:
{text}"
        );
        assert!(
            text.contains("1 hidden, shown"),
            "the header must say what is going on:
{text}"
        );
        app.hidden.clear();
    }

    /// A list that is quietly incomplete is worse than a long one.
    #[test]
    fn the_header_never_hides_that_it_is_hiding() {
        let mut app = demo();
        app.hidden.toggle("mystery.exe");
        let text = render(&mut app, 108, 12);
        assert!(
            text.contains("1 hidden"),
            "not stated:
{text}"
        );
        assert!(
            !text.contains("mystery.exe"),
            "it should be out of the list:
{text}"
        );
        app.hidden.clear();
    }

    #[test]
    fn stopping_a_program_is_asked_about_first() {
        let mut app = demo();
        app.confirm = Some(Confirm {
            pid: 6124,
            name: "firefox.exe".into(),
            path: "C:/Program Files/Mozilla Firefox/firefox.exe".into(),
            critical: false,
        });
        let text = render(&mut app, 108, 16);
        println!(
            "
{text}"
        );

        assert!(
            text.contains("Stop this program?"),
            "no question:
{text}"
        );
        assert!(
            text.contains("firefox.exe"),
            "no name:
{text}"
        );
        assert!(
            text.contains("pid 6124"),
            "no pid:
{text}"
        );
        assert!(
            text.contains("cannot be undone"),
            "no warning:
{text}"
        );
        assert!(
            text.contains("leave it alone"),
            "no way out:
{text}"
        );
    }

    /// "Are you sure" does not carry enough when the answer is a blue screen.
    #[test]
    fn a_core_windows_process_says_what_will_happen() {
        let mut app = demo();
        app.confirm = Some(Confirm {
            pid: 900,
            name: "lsass.exe".into(),
            path: "C:/Windows/System32/lsass.exe".into(),
            critical: crate::procs::is_critical("lsass.exe"),
        });
        let text = render(&mut app, 108, 18);
        println!(
            "
{text}"
        );
        assert!(
            text.contains("core Windows process"),
            "the warning must name what it is:
{text}"
        );
        assert!(
            text.contains("crash the machine"),
            "and what it will do:
{text}"
        );
    }

    fn hist(v: &[f64]) -> std::collections::VecDeque<f64> {
        v.iter().cloned().collect()
    }

    /// The shape is the point: a steady stream and one burst can average to
    /// exactly the same rate, and the number cannot tell them apart.
    #[test]
    fn a_burst_and_a_steady_stream_look_different() {
        let steady = sparkline(&hist(&[50.0; 8]), 8);
        let burst = sparkline(&hist(&[0.0, 0.0, 0.0, 400.0, 0.0, 0.0, 0.0, 0.0]), 8);
        assert_ne!(steady, burst);
        assert!(burst.contains('█'), "the peak should stand out: {burst}");
        assert_eq!(burst.chars().filter(|c| *c == '█').count(), 1);
    }

    /// Scaled to the process's own peak, not to the busiest program on screen:
    /// otherwise everything but the loudest would be a flat line.
    #[test]
    fn each_program_is_drawn_against_its_own_peak() {
        let small = sparkline(&hist(&[1.0, 2.0, 4.0]), 8);
        let large = sparkline(&hist(&[1000.0, 2000.0, 4000.0]), 8);
        assert_eq!(small, large, "the same shape at any scale");
    }

    /// An idle tick is data. Drawn as a blank it would read as missing.
    #[test]
    fn quiet_ticks_are_drawn_not_skipped() {
        let s = sparkline(&hist(&[0.0, 0.0, 0.0]), 8);
        assert_eq!(s.chars().count(), 3);
        assert!(s.chars().all(|c| c == '▁'), "{s}");
    }

    #[test]
    fn only_the_last_ticks_are_shown() {
        let s = sparkline(&hist(&[9.0, 9.0, 9.0, 9.0, 9.0]), 3);
        assert_eq!(s.chars().count(), 3);
        assert!(sparkline(&hist(&[]), 8).is_empty());
    }

    #[test]
    fn the_sort_can_be_switched() {
        let app = demo();
        let by_rate = app.state.ranked(true)[0].pid;
        let by_total = app.state.ranked(false)[0].pid;
        assert_eq!(by_rate, 6124);
        assert_eq!(by_total, 6124);
        assert_eq!(app.state.ranked(true).len(), 3);
    }
}
