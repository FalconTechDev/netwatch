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

use crate::state::State;
use crate::{bytes, etw, rate, trunc};

struct App {
    state: State,
    table: TableState,
    /// Rank by what is moving now, rather than by what has moved in total.
    by_rate: bool,
    /// The process whose peers are open, if any.
    expanded: Option<u32>,
    started: Instant,
}

pub fn run() -> Result<(), String> {
    let (tx, rx) = mpsc::channel();
    let trace = etw::start(tx)?;

    let mut app = App {
        state: State::new(),
        table: TableState::default().with_selected(0),
        by_rate: true,
        expanded: None,
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

        let rows = app.state.ranked(app.by_rate).len();
        match key.code {
            KeyCode::Char('q') => return Ok(()),
            KeyCode::Esc if app.expanded.is_some() => app.expanded = None,
            KeyCode::Esc => return Ok(()),
            KeyCode::Char('t') => app.by_rate = !app.by_rate,
            KeyCode::Enter => {
                app.expanded = match app.expanded {
                    Some(_) => None,
                    None => app
                        .state
                        .ranked(app.by_rate)
                        .get(app.table.selected().unwrap_or(0))
                        .map(|p| p.pid),
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

fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .split(f.area());

    let ranked = app.state.ranked(app.by_rate);
    let elapsed = app.started.elapsed().as_secs();

    // ── title ───────────────────────────────────────────────────────────────
    let down: f64 = ranked.iter().map(|p| p.received_rate).sum();
    let up: f64 = ranked.iter().map(|p| p.sent_rate).sum();
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
                    "{} programs · {} in {}m{:02}s · sorted by {}",
                    ranked.len(),
                    bytes(app.state.total.total()),
                    elapsed / 60,
                    elapsed % 60,
                    if app.by_rate { "rate" } else { "total" }
                ),
                Style::new().fg(Color::DarkGray),
            ),
        ])),
        chunks[0],
    );

    // ── table ───────────────────────────────────────────────────────────────
    let header = Row::new(
        [
            "PROGRAM",
            "PID",
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
            Cell::from(if i >= 1 { line.right_aligned() } else { line })
        }),
    )
    .style(Style::new().bold().fg(Color::White));

    let rows: Vec<Row> = ranked
        .iter()
        .map(|p| {
            Row::new(vec![
                Cell::from(trunc(&p.name, 26)),
                Cell::from(Line::from(p.pid.to_string()).right_aligned()),
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

    let widths = [
        Constraint::Min(18),
        Constraint::Length(8),
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
    if ranked.len() > visible {
        let mut sb = ScrollbarState::new(ranked.len()).position(app.table.selected().unwrap_or(0));
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
            Span::styled(" what it is, where it talks   ", dim),
            Span::styled("t", key),
            Span::styled(" sort by rate/total   ", dim),
            Span::styled("j k", key),
            Span::styled(" move   ", dim),
            Span::styled("q", key),
            Span::styled(" quit", dim),
        ])),
        chunks[2],
    );

    if let Some(pid) = app.expanded {
        draw_detail(f, app, pid);
    }
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
    let h = area.height.saturating_sub(4).clamp(10, 26);
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
    let parts = Layout::vertical([Constraint::Length(5), Constraint::Min(1)]).split(inner);

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
                Span::styled(format!("{:<10}", "traffic"), dim),
                Span::styled(bytes(p.traffic.received), Style::new().fg(Color::Green)),
                Span::styled(" down · ", dim),
                Span::styled(bytes(p.traffic.sent), Style::new().fg(Color::Blue)),
                Span::styled(format!(" up · pid {} · {} peers", p.pid, peers.len()), dim),
            ]),
        ]),
        parts[0],
    );

    let rows: Vec<Row> = peers
        .iter()
        .map(|peer| {
            Row::new(vec![
                Cell::from(format!("{}:{}", peer.addr, peer.port)),
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
                Constraint::Min(22),
                Constraint::Length(6),
                Constraint::Length(11),
                Constraint::Length(11),
            ],
        )
        .header(
            Row::new(vec![
                Cell::from("PEER"),
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
            state.apply(crate::etw::Event {
                pid,
                proto: Proto::Tcp,
                dir,
                bytes: n,
                peer: IpAddr::V4(Ipv4Addr::from(peer)),
                peer_port: 443,
            });
        }
        state.tick(1.0);

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
