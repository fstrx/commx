use commx_core::ipc::ChatLine;
use commx_core::room::KillMode;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, Secret, LOCAL};

const ACCENT: Color = Color::Rgb(120, 220, 160);
const DIM: Color = Color::DarkGray;
const DANGER: Color = Color::Rgb(255, 95, 95);
const NAME_COLORS: [Color; 6] = [
    Color::Rgb(130, 170, 255),
    Color::Rgb(255, 180, 100),
    Color::Rgb(200, 140, 255),
    Color::Rgb(255, 130, 180),
    Color::Rgb(120, 210, 230),
    Color::Rgb(230, 220, 110),
];

fn name_color(name: &str) -> Color {
    let h = name.bytes().fold(5381u32, |h, b| h.wrapping_mul(33) ^ b as u32);
    NAME_COLORS[h as usize % NAME_COLORS.len()]
}

/// Local wall-clock HH:MM for a minute-resolution unix timestamp.
fn hhmm(ts_min: u64) -> String {
    let t = (ts_min * 60) as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
        return "--:--".into();
    }
    format!("{:02}:{:02}", tm.tm_hour, tm.tm_min)
}

pub fn draw(f: &mut Frame, app: &App) {
    let [main, input, status] =
        Layout::vertical([Constraint::Min(5), Constraint::Length(3), Constraint::Length(1)]).areas(f.area());
    let [side, chat] = Layout::horizontal([Constraint::Length(28), Constraint::Min(20)]).areas(main);
    sidebar(f, app, side);
    if app.sel == 0 {
        home(f, app, chat);
    } else {
        room(f, app, chat);
    }
    input_box(f, app, input);
    status_bar(f, app, status);
}

fn panel(title: impl Into<Line<'static>>, focused: bool) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(if focused { ACCENT } else { DIM }))
        .title(title)
}

fn sidebar(f: &mut Frame, app: &App, area: Rect) {
    let mut items = vec![ListItem::new(Line::from(vec![Span::raw(" ~ "), Span::raw("home")]))];
    for r in &app.rooms {
        let glyph = if r.is_dm { "@" } else { "#" };
        let mode = match r.kill_mode {
            KillMode::AnyMember => Span::styled(" ☢", Style::default().fg(DANGER)),
            KillMode::HostOnly => Span::styled(" ◆", Style::default().fg(DIM)),
        };
        let unread = if app.unread.contains(&r.room_id) {
            Span::styled(" •", Style::default().fg(ACCENT).bold())
        } else {
            Span::raw("")
        };
        let host = if r.is_host { Span::styled(" host", Style::default().fg(DIM)) } else { Span::raw("") };
        items.push(ListItem::new(Line::from(vec![
            Span::raw(format!(" {glyph} ")),
            Span::raw(r.name.clone()),
            mode,
            host,
            unread,
        ])));
    }
    let list = List::new(items)
        .block(panel(" commx ", false))
        .highlight_style(Style::default().bg(Color::Rgb(40, 50, 45)).fg(ACCENT).add_modifier(Modifier::BOLD));
    let mut state = ListState::default().with_selected(Some(app.sel));
    f.render_stateful_widget(list, area, &mut state);
}

fn home(f: &mut Frame, app: &App, area: Rect) {
    let lines: Vec<Line> = app
        .home
        .iter()
        .map(|(t, err)| {
            if *err {
                Line::styled(t.clone(), Style::default().fg(DANGER))
            } else if t.starts_with("cx1:") {
                Line::styled(t.clone(), Style::default().fg(ACCENT).bold())
            } else {
                Line::raw(t.clone())
            }
        })
        .collect();
    scrolled(f, lines, panel(" ~ home ", true), area, app.scroll);
}

fn room(f: &mut Frame, app: &App, area: Rect) {
    let Some(r) = app.current() else { return };
    let mode_style = match r.kill_mode {
        KillMode::AnyMember => Style::default().fg(DANGER),
        KillMode::HostOnly => Style::default().fg(DIM),
    };
    let title = Line::from(vec![
        Span::raw(format!(" {}{} ", if r.is_dm { "@" } else { "#" }, r.name)),
        Span::styled(format!("kill:{} {}s ", r.kill_mode.label(), r.grace_secs), mode_style),
        Span::styled(format!("· {} ", r.members.join(", ")), Style::default().fg(DIM)),
    ]);
    // Decrypt only what can be on screen; it's dropped (and wiped) after drawing.
    let rows = area.height.saturating_sub(2) as usize;
    let visible: Vec<ChatLine> = app.lines.get(&r.room_id).map(|l| l.tail(rows, app.scroll)).unwrap_or_default();
    let lines: Vec<Line> = visible.iter().map(chat_line).collect();
    scrolled(f, lines, panel(title, true), area, 0);
}

fn chat_line(l: &ChatLine) -> Line<'static> {
    let ts = Span::styled(format!("{} ", hhmm(l.ts_min)), Style::default().fg(DIM));
    if l.from == LOCAL {
        let style = if l.text.starts_with("cx1:") {
            Style::default().fg(ACCENT).bold()
        } else {
            Style::default().fg(DIM).italic()
        };
        return Line::from(vec![ts, Span::styled(l.text.clone(), style)]);
    }
    if l.system {
        return Line::from(vec![ts, Span::styled(format!("* {}", l.text), Style::default().fg(Color::Yellow).italic())]);
    }
    let name_style = if l.mine { Style::default().fg(ACCENT).bold() } else { Style::default().fg(name_color(&l.from)).bold() };
    Line::from(vec![ts, Span::styled(format!("{} ", l.from), name_style), Span::raw(l.text.clone())])
}

/// Bottom-anchored text with wrap; `scroll` counts lines up from the bottom.
fn scrolled(f: &mut Frame, lines: Vec<Line<'static>>, block: Block<'static>, area: Rect, scroll: usize) {
    let inner_w = area.width.saturating_sub(2).max(1) as usize;
    let inner_h = area.height.saturating_sub(2) as usize;
    let end = lines.len().saturating_sub(scroll);
    let mut start = end;
    let mut used = 0;
    while start > 0 {
        let h = lines[start - 1].width().max(1).div_ceil(inner_w);
        if used + h > inner_h {
            break;
        }
        used += h;
        start -= 1;
    }
    let p = Paragraph::new(lines[start..end].to_vec()).block(block).wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

fn input_box(f: &mut Frame, app: &App, area: Rect) {
    let (title, shown) = match &app.secret {
        Some(Secret::Unlock) => (" passphrase to unlock (hidden) ".to_string(), "•".repeat(app.input.chars().count())),
        Some(Secret::NewAlias(n)) => (
            format!(" passphrase for '{n}' (8+ chars, hidden) "),
            "•".repeat(app.input.chars().count()),
        ),
        None => {
            let t = match app.current() {
                Some(r) => format!(" message {}{} ", if r.is_dm { "@" } else { "#" }, r.name),
                None => " command ".to_string(),
            };
            (t, app.input.clone())
        }
    };
    let width = area.width.saturating_sub(3) as usize;
    let chars: Vec<char> = shown.chars().collect();
    let visible: String = chars[chars.len().saturating_sub(width)..].iter().collect();
    let cursor_x = area.x + 1 + visible.chars().count() as u16;
    f.render_widget(Paragraph::new(visible).block(panel(title, true)), area);
    f.set_cursor_position((cursor_x, area.y + 1));
}

fn status_bar(f: &mut Frame, app: &App, area: Rect) {
    let s = &app.status;
    let mut spans = vec![
        Span::styled(
            format!(" {} ", s.alias.as_deref().unwrap_or("locked")),
            Style::default().bg(ACCENT).fg(Color::Black).bold(),
        ),
        Span::styled(format!(" {} ", s.fingerprint.as_deref().unwrap_or("-")), Style::default().fg(DIM)),
        Span::styled(format!("· {} · {} ", s.listen, s.power), Style::default().fg(DIM)),
    ];
    if let Some(n) = &app.notice {
        spans.push(Span::styled(
            format!("· {}", n.text),
            Style::default().fg(if n.error { DANGER } else { ACCENT }),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}
