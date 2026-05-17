use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph},
};

use super::app::App;
use super::pane::local::LocalEntry;
use super::pane::remote::RemoteEntry;
use super::pane::remote::RemoteLevel;
use super::state::{AdminTab, ConfirmAction, FocusedPane, Mode};
use super::widgets::{confirm_dialog, keybindings_bar, transfer_bar};

pub fn render(frame: &mut Frame, app: &mut App) {
    let area = frame.area();

    let transfer_height = if app.transfer_bar_visible { 5u16 } else { 0u16 };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(transfer_height),
            Constraint::Length(1),
        ])
        .split(area);

    let pane_area = chunks[0];
    let transfer_area = chunks[1];
    let kb_area = chunks[2];

    match app.mode.clone() {
        Mode::Admin(tab) => render_admin(frame, pane_area, app, tab),
        _ => render_panes(frame, pane_area, app),
    }

    if app.transfer_bar_visible && transfer_height > 0 {
        let entries: Vec<_> = app.transfers.iter().cloned().collect();
        transfer_bar::render(frame, transfer_area, &entries);
    }

    let show_new_bucket = matches!(&app.mode, Mode::Browse | Mode::Input { .. })
        && app.focused == FocusedPane::Remote
        && matches!(app.remote.level, RemoteLevel::Buckets { .. });

    let bindings: &[(&str, &str)] = match &app.mode {
        Mode::Admin(AdminTab::Users) => &[
            ("Tab", "tab"),
            ("↑↓/jk", "nav"),
            ("n", "add user"),
            ("d", "del"),
            ("q/Esc", "close"),
        ],
        Mode::Admin(_) => &[
            ("Tab", "tab"),
            ("↑↓/jk", "nav"),
            ("d", "delete"),
            ("q/Esc", "close"),
        ],
        Mode::Input { .. } => &[("Enter", "confirm"), ("Esc", "cancel")],
        _ if show_new_bucket => &[
            ("Tab", "pane"),
            ("↑↓/jk", "nav"),
            ("Enter", "open"),
            ("n", "new bucket"),
            ("c", "copy"),
            ("d", "del"),
            ("r", "refresh"),
            ("a", "admin"),
            ("t", "transfers"),
            ("q", "quit"),
        ],
        _ => &[
            ("Tab", "pane"),
            ("↑↓/jk", "nav"),
            ("Enter", "open"),
            ("c", "copy"),
            ("d", "del"),
            ("r", "refresh"),
            ("a", "admin"),
            ("t", "transfers"),
            ("q", "quit"),
        ],
    };
    keybindings_bar::render(frame, kb_area, bindings);

    // Modal overlays — rendered last so they appear on top
    match app.mode.clone() {
        Mode::Confirm(action) => {
            let msg = match action {
                ConfirmAction::DeleteRemote { bucket, key, .. } => {
                    format!("Delete {bucket}/{key}?")
                }
                ConfirmAction::DeleteUser { username, .. } => {
                    format!("Delete user `{username}`?")
                }
            };
            confirm_dialog::render(frame, area, &msg);
        }
        Mode::Error(e) => render_error_popup(frame, area, &e),
        Mode::Input { prompt, value, .. } => render_input_dialog(frame, area, &prompt, &value),
        Mode::ObjectStat { lines, .. } => render_object_stat_popup(frame, area, &lines),
        _ => {}
    }
}

fn render_panes(frame: &mut Frame, area: Rect, app: &mut App) {
    let halves = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    render_local_pane(frame, halves[0], app);
    render_remote_pane(frame, halves[1], app);
}

fn render_local_pane(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.focused == FocusedPane::Local;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let title = format!(" Local — {} ", app.local.cwd.display());
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(border_style);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let visible = inner.height as usize;
    let items: Vec<ListItem> = app
        .local
        .entries
        .iter()
        .enumerate()
        .skip(app.local.scroll)
        .take(visible)
        .map(|(idx, entry)| {
            let selected = idx == app.local.selected;
            let (prefix, color) = match entry {
                LocalEntry::Dir(n) if n == ".." => ("↑ ", Color::Yellow),
                LocalEntry::Dir(_) => ("▶ ", Color::Blue),
                LocalEntry::File { .. } => ("  ", Color::White),
            };
            let label = format!("{prefix}{}", entry.name());
            let style = if selected && focused {
                Style::default()
                    .fg(Color::White)
                    .bg(Color::Blue)
                    .add_modifier(Modifier::BOLD)
            } else if selected {
                Style::default().fg(Color::White).bg(Color::DarkGray)
            } else {
                Style::default().fg(color)
            };
            ListItem::new(Line::from(Span::styled(label, style)))
        })
        .collect();
    frame.render_widget(List::new(items), inner);
}

fn render_remote_pane(frame: &mut Frame, area: Rect, app: &mut App) {
    let focused = app.focused == FocusedPane::Remote;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let title = format!(" {} ", app.remote.title());
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(border_style);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.remote_throbber.active {
        let throbber = throbber_widgets_tui::Throbber::default()
            .label(" Loading…")
            .style(Style::default().fg(Color::Cyan));
        frame.render_stateful_widget(throbber, inner, &mut app.remote_throbber.state);
        return;
    }

    // Show a hint when navigated into a new/empty bucket (only Back entry present).
    let is_empty_bucket = matches!(app.remote.level, RemoteLevel::Objects { .. })
        && app.remote.entries.len() == 1
        && matches!(app.remote.entries.first(), Some(RemoteEntry::Back));

    let visible = inner.height as usize;
    let mut items: Vec<ListItem> = app
        .remote
        .entries
        .iter()
        .enumerate()
        .skip(app.remote.scroll)
        .take(visible)
        .map(|(idx, entry)| {
            let selected = idx == app.remote.selected;
            let (prefix, color) = match entry {
                RemoteEntry::Back => ("↑ ", Color::Yellow),
                RemoteEntry::Alias(_) => ("⊞ ", Color::Magenta),
                RemoteEntry::Bucket(_) => ("▶ ", Color::Blue),
                RemoteEntry::Dir(_) => ("▶ ", Color::Cyan),
                RemoteEntry::Object(_) => ("  ", Color::White),
            };
            let label = format!("{prefix}{}", entry.display_name());
            let style = if selected && focused {
                Style::default()
                    .fg(Color::White)
                    .bg(Color::Blue)
                    .add_modifier(Modifier::BOLD)
            } else if selected {
                Style::default().fg(Color::White).bg(Color::DarkGray)
            } else {
                Style::default().fg(color)
            };
            ListItem::new(Line::from(Span::styled(label, style)))
        })
        .collect();
    if is_empty_bucket {
        items.push(ListItem::new(Line::from(Span::styled(
            "  (empty — select a local file and press 'c' to upload)",
            Style::default().fg(Color::DarkGray),
        ))));
    }
    frame.render_widget(List::new(items), inner);
}

fn render_admin(frame: &mut Frame, area: Rect, app: &App, tab: AdminTab) {
    let tab_spans: Vec<Span> = [
        ("Rebuild", AdminTab::Rebuild),
        ("Locks", AdminTab::Locks),
        ("Users", AdminTab::Users),
    ]
    .into_iter()
    .map(|(name, t)| {
        if t == tab {
            Span::styled(
                format!(" [{name}] "),
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled(format!("  {name}  "), Style::default().fg(Color::DarkGray))
        }
    })
    .collect();

    let block = Block::default()
        .title(Line::from(tab_spans))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    match tab {
        AdminTab::Rebuild => render_rebuild_tab(frame, inner, app),
        AdminTab::Locks => render_locks_tab(frame, inner, app),
        AdminTab::Users => render_users_tab(frame, inner, app),
    }
}

fn render_rebuild_tab(frame: &mut Frame, area: Rect, app: &App) {
    let s = &app.rebuild;
    let lines = if s.state.is_empty() {
        vec![Line::from(Span::styled(
            "No rebuild in progress.",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        let mut v = vec![Line::from(Span::styled(
            format!("State: {}", s.state),
            Style::default().fg(Color::Cyan),
        ))];
        if let Some(pct) = s.percent {
            v.push(Line::from(format!("Progress: {pct}%")));
        }
        if let Some(ref reason) = s.reason {
            v.push(Line::from(Span::styled(
                format!("Reason: {reason}"),
                Style::default().fg(Color::Red),
            )));
        }
        v
    };
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_locks_tab(frame: &mut Frame, area: Rect, app: &App) {
    if app.locks.loading {
        frame.render_widget(Paragraph::new("Loading locks…"), area);
        return;
    }
    if app.locks.locks.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "No stale locks found.",
                Style::default().fg(Color::DarkGray),
            )),
            area,
        );
        return;
    }
    let items: Vec<ListItem> = app
        .locks
        .locks
        .iter()
        .enumerate()
        .map(|(i, lock)| {
            let sel = i == app.locks.selected;
            let short_uuid = &lock.uuid[..8.min(lock.uuid.len())];
            let text = format!(
                "{}/{}… — {}s old",
                lock.bucket, short_uuid, lock.age_seconds
            );
            let style = if sel {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(Span::styled(text, style)))
        })
        .collect();
    frame.render_widget(List::new(items), area);
}

fn render_users_tab(frame: &mut Frame, area: Rect, app: &App) {
    if app.users_view.loading {
        frame.render_widget(Paragraph::new("Loading users…"), area);
        return;
    }
    if app.users_view.users.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "No users.",
                Style::default().fg(Color::DarkGray),
            )),
            area,
        );
        return;
    }
    let items: Vec<ListItem> = app
        .users_view
        .users
        .iter()
        .enumerate()
        .map(|(i, user)| {
            let sel = i == app.users_view.selected;
            let style = if sel {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(Span::styled(user.username.clone(), style)))
        })
        .collect();
    frame.render_widget(List::new(items), area);
}

fn render_input_dialog(frame: &mut Frame, area: Rect, prompt: &str, value: &str) {
    let w = 50u16.min(area.width.saturating_sub(4));
    let h = 5u16;
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let popup = Rect {
        x,
        y,
        width: w,
        height: h,
    };
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .title(format!(" {prompt} "))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let cursor_line = format!("{value}_");
    let text = vec![
        Line::from(Span::styled(cursor_line, Style::default().fg(Color::White))),
        Line::from(""),
        Line::from(Span::styled(
            "Enter: confirm   Esc: cancel",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text).block(block).alignment(Alignment::Left),
        popup,
    );
}

fn render_object_stat_popup(frame: &mut Frame, area: Rect, lines: &[String]) {
    let content_w = lines.iter().map(|l| l.len()).max().unwrap_or(20) as u16;
    let w = (content_w + 4).max(40).min(area.width.saturating_sub(4));
    let h = ((lines.len() as u16) + 4).min(area.height.saturating_sub(4));
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let popup = Rect {
        x,
        y,
        width: w,
        height: h,
    };
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .title(" Object Info ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let mut text: Vec<Line> = lines
        .iter()
        .map(|l| Line::from(Span::raw(l.as_str())))
        .collect();
    text.push(Line::from(""));
    text.push(Line::from(Span::styled(
        "[any key] dismiss",
        Style::default().fg(Color::DarkGray),
    )));
    frame.render_widget(Paragraph::new(text).block(block), popup);
}

fn render_error_popup(frame: &mut Frame, area: Rect, message: &str) {
    let w = (message.len() as u16 + 6)
        .max(30)
        .min(area.width.saturating_sub(4));
    let h = 5u16;
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let popup = Rect {
        x,
        y,
        width: w,
        height: h,
    };
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .title(" Error ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red));
    let text = vec![
        Line::from(Span::raw(message)),
        Line::from(""),
        Line::from(Span::styled(
            "[any key] dismiss",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(block)
            .alignment(Alignment::Center),
        popup,
    );
}
