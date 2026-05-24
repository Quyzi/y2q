use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, List, ListItem, Paragraph},
};

use crate::output::fmt_bytes;

use super::app::App;
use super::pane::local::LocalEntry;
use super::pane::remote::RemoteEntry;
use super::pane::remote::RemoteLevel;
use super::state::{AdminTab, ConfirmAction, FocusedPane, InputAction, Mode};
use super::theme::*;
use super::widgets::{confirm_dialog, keybindings_bar, transfer_bar};

pub fn render(frame: &mut Frame, app: &mut App) {
    let area = frame.area();

    let transfer_height = if app.transfer_bar_visible { 5u16 } else { 0u16 };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(transfer_height),
            Constraint::Length(1),
        ])
        .split(area);

    let header_area = chunks[0];
    let pane_area = chunks[1];
    let transfer_area = chunks[2];
    let kb_area = chunks[3];

    render_header(frame, header_area);

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
        Mode::Admin(AdminTab::Metrics) => &[
            ("Tab", "tab"),
            ("↑↓/jk", "scroll"),
            ("r", "refresh"),
            ("q/Esc", "close"),
        ],
        Mode::Admin(AdminTab::Events) => &[("Tab", "tab"), ("(live)", "trace"), ("q/Esc", "close")],
        Mode::Admin(AdminTab::Rebuild) => &[
            ("Tab", "tab"),
            ("s", "start"),
            ("r", "refresh"),
            ("q/Esc", "close"),
        ],
        Mode::Admin(AdminTab::Locks) => &[
            ("Tab", "tab"),
            ("↑↓/jk", "nav"),
            ("c", "clear stale"),
            ("r", "refresh"),
            ("q/Esc", "close"),
        ],
        Mode::Input { .. } => &[("Enter", "confirm"), ("Esc", "cancel")],
        Mode::Labels { .. } => &[
            ("↑↓/jk", "nav"),
            ("a", "add"),
            ("d", "remove"),
            ("q/Esc", "close"),
        ],
        Mode::BucketConfig { .. } => &[
            ("↑↓/jk", "field"),
            ("Enter", "edit"),
            ("d", "clear"),
            ("q/Esc", "close"),
        ],
        Mode::Results { .. } => &[("↑↓/jk", "scroll"), ("q/Esc", "close")],
        _ if show_new_bucket => &[
            ("Tab", "pane"),
            ("↑↓/jk", "nav"),
            ("Enter", "open"),
            ("n", "new bucket"),
            ("g", "config"),
            ("d", "del"),
            ("L", "login"),
            ("r", "refresh"),
            ("a", "admin"),
            ("q", "quit"),
        ],
        _ => &[
            ("Tab", "pane"),
            ("↑↓/jk", "nav"),
            ("Enter", "open"),
            ("c", "copy"),
            ("m", "rename"),
            ("l", "labels"),
            ("s", "search"),
            ("f", "find"),
            ("u", "du"),
            ("T", "tree"),
            ("D", "diff"),
            ("M", "mirror"),
            ("d", "del"),
            ("L", "login"),
            ("a", "admin"),
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
                ConfirmAction::DeleteBucket { bucket, .. } => {
                    format!("Delete bucket `{bucket}` and ALL its objects?")
                }
                ConfirmAction::DeleteUser { username, .. } => {
                    format!("Delete user `{username}`?")
                }
                ConfirmAction::ClearLocks { older_than, .. } => {
                    format!("Clear stale locks older than {older_than}?")
                }
            };
            confirm_dialog::render(frame, area, &msg);
        }
        Mode::Error(e) => render_error_popup(frame, area, &e),
        Mode::Input {
            prompt,
            value,
            action,
        } => {
            let secret = matches!(
                action,
                InputAction::AddUserPassword { .. }
                    | InputAction::LoginPassword { .. }
                    | InputAction::PasswdCurrent { .. }
                    | InputAction::PasswdNew { .. }
            );
            render_input_dialog(frame, area, &prompt, &value, secret);
        }
        Mode::ObjectStat { lines, .. } => render_object_stat_popup(frame, area, &lines),
        Mode::Labels {
            bucket,
            key,
            labels,
            selected,
            ..
        } => render_labels_popup(frame, area, &bucket, &key, &labels, selected),
        Mode::BucketConfig {
            bucket,
            quota_bytes,
            default_sse,
            selected,
            ..
        } => render_bucket_config_popup(frame, area, &bucket, quota_bytes, &default_sse, selected),
        Mode::Results {
            title,
            lines,
            selected,
        } => render_results_popup(frame, area, &title, &lines, selected),
        _ => {}
    }
}

fn render_results_popup(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    lines: &[String],
    selected: usize,
) {
    let w = area.width.saturating_sub(8).max(40);
    let h = area.height.saturating_sub(6).max(6);
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
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(NEON_CYAN).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(NEON_CYAN));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    if lines.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled("(no results)", Style::default().fg(DIM_TEXT))),
            inner,
        );
        return;
    }
    let visible = inner.height as usize;
    let start = if selected >= visible {
        selected - visible + 1
    } else {
        0
    };
    let items: Vec<ListItem> = lines
        .iter()
        .enumerate()
        .skip(start)
        .take(visible)
        .map(|(i, l)| {
            let style = if i == selected {
                Style::default().fg(Color::Black).bg(NEON_PINK)
            } else {
                Style::default().fg(NORMAL_TEXT)
            };
            ListItem::new(Line::from(Span::styled(l.clone(), style)))
        })
        .collect();
    frame.render_widget(List::new(items), inner);
}

fn render_labels_popup(
    frame: &mut Frame,
    area: Rect,
    bucket: &str,
    key: &str,
    labels: &[(String, String)],
    selected: usize,
) {
    let title = format!(" Labels — {bucket}/{key} ");
    let mut lines: Vec<Line> = Vec::new();
    if labels.is_empty() {
        lines.push(Line::from(Span::styled(
            "(no labels — press 'a' to add)",
            Style::default().fg(DIM_TEXT),
        )));
    } else {
        for (i, (k, v)) in labels.iter().enumerate() {
            let style = if i == selected {
                Style::default().fg(Color::Black).bg(NEON_PINK)
            } else {
                Style::default().fg(NORMAL_TEXT)
            };
            lines.push(Line::from(Span::styled(format!("{k} = {v}"), style)));
        }
    }
    render_lines_popup(frame, area, &title, lines);
}

fn render_bucket_config_popup(
    frame: &mut Frame,
    area: Rect,
    bucket: &str,
    quota_bytes: Option<u64>,
    default_sse: &Option<String>,
    selected: usize,
) {
    let title = format!(" Config — {bucket} ");
    let quota = quota_bytes
        .map(fmt_bytes)
        .unwrap_or_else(|| "(none)".into());
    let sse = default_sse.clone().unwrap_or_else(|| "(none)".into());
    let rows = [format!("Quota:  {quota}"), format!("SSE:    {sse}")];
    let lines: Vec<Line> = rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let style = if i == selected {
                Style::default().fg(Color::Black).bg(NEON_PINK)
            } else {
                Style::default().fg(NORMAL_TEXT)
            };
            Line::from(Span::styled(r.clone(), style))
        })
        .collect();
    render_lines_popup(frame, area, &title, lines);
}

/// Render a centered popup box containing pre-built lines.
fn render_lines_popup(frame: &mut Frame, area: Rect, title: &str, lines: Vec<Line>) {
    let content_w = lines
        .iter()
        .map(|l| l.width())
        .max()
        .unwrap_or(20)
        .max(title.len()) as u16;
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
        .title(Span::styled(
            title.to_owned(),
            Style::default().fg(NEON_CYAN).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(NEON_CYAN));
    frame.render_widget(Paragraph::new(lines).block(block), popup);
}

fn render_header(frame: &mut Frame, area: Rect) {
    let spans = vec![
        Span::styled(" // ", Style::default().fg(DIM_TEXT)),
        Span::styled(
            "Y2Q",
            Style::default().fg(NEON_PINK).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" // ", Style::default().fg(DIM_TEXT)),
        Span::styled(
            "POST-QUANTUM SECURE STORAGE",
            Style::default().fg(NEON_CYAN),
        ),
        Span::styled("  //  ", Style::default().fg(DIM_TEXT)),
        Span::styled("KYBER-1024", Style::default().fg(NEON_PURPLE)),
        Span::styled(" + ", Style::default().fg(DIM_TEXT)),
        Span::styled("AES-256-GCM", Style::default().fg(NEON_GREEN)),
        Span::styled(" // ", Style::default().fg(DIM_TEXT)),
    ];
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_panes(frame: &mut Frame, area: Rect, app: &mut App) {
    let halves = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    render_local_pane(frame, halves[0], app);
    render_remote_pane(frame, halves[1], app);
}

fn focused_block(title: String, focused: bool) -> Block<'static> {
    if focused {
        Block::default()
            .title(Span::styled(
                title,
                Style::default().fg(NEON_PINK).add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_type(BorderType::Double)
            .border_style(Style::default().fg(NEON_PINK))
    } else {
        Block::default()
            .title(Span::styled(title, Style::default().fg(DIM_TEXT)))
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(DIM_BORDER))
    }
}

fn render_local_pane(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.focused == FocusedPane::Local;
    let title = format!(" LOCAL  {}  ", app.local.cwd.display());
    let block = focused_block(title, focused);
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
                LocalEntry::Dir(n) if n == ".." => ("↑ ", NEON_YELLOW),
                LocalEntry::Dir(_) => ("▶ ", NEON_PURPLE),
                LocalEntry::File { .. } => ("  ", NORMAL_TEXT),
            };
            let label = format!("{prefix}{}", entry.name());
            let style = if selected && focused {
                Style::default()
                    .fg(Color::Black)
                    .bg(NEON_PINK)
                    .add_modifier(Modifier::BOLD)
            } else if selected {
                Style::default().fg(NORMAL_TEXT).bg(DIM_BORDER)
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
    let title = format!(" REMOTE  {}  ", app.remote.title());
    let block = focused_block(title, focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.remote_throbber.active {
        let throbber = throbber_widgets_tui::Throbber::default()
            .label(" Connecting…")
            .style(Style::default().fg(NEON_CYAN));
        frame.render_stateful_widget(throbber, inner, &mut app.remote_throbber.state);
        return;
    }

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
                RemoteEntry::Back => ("↑ ", NEON_YELLOW),
                RemoteEntry::Alias(_) => ("⊞ ", NEON_ORANGE),
                RemoteEntry::Bucket(_) => ("▶ ", NEON_CYAN),
                RemoteEntry::Dir(_) => ("▶ ", NEON_PURPLE),
                RemoteEntry::Object(_) => ("  ", NORMAL_TEXT),
            };
            let label = format!("{prefix}{}", entry.display_name());
            let style = if selected && focused {
                Style::default()
                    .fg(Color::Black)
                    .bg(NEON_PINK)
                    .add_modifier(Modifier::BOLD)
            } else if selected {
                Style::default().fg(NORMAL_TEXT).bg(DIM_BORDER)
            } else {
                Style::default().fg(color)
            };
            ListItem::new(Line::from(Span::styled(label, style)))
        })
        .collect();
    if is_empty_bucket {
        items.push(ListItem::new(Line::from(Span::styled(
            "  (empty — select a local file and press 'c' to upload)",
            Style::default().fg(DIM_TEXT),
        ))));
    }
    frame.render_widget(List::new(items), inner);
}

fn render_admin(frame: &mut Frame, area: Rect, app: &App, tab: AdminTab) {
    let tab_spans: Vec<Span> = [
        ("Rebuild", AdminTab::Rebuild),
        ("Locks", AdminTab::Locks),
        ("Users", AdminTab::Users),
        ("Metrics", AdminTab::Metrics),
        ("Events", AdminTab::Events),
    ]
    .into_iter()
    .map(|(name, t)| {
        if t == tab {
            Span::styled(
                format!(" ▶ {name} ◀ "),
                Style::default()
                    .fg(Color::Black)
                    .bg(NEON_PINK)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled(format!("  {name}  "), Style::default().fg(DIM_TEXT))
        }
    })
    .collect();

    let block = Block::default()
        .title(Line::from(tab_spans))
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(NEON_CYAN));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    match tab {
        AdminTab::Rebuild => render_rebuild_tab(frame, inner, app),
        AdminTab::Locks => render_locks_tab(frame, inner, app),
        AdminTab::Users => render_users_tab(frame, inner, app),
        AdminTab::Metrics => render_metrics_tab(frame, inner, app),
        AdminTab::Events => render_events_tab(frame, inner, app),
    }
}

fn render_metrics_tab(frame: &mut Frame, area: Rect, app: &App) {
    let m = &app.metrics_view;
    if let Some(ref e) = m.error {
        frame.render_widget(
            Paragraph::new(Span::styled(
                format!("Metrics unavailable: {e}"),
                Style::default().fg(ERROR_RED),
            )),
            area,
        );
        return;
    }
    if m.loading && m.lines.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "Loading metrics…",
                Style::default().fg(NEON_CYAN),
            )),
            area,
        );
        return;
    }
    if m.lines.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "No metrics. Press 'r' to refresh.",
                Style::default().fg(DIM_TEXT),
            )),
            area,
        );
        return;
    }
    let visible = area.height as usize;
    let items: Vec<ListItem> = m
        .lines
        .iter()
        .skip(m.scroll)
        .take(visible)
        .map(|l| {
            // Split "metric_name{labels} value" → name dim, value bright.
            let (name, value) = l.rsplit_once(' ').unwrap_or((l.as_str(), ""));
            ListItem::new(Line::from(vec![
                Span::styled(name.to_owned(), Style::default().fg(NEON_CYAN)),
                Span::raw("  "),
                Span::styled(value.to_owned(), Style::default().fg(NEON_GREEN)),
            ]))
        })
        .collect();
    frame.render_widget(List::new(items), area);
}

fn render_events_tab(frame: &mut Frame, area: Rect, app: &App) {
    let v = &app.events_view;
    if let Some(ref e) = v.error {
        frame.render_widget(
            Paragraph::new(Span::styled(
                format!("Trace stream ended: {e}"),
                Style::default().fg(ERROR_RED),
            )),
            area,
        );
        return;
    }
    if v.events.is_empty() {
        let msg = if v.streaming {
            "Streaming… waiting for events."
        } else {
            "Not streaming."
        };
        frame.render_widget(
            Paragraph::new(Span::styled(msg, Style::default().fg(DIM_TEXT))),
            area,
        );
        return;
    }
    let visible = area.height as usize;
    // Newest at the bottom: show the last `visible` events.
    let skip = v.events.len().saturating_sub(visible);
    let items: Vec<ListItem> = v
        .events
        .iter()
        .skip(skip)
        .map(|e| {
            let color = match e.status {
                200..=299 => NEON_GREEN,
                300..=399 => NEON_CYAN,
                400..=499 => NEON_YELLOW,
                _ => ERROR_RED,
            };
            let line = format!(
                "{:<6} {:<48} {:>3}  {:>7.1}ms",
                e.method, e.path, e.status, e.latency_ms
            );
            ListItem::new(Line::from(Span::styled(line, Style::default().fg(color))))
        })
        .collect();
    frame.render_widget(List::new(items), area);
}

fn render_rebuild_tab(frame: &mut Frame, area: Rect, app: &App) {
    let s = &app.rebuild;
    let lines = if s.state.is_empty() {
        vec![Line::from(Span::styled(
            "No rebuild in progress.",
            Style::default().fg(DIM_TEXT),
        ))]
    } else {
        let mut v = vec![Line::from(Span::styled(
            format!("State: {}", s.state),
            Style::default().fg(NEON_CYAN),
        ))];
        if let Some(pct) = s.percent {
            v.push(Line::from(Span::styled(
                format!("Progress: {pct}%"),
                Style::default().fg(NEON_GREEN),
            )));
        }
        if let Some(ref reason) = s.reason {
            v.push(Line::from(Span::styled(
                format!("Reason: {reason}"),
                Style::default().fg(ERROR_RED),
            )));
        }
        v
    };
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_locks_tab(frame: &mut Frame, area: Rect, app: &App) {
    if app.locks.loading {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "Loading locks…",
                Style::default().fg(NEON_CYAN),
            )),
            area,
        );
        return;
    }
    if app.locks.locks.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "No stale locks found.",
                Style::default().fg(DIM_TEXT),
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
                Style::default().fg(Color::Black).bg(NEON_PINK)
            } else {
                Style::default().fg(NORMAL_TEXT)
            };
            ListItem::new(Line::from(Span::styled(text, style)))
        })
        .collect();
    frame.render_widget(List::new(items), area);
}

fn render_users_tab(frame: &mut Frame, area: Rect, app: &App) {
    if app.users_view.loading {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "Loading users…",
                Style::default().fg(NEON_CYAN),
            )),
            area,
        );
        return;
    }
    if app.users_view.users.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled("No users.", Style::default().fg(DIM_TEXT))),
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
                Style::default().fg(Color::Black).bg(NEON_PINK)
            } else {
                Style::default().fg(NORMAL_TEXT)
            };
            ListItem::new(Line::from(Span::styled(user.username.clone(), style)))
        })
        .collect();
    frame.render_widget(List::new(items), area);
}

fn render_input_dialog(frame: &mut Frame, area: Rect, prompt: &str, value: &str, secret: bool) {
    let w = 54u16.min(area.width.saturating_sub(4));
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
        .title(Span::styled(
            format!(" ▶ {prompt} "),
            Style::default().fg(NEON_CYAN).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(NEON_CYAN));
    let shown = if secret {
        "*".repeat(value.chars().count())
    } else {
        value.to_owned()
    };
    let cursor_line = format!("{shown}_");
    let text = vec![
        Line::from(Span::styled(cursor_line, Style::default().fg(NEON_GREEN))),
        Line::from(""),
        Line::from(Span::styled(
            "Enter: confirm   Esc: cancel",
            Style::default().fg(DIM_TEXT),
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
        .title(Span::styled(
            " ◆ OBJECT INFO ◆ ",
            Style::default()
                .fg(NEON_PURPLE)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(NEON_PURPLE));
    let mut text: Vec<Line> = lines
        .iter()
        .map(|l| Line::from(Span::styled(l.as_str(), Style::default().fg(NORMAL_TEXT))))
        .collect();
    text.push(Line::from(""));
    text.push(Line::from(Span::styled(
        "[any key] dismiss",
        Style::default().fg(DIM_TEXT),
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
        .title(Span::styled(
            " ✗ ERROR ",
            Style::default().fg(ERROR_RED).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(ERROR_RED));
    let text = vec![
        Line::from(Span::styled(message, Style::default().fg(NEON_YELLOW))),
        Line::from(""),
        Line::from(Span::styled(
            "[any key] dismiss",
            Style::default().fg(DIM_TEXT),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(block)
            .alignment(Alignment::Center),
        popup,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CliConfig;
    use crate::tui::widgets::transfer_bar::{TransferEntry, TransferStatus};
    use ratatui::{Terminal, backend::TestBackend};
    use std::time::Duration;

    fn app() -> App {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        App::new(CliConfig::default(), tx)
    }

    fn draw(app: &mut App) {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, app)).unwrap();
    }

    #[test]
    fn renders_every_mode() {
        // Browse, both panes focused.
        let mut a = app();
        draw(&mut a);
        a.focused = FocusedPane::Remote;
        draw(&mut a);

        // Each admin tab.
        for tab in [
            AdminTab::Rebuild,
            AdminTab::Locks,
            AdminTab::Users,
            AdminTab::Metrics,
            AdminTab::Events,
        ] {
            a.mode = Mode::Admin(tab);
            draw(&mut a);
        }

        // Confirm / Input / Error / ObjectStat popups.
        a.mode = Mode::Confirm(ConfirmAction::DeleteRemote {
            alias: "x".into(),
            bucket: "b".into(),
            key: "k".into(),
        });
        draw(&mut a);
        a.mode = Mode::Input {
            prompt: "Name:".into(),
            value: "typed".into(),
            action: InputAction::CreateBucket { alias: "x".into() },
        };
        draw(&mut a);
        a.mode = Mode::Error("something broke".into());
        draw(&mut a);
        a.mode = Mode::ObjectStat {
            path: "a/b/c".into(),
            lines: vec!["Size: 10".into(), "KEM: ml-kem".into()],
        };
        draw(&mut a);
    }

    #[test]
    fn renders_transfer_bar_states() {
        let mut a = app();
        a.transfer_bar_visible = true;
        let mut running = TransferEntry::new(1, "up".into(), Some(100));
        running.status = TransferStatus::Running;
        running.bytes_done = 40;
        let mut done = TransferEntry::new(2, "done".into(), Some(100));
        done.status = TransferStatus::Done {
            bytes: 100,
            elapsed: Duration::from_secs(1),
            avg_bps: 100,
        };
        let failed = {
            let mut e = TransferEntry::new(3, "bad".into(), None);
            e.status = TransferStatus::Failed("nope".into());
            e
        };
        a.transfers.extend([running, done, failed]);
        draw(&mut a);
    }
}
