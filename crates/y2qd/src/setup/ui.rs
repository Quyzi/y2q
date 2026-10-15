//! Rendering. Frames are built with `Buffer::set_string` over `&str` slices and
//! every dynamic string passes through `sanitize` first, so nothing from the
//! filesystem, the environment or a probe can move the cursor or reorder text.

use ratatui::Frame;
use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier, Style};

use super::apply::{Plan, UnitState};
use super::sanitize;
use super::scan::{Group, Level};
use super::validate::{Sev, Step};
use super::wizard::{FieldKind, ListEdit, Wizard};

// Colours copied from y2q-cli's TUI theme (no shared crate by design).
const NEON_CYAN: Color = Color::Rgb(0, 255, 255);
const NEON_GREEN: Color = Color::Rgb(57, 255, 20);
const NEON_YELLOW: Color = Color::Rgb(255, 215, 0);
const NEON_PINK: Color = Color::Rgb(255, 20, 147);
const ERROR_RED: Color = Color::Rgb(255, 50, 50);
const DIM_TEXT: Color = Color::Rgb(90, 90, 130);
const NORMAL_TEXT: Color = Color::Rgb(200, 210, 255);

pub const MIN_COLS: u16 = 80;
pub const MIN_ROWS: u16 = 24;

fn normal() -> Style {
    Style::default().fg(NORMAL_TEXT)
}
fn dim() -> Style {
    Style::default().fg(DIM_TEXT)
}
fn bold(c: Color) -> Style {
    Style::default().fg(c).add_modifier(Modifier::BOLD)
}

struct Canvas<'a> {
    buf: &'a mut Buffer,
    w: u16,
}

impl Canvas<'_> {
    /// Sanitised, truncated to the width. Returns the columns written.
    fn put(&mut self, x: u16, y: u16, text: &str, style: Style) -> u16 {
        if x >= self.w {
            return 0;
        }
        let clean = sanitize(text);
        let max = usize::from(self.w - x);
        let shown: String = clean.chars().take(max).collect();
        let n = shown.chars().count() as u16;
        self.buf.set_string(x, y, &shown, style);
        n
    }
}

/// One body line: text, style and (for forms) the field it belongs to.
struct Line {
    text: String,
    style: Style,
    field: Option<usize>,
}

fn line(text: impl Into<String>, style: Style) -> Line {
    Line {
        text: text.into(),
        style,
        field: None,
    }
}

/// Word-wrap `text` to `width` columns.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    for para in text.split('\n') {
        let mut cur = String::new();
        for word in para.split_whitespace() {
            let would = cur.chars().count() + usize::from(!cur.is_empty()) + word.chars().count();
            if !cur.is_empty() && would > width {
                out.push(std::mem::take(&mut cur));
            }
            if !cur.is_empty() {
                cur.push(' ');
            }
            cur.push_str(word);
        }
        out.push(cur);
    }
    out
}

fn push_wrapped(lines: &mut Vec<Line>, indent: &str, text: &str, style: Style, width: usize) {
    let w = width.saturating_sub(indent.chars().count()).max(10);
    for l in wrap(text, w) {
        lines.push(line(format!("{indent}{l}"), style));
    }
}

pub fn draw(f: &mut Frame, wiz: &Wizard) {
    let area = f.area();
    let (w, h) = (area.width, area.height);
    let mut c = Canvas {
        buf: f.buffer_mut(),
        w,
    };
    if w < MIN_COLS || h < MIN_ROWS {
        c.put(
            0,
            0,
            &format!("terminal too small (need {MIN_COLS}x{MIN_ROWS})"),
            bold(ERROR_RED),
        );
        return;
    }
    let total = 10u16;
    let n = wiz.step as u16 + 1;
    c.put(
        1,
        0,
        &format!("y2qd setup - {}", wiz.step.title()),
        bold(NEON_CYAN),
    );
    c.put(w.saturating_sub(12), 0, &format!("step {n}/{total}"), dim());
    c.put(0, 1, &"-".repeat(usize::from(w)), dim());

    let body_top = 2u16;
    let body_h = usize::from(h - 5);
    let width = usize::from(w.saturating_sub(4));

    let (lines, cursor_line) = match wiz.step {
        Step::Scan => (scan_lines(wiz, width), wiz.scroll),
        Step::ExistingWarning => (existing_lines(wiz, width), 0),
        Step::Review => review_lines(wiz, width),
        _ => form_lines(wiz, width),
    };
    let offset = if wiz.step == Step::Scan || wiz.step == Step::Review {
        if wiz.step == Step::Scan {
            wiz.scroll.min(lines.len().saturating_sub(1))
        } else {
            wiz.review_scroll.min(lines.len().saturating_sub(1))
        }
    } else {
        (cursor_line + 3).saturating_sub(body_h)
    };
    for (i, l) in lines.iter().skip(offset).take(body_h).enumerate() {
        let selected = l.field.is_some_and(|fi| fi == wiz.form.cursor)
            && wiz.step != Step::Review
            && wiz.step != Step::Scan;
        let mut style = l.style;
        let mut prefix = "  ";
        if selected {
            prefix = "> ";
            style = style.add_modifier(Modifier::BOLD);
        }
        let y = body_top + i as u16;
        c.put(0, y, prefix, bold(NEON_PINK));
        c.put(2, y, &l.text, style);
    }

    // Footer.
    let msg_y = h - 2;
    if let Some(b) = &wiz.busy {
        c.put(1, msg_y, b, bold(NEON_YELLOW));
    } else if let Some(fl) = &wiz.flash {
        c.put(1, msg_y, fl, bold(NEON_YELLOW));
    }
    let help = if wiz.quit_prompt {
        "Quit setup? Nothing has been changed.   y = quit   n = stay"
    } else {
        match wiz.step {
            Step::Scan => "Up/Down scroll   Tab/Enter continue   Esc quit   Ctrl-C quit",
            Step::ExistingWarning if wiz.parse_failed => {
                "s start from defaults (original is backed up)   q quit"
            }
            Step::ExistingWarning => "Enter/Tab continue   Esc quit",
            Step::Review => "Up/Down choose   Enter select   PgUp/PgDn scroll   Esc back",
            Step::Authority => {
                "Up/Down field   Enter edit   Tab next   Esc back   c check now   a/d add/delete row"
            }
            _ => "Up/Down field   Enter edit/toggle   Left/Right cycle   Tab next   Esc back",
        }
    };
    c.put(
        1,
        h - 1,
        help,
        if wiz.quit_prompt {
            bold(NEON_YELLOW)
        } else {
            dim()
        },
    );
}

fn scan_lines(wiz: &Wizard, width: usize) -> Vec<Line> {
    let mut lines = Vec::new();
    for group in [Group::Hardware, Group::Software, Group::Existing] {
        let rows: Vec<_> = wiz.findings.iter().filter(|f| f.group == group).collect();
        if rows.is_empty() {
            continue;
        }
        lines.push(line(group.title(), bold(NEON_CYAN)));
        for f in rows {
            let colour = match f.level {
                Level::Ok => NEON_GREEN,
                Level::Info => NORMAL_TEXT,
                Level::Warn => NEON_YELLOW,
                Level::Fail => ERROR_RED,
            };
            lines.push(line(
                format!("  {:<4} {}", f.level.glyph(), f.title),
                Style::default().fg(colour),
            ));
            if !f.detail.is_empty() {
                push_wrapped(&mut lines, "         ", &f.detail, dim(), width);
            }
        }
    }
    lines
}

fn existing_lines(wiz: &Wizard, width: usize) -> Vec<Line> {
    let mut lines = vec![
        line(
            "Warning: an existing installation was found",
            bold(NEON_YELLOW),
        ),
        line("", normal()),
    ];
    let e = &wiz.existing;
    let mut found = Vec::new();
    if e.config_exists {
        found.push(format!("config file {}", wiz.a.config_path.display()));
    }
    if e.keystore_json {
        found.push("keystore.json".to_owned());
    }
    if e.devices_json {
        found.push("devices.json (device registry)".to_owned());
    }
    if e.users_redb {
        found.push("users.redb".to_owned());
    }
    if e.storage_nonempty {
        found.push("a non-empty data directory".to_owned());
    }
    for f in found {
        lines.push(line(format!("  - {f}"), normal()));
    }
    lines.push(line("", normal()));
    if let Err(msg) = &e.config_parse {
        push_wrapped(
            &mut lines,
            "",
            "The existing config file does not parse:",
            bold(ERROR_RED),
            width,
        );
        push_wrapped(&mut lines, "  ", msg, Style::default().fg(ERROR_RED), width);
        push_wrapped(
            &mut lines,
            "",
            "Press s to start from defaults; the original file is copied to a .bak- file before anything is written.",
            normal(),
            width,
        );
    } else {
        push_wrapped(
            &mut lines,
            "",
            "You can continue. Existing values become the defaults and everything setup does not manage is preserved. A backup of the config is made before it is rewritten. Setup never rotates a node key and never edits an existing device registry.",
            normal(),
            width,
        );
    }
    lines
}

fn form_lines(wiz: &Wizard, width: usize) -> (Vec<Line>, usize) {
    let mut lines: Vec<Line> = Vec::new();
    let mut cursor_line = 0;
    if wiz.step == Step::Paths && wiz.orphan_risk() {
        push_wrapped(
            &mut lines,
            "",
            "DATA RISK: setup does not move data. Existing data is not under this keystore and may become unreadable.",
            bold(ERROR_RED),
            width,
        );
        lines.push(line("", normal()));
    }
    for (i, field) in wiz.form.fields.iter().enumerate() {
        if i == wiz.form.cursor {
            cursor_line = lines.len();
        }
        let shown = match (&field.kind, &wiz.form.editing) {
            (_, Some(buf)) if i == wiz.form.cursor => format!("{buf}_"),
            (FieldKind::Toggle, _) => format!("[{}]", if field.value == "yes" { "x" } else { " " }),
            (FieldKind::Choice(_), _) => format!("< {} >", field.value),
            (FieldKind::List, _) => format!("({} server(s))", wiz.a.device.roughtime_servers.len()),
            _ => field.value.clone(),
        };
        let mut l = line(format!("{}: {}", field.label, shown), normal());
        l.field = Some(i);
        lines.push(l);
        if matches!(field.kind, FieldKind::List) {
            for (ri, row) in field.value.lines().enumerate() {
                let mark = if ri == wiz.rt_sel { ">" } else { " " };
                lines.push(line(format!("    {mark} {row}"), dim()));
            }
        }
        if i == wiz.form.cursor {
            if let Some(help) = field.help {
                push_wrapped(&mut lines, "    ", help, dim(), width);
            }
            for note in &field.notes {
                push_wrapped(&mut lines, "    ", note, dim(), width);
            }
        }
        for issue in wiz.current_issues(field.id) {
            let (glyph, colour) = match issue.sev {
                Sev::Error => ("x", ERROR_RED),
                Sev::Warning => ("!", NEON_YELLOW),
            };
            push_wrapped(
                &mut lines,
                &format!("    {glyph} "),
                &issue.msg,
                Style::default().fg(colour),
                width,
            );
        }
    }
    if let Some(edit) = &wiz.list_edit {
        lines.push(line("", normal()));
        let prompt = ListEdit::PROMPTS[edit.stage.min(2)];
        let buf = match edit.stage {
            0 => &edit.name,
            1 => &edit.addr,
            _ => &edit.key,
        };
        lines.push(line(
            format!("  Roughtime server {prompt}: {buf}_"),
            bold(NEON_CYAN),
        ));
    }
    let unattached = wiz.unattached_issues();
    if !unattached.is_empty() {
        lines.push(line("", normal()));
        for issue in unattached {
            let (glyph, colour) = match issue.sev {
                Sev::Error => ("x", ERROR_RED),
                Sev::Warning => ("!", NEON_YELLOW),
            };
            push_wrapped(
                &mut lines,
                &format!("  {glyph} "),
                &issue.msg,
                Style::default().fg(colour),
                width,
            );
        }
    }
    (lines, cursor_line)
}

fn section(lines: &mut Vec<Line>, title: &str) {
    lines.push(line("", normal()));
    lines.push(line(title, bold(NEON_CYAN)));
}

fn review_plan(lines: &mut Vec<Line>, plan: &Plan, width: usize) {
    section(lines, "Configuration changes");
    if plan.changes.is_empty() {
        lines.push(line(
            if plan.config_existed {
                "  (none)"
            } else {
                "  (a new config file will be written)"
            },
            dim(),
        ));
    }
    for ch in &plan.changes {
        let old = ch.old.as_deref().unwrap_or("(absent)");
        let new = ch.new.as_deref().unwrap_or("(removed)");
        push_wrapped(
            lines,
            "  ",
            &format!("{}: {old} -> {new}", ch.path),
            normal(),
            width,
        );
    }
    section(lines, "Directories");
    let mut any = false;
    for d in plan.dirs_to_create() {
        any = true;
        let owner = d
            .owner
            .map_or(String::new(), |(u, g)| format!(" owner {u}:{g}"));
        lines.push(line(
            format!("  create {} ({:04o}{owner})", d.path.display(), d.mode),
            normal(),
        ));
    }
    if !any {
        lines.push(line("  (none to create)", dim()));
    }
    section(lines, "Ownership");
    if plan.ownership.is_empty() {
        lines.push(line("  (no ownership changes)", dim()));
    }
    for o in &plan.ownership {
        let owner = o
            .owner
            .map_or("(unchanged)".to_owned(), |(u, g)| format!("{u}:{g}"));
        lines.push(line(
            format!("  {} -> {owner} {:04o}", o.path.display(), o.mode),
            normal(),
        ));
    }
    section(lines, "Authority");
    match plan.authority.describe() {
        Some(text) => {
            let style = if plan.authority.irreversible() {
                bold(ERROR_RED)
            } else {
                normal()
            };
            push_wrapped(lines, "  ", &text, style, width);
        }
        None => lines.push(line("  (unchanged)", dim())),
    }
    section(lines, "Units");
    if plan.units.is_empty() {
        lines.push(line("  (not installing units)", dim()));
    }
    for u in &plan.units {
        let state = match u.state {
            UnitState::Create => "create ",
            UnitState::Replace => "replace",
            UnitState::Same => "same   ",
        };
        lines.push(line(format!("  {state} {}", u.path.display()), normal()));
    }
    section(lines, "Warnings");
    if plan.warnings.is_empty() {
        lines.push(line("  (none)", dim()));
    }
    for wn in &plan.warnings {
        let style = Style::default().fg(if wn.severe { ERROR_RED } else { NEON_YELLOW });
        push_wrapped(lines, "  ! ", &wn.text, style, width);
    }
}

fn review_lines(wiz: &Wizard, width: usize) -> (Vec<Line>, usize) {
    let mut lines = Vec::new();
    match &wiz.plan {
        Some(Ok(plan)) => {
            if plan.is_noop() {
                lines.push(line(
                    "No changes: everything already matches. Apply is disabled.",
                    bold(NEON_GREEN),
                ));
            }
            review_plan(&mut lines, plan, width);
        }
        Some(Err(e)) => {
            push_wrapped(
                &mut lines,
                "",
                &format!("cannot build the plan: {e}"),
                bold(ERROR_RED),
                width,
            );
        }
        None => {}
    }
    if !wiz.review_failures.is_empty() {
        section(&mut lines, "Preflight");
        for i in &wiz.review_failures {
            let (glyph, colour) = match i.sev {
                Sev::Error => ("x", ERROR_RED),
                Sev::Warning => ("!", NEON_YELLOW),
            };
            push_wrapped(
                &mut lines,
                &format!("  {glyph} "),
                &i.msg,
                Style::default().fg(colour),
                width,
            );
        }
    }
    lines.push(line("", normal()));
    let can_apply = matches!(&wiz.plan, Some(Ok(p)) if !p.is_noop());
    let irreversible = matches!(&wiz.plan, Some(Ok(p)) if p.authority.irreversible());
    let apply_label = if !can_apply {
        "  [ Apply (disabled) ]".to_owned()
    } else if irreversible && wiz.confirm_armed {
        "  [ Apply ]  press Enter AGAIN to confirm the irreversible action".to_owned()
    } else {
        "  [ Apply ]".to_owned()
    };
    let sel = |i: usize| {
        if wiz.review_cursor == i {
            bold(NEON_PINK)
        } else {
            normal()
        }
    };
    lines.push(line(apply_label, if can_apply { sel(0) } else { dim() }));
    lines.push(line("  [ Back ]", sel(1)));
    (lines, 0)
}
