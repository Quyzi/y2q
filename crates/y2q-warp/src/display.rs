use std::collections::{HashMap, VecDeque};
use std::io::stdout;
use std::time::{Duration, Instant};

use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use futures::StreamExt;
use ratatui::Frame;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Sparkline, Table};
use tokio::sync::mpsc;

use crate::metrics::{Aggregate, ns_to_ms_str};
use crate::ops::OpKind;

// ── Cyberpunk palette ────────────────────────────────────────────────────────
const NEON_PINK: Color = Color::Rgb(255, 20, 147);
const NEON_CYAN: Color = Color::Rgb(0, 255, 255);
const NEON_GREEN: Color = Color::Rgb(57, 255, 20);
const NEON_YELLOW: Color = Color::Rgb(255, 215, 0);
const NEON_PURPLE: Color = Color::Rgb(188, 0, 255);
const ERROR_RED: Color = Color::Rgb(255, 50, 50);
const DIM_BORDER: Color = Color::Rgb(50, 50, 80);
const DIM_TEXT: Color = Color::Rgb(90, 90, 130);
const NORMAL_TEXT: Color = Color::Rgb(200, 210, 255);

// ── Particle bar ─────────────────────────────────────────────────────────────
const PARTICLES: &[(usize, char)] = &[(1, '·'), (3, '∘'), (5, '·'), (8, '⋅'), (11, '·')];

/// Build colored particle-animated bar spans (no brackets).
/// `bar_w` — inner character width.
/// `frame` — animation counter (e.g. elapsed secs, done-count/10, etc.)
fn particle_bar_spans(
    bar_w: usize,
    ratio: f64,
    frame: usize,
    fill_color: Color,
) -> Vec<Span<'static>> {
    let fill = ((ratio * bar_w as f64) as usize).min(bar_w);
    let remaining = bar_w.saturating_sub(fill);
    let mut spans = Vec::with_capacity(4);

    if fill > 1 {
        spans.push(Span::styled(
            "█".repeat(fill - 1),
            Style::default().fg(fill_color),
        ));
    }
    if fill > 0 {
        spans.push(Span::styled(
            "▶",
            Style::default().fg(NEON_PINK).add_modifier(Modifier::BOLD),
        ));
    }
    if remaining > 0 {
        let mut empty: Vec<char> = vec!['░'; remaining];
        for &(base_off, ch) in PARTICLES {
            let pos = (base_off + frame / 2) % remaining.max(1);
            empty[pos] = ch;
        }
        spans.push(Span::styled(
            empty.into_iter().collect::<String>(),
            Style::default().fg(NEON_YELLOW),
        ));
    }
    spans
}

/// Render a full particle bar row (brackets + bar + label suffix) into `area`.
fn render_particle_bar(
    f: &mut Frame,
    area: Rect,
    ratio: f64,
    frame: usize,
    fill_color: Color,
    label: &str,
) {
    let label_w = label.chars().count() as u16;
    let bar_w = area.width.saturating_sub(label_w).saturating_sub(2) as usize; // subtract [ ]

    let mut spans = vec![Span::styled("[", Style::default().fg(DIM_BORDER))];
    spans.extend(particle_bar_spans(bar_w, ratio, frame, fill_color));
    spans.push(Span::styled("]", Style::default().fg(DIM_BORDER)));
    spans.push(Span::styled(
        label.to_owned(),
        Style::default().fg(NEON_GREEN),
    ));

    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

// ── Data / state ─────────────────────────────────────────────────────────────
const HISTORY_CAP: usize = 256;
const TICK_MS: u64 = 100;
const SAMPLE_INTERVAL_MS: u128 = 1_000;

/// One live snapshot from the recorder: per-op rollups plus per-contact-node
/// rollups (the latter keyed by the round-robin endpoint label).
pub struct RunningSnapshot {
    pub ops: HashMap<OpKind, Aggregate>,
    pub nodes: HashMap<String, Aggregate>,
}

pub enum DisplayMsg {
    Preparing { done: u32, total: u32 },
    Running(RunningSnapshot),
}

enum Phase {
    Preparing { done: u32, total: u32 },
    Running,
}

struct AppState {
    phase: Phase,
    aggregates: HashMap<OpKind, Aggregate>,
    /// Per-contact-node rollups, keyed by endpoint label ("0", "1", …).
    node_aggregates: HashMap<String, Aggregate>,
    throughput_history: VecDeque<u64>,
    ops_history: HashMap<OpKind, VecDeque<u64>>,
    errors_4xx_per_sec: HashMap<OpKind, f64>,
    errors_5xx_per_sec: HashMap<OpKind, f64>,
    /// Cumulative byte/op counts timestamped at snapshot-arrival time. Displayed
    /// throughput is the *slope* over a trailing window of these, not a per-tick
    /// delta. Because cumulative counts are monotonic and anchored to real
    /// arrival times, a dropped or late snapshot can never produce the
    /// zero-delta-then-catch-up "dip + spike" pair the old per-tick reset did.
    bytes_ring: VecDeque<(Instant, u64)>,
    ops_ring: HashMap<OpKind, VecDeque<(Instant, u64)>>,
    prev_errors_4xx: HashMap<OpKind, u64>,
    prev_errors_5xx: HashMap<OpKind, u64>,
    last_err_sample: Instant,
    last_history: Instant,
    bench_start: Option<Instant>,
}

impl AppState {
    fn new() -> Self {
        Self {
            phase: Phase::Preparing { done: 0, total: 0 },
            aggregates: HashMap::new(),
            node_aggregates: HashMap::new(),
            throughput_history: VecDeque::with_capacity(HISTORY_CAP + 1),
            ops_history: HashMap::new(),
            errors_4xx_per_sec: HashMap::new(),
            errors_5xx_per_sec: HashMap::new(),
            bytes_ring: VecDeque::new(),
            ops_ring: HashMap::new(),
            prev_errors_4xx: HashMap::new(),
            prev_errors_5xx: HashMap::new(),
            last_err_sample: Instant::now(),
            last_history: Instant::now(),
            bench_start: None,
        }
    }

    fn handle_msg(&mut self, msg: DisplayMsg) {
        match msg {
            DisplayMsg::Preparing { done, total } => {
                self.phase = Phase::Preparing { done, total };
            }
            DisplayMsg::Running(snap) => {
                if self.bench_start.is_none() {
                    self.bench_start = Some(Instant::now());
                }
                self.phase = Phase::Running;
                self.aggregates = snap.ops;
                self.node_aggregates = snap.nodes;
                self.record_snapshot();
            }
        }
    }

    /// Append the latest cumulative counts to the rings (called on every
    /// snapshot arrival, decoupled from the history sampling cadence).
    fn record_snapshot(&mut self) {
        let now = Instant::now();
        let total_bytes: u64 = self.aggregates.values().map(|a| a.total_bytes).sum();
        push_ring(&mut self.bytes_ring, now, total_bytes);

        // Snapshot per-op cumulative counts up front to avoid borrowing
        // `self.aggregates` while mutating the ring/error maps below.
        let snap: Vec<(OpKind, u64, u64, u64)> = self
            .aggregates
            .iter()
            .map(|(&op, a)| (op, a.n_ops, a.n_errors_4xx, a.n_errors_5xx))
            .collect();

        let dt_s = self.last_err_sample.elapsed().as_secs_f64().max(1e-3);
        for (op, n_ops, n_4xx, n_5xx) in snap {
            push_ring(self.ops_ring.entry(op).or_default(), now, n_ops);

            let p4 = *self.prev_errors_4xx.get(&op).unwrap_or(&0);
            self.errors_4xx_per_sec
                .insert(op, n_4xx.saturating_sub(p4) as f64 / dt_s);
            self.prev_errors_4xx.insert(op, n_4xx);

            let p5 = *self.prev_errors_5xx.get(&op).unwrap_or(&0);
            self.errors_5xx_per_sec
                .insert(op, n_5xx.saturating_sub(p5) as f64 / dt_s);
            self.prev_errors_5xx.insert(op, n_5xx);
        }
        self.last_err_sample = now;
    }

    fn tick(&mut self) {
        if matches!(self.phase, Phase::Running)
            && self.last_history.elapsed().as_millis() >= SAMPLE_INTERVAL_MS
        {
            self.push_history();
            self.last_history = Instant::now();
        }
    }

    /// Push one bar per op to the sparkline histories, valued by the trailing
    /// 1s slope of the cumulative rings. Cadence is the fixed ticker, so the
    /// x-axis is uniform; values come from the rings, so the y-axis is correct
    /// regardless of snapshot jitter.
    fn push_history(&mut self) {
        let now = Instant::now();
        let window = Duration::from_secs(1);

        let bps = rate_per_s(&self.bytes_ring, window, now);
        push_cap(
            &mut self.throughput_history,
            (bps as f64 / 1_048_576.0).round() as u64,
        );

        let ops: Vec<OpKind> = self.aggregates.keys().copied().collect();
        for op in ops {
            let r = self
                .ops_ring
                .get(&op)
                .map(|ring| rate_per_s(ring, window, now))
                .unwrap_or(0);
            push_cap(self.ops_history.entry(op).or_default(), r);
        }
    }

    fn bench_elapsed(&self) -> Duration {
        self.bench_start.map_or(Duration::ZERO, |s| s.elapsed())
    }
}

fn push_cap(h: &mut VecDeque<u64>, v: u64) {
    if h.len() >= HISTORY_CAP {
        h.pop_front();
    }
    h.push_back(v);
}

/// Append a timestamped cumulative sample, trimming entries older than the
/// retention window (but always keeping at least two points for a slope).
fn push_ring(ring: &mut VecDeque<(Instant, u64)>, now: Instant, val: u64) {
    ring.push_back((now, val));
    while ring.len() > 2 {
        match ring.front() {
            Some(&(t, _)) if now.duration_since(t) > Duration::from_secs(3) => {
                ring.pop_front();
            }
            _ => break,
        }
    }
}

/// Average rate per second over the trailing `window`: the slope between the
/// newest cumulative sample and the newest sample at or before `now - window`
/// (falling back to the oldest sample). Monotonic input → never negative, and
/// a missing snapshot just widens the interval rather than zeroing it.
fn rate_per_s(ring: &VecDeque<(Instant, u64)>, window: Duration, now: Instant) -> u64 {
    if ring.len() < 2 {
        return 0;
    }
    let (t_late, v_late) = *ring.back().unwrap();
    let target = now.checked_sub(window);
    let mut start = *ring.front().unwrap();
    for &p in ring.iter() {
        match target {
            Some(tt) if p.0 <= tt => start = p,
            _ => break,
        }
    }
    let (t_early, v_early) = start;
    let dt = t_late.saturating_duration_since(t_early).as_secs_f64();
    if dt <= 0.0 {
        return 0;
    }
    (v_late.saturating_sub(v_early) as f64 / dt).round() as u64
}

fn rjust(data: &VecDeque<u64>, width: usize) -> Vec<u64> {
    if width == 0 {
        return vec![];
    }
    let skip = data.len().saturating_sub(width);
    let zeros = width.saturating_sub(data.len());
    std::iter::repeat_n(0, zeros)
        .chain(data.iter().skip(skip).copied())
        .collect()
}

// ── Entry point ───────────────────────────────────────────────────────────────
pub async fn run_display(
    rx: mpsc::Receiver<DisplayMsg>,
    sentinel_op: OpKind,
    total_duration: Duration,
) -> bool {
    if enable_raw_mode().is_err() {
        plain_fallback(rx, sentinel_op, total_duration).await;
        return false;
    }
    let mut out = stdout();
    if execute!(out, EnterAlternateScreen).is_err() {
        let _ = disable_raw_mode();
        plain_fallback(rx, sentinel_op, total_duration).await;
        return false;
    }
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = match ratatui::Terminal::new(backend) {
        Ok(t) => t,
        Err(_) => {
            let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
            let _ = disable_raw_mode();
            plain_fallback(rx, sentinel_op, total_duration).await;
            return false;
        }
    };
    let _ = terminal.clear();

    let mut state = AppState::new();
    let mut ticker = tokio::time::interval(Duration::from_millis(TICK_MS));
    let mut rx = rx;
    let mut events = EventStream::new();
    let mut user_quit = false;

    'outer: loop {
        tokio::select! {
            _ = ticker.tick() => {
                state.tick();
            }
            msg = rx.recv() => {
                match msg {
                    None => break 'outer,
                    Some(m) => state.handle_msg(m),
                }
            }
            event = events.next() => {
                if let Some(Ok(Event::Key(key))) = event
                    && key.kind == KeyEventKind::Press {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
                                user_quit = true;
                                break 'outer;
                            }
                            _ => {}
                        }
                    }
            }
        }
        while let Ok(m) = rx.try_recv() {
            state.handle_msg(m);
        }
        let _ = terminal.draw(|f| render(f, sentinel_op, total_duration, &state));
    }

    let _ = terminal.draw(|f| render(f, sentinel_op, total_duration, &state));
    if !user_quit {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = disable_raw_mode();
    user_quit
}

// ── Render ────────────────────────────────────────────────────────────────────
fn render(f: &mut Frame, sentinel_op: OpKind, total_duration: Duration, state: &AppState) {
    let area = f.area();
    let outer = Block::default()
        .title(Span::styled(
            " // Y2Q-WARP // POST-QUANTUM BENCHMARK // ",
            Style::default().fg(NEON_PINK).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(NEON_PINK));
    let inner = outer.inner(area);
    f.render_widget(outer, area);

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(inner);
    let main_area = layout[0];
    let status_area = layout[1];

    render_statusbar(f, status_area);

    match &state.phase {
        Phase::Preparing { done, total } => render_prepare(f, main_area, *done, *total),
        Phase::Running => {
            let mut op_kinds: Vec<OpKind> = state.aggregates.keys().copied().collect();
            op_kinds.sort_by_key(|k| k.as_str());
            render_running(f, main_area, sentinel_op, total_duration, state, &op_kinds);
        }
    }
}

fn render_prepare(f: &mut Frame, area: Rect, done: u32, total: u32) {
    let ratio = if total > 0 {
        (done as f64 / total as f64).clamp(0.0, 1.0)
    } else {
        0.0
    };
    let pct = (ratio * 100.0) as u16;
    let frame = (done / 10) as usize;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(area);

    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            "SEEDING  ",
            Style::default()
                .fg(NEON_YELLOW)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{done}"),
            Style::default().fg(NEON_CYAN).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" / ", Style::default().fg(DIM_TEXT)),
        Span::styled(format!("{total}"), Style::default().fg(NEON_CYAN)),
        Span::styled(format!("  {pct}%"), Style::default().fg(NEON_GREEN)),
    ]));
    f.render_widget(title, chunks[0]);

    render_particle_bar(f, chunks[1], ratio, frame, NEON_CYAN, "");
}

fn render_running(
    f: &mut Frame,
    area: Rect,
    sentinel_op: OpKind,
    total_duration: Duration,
    state: &AppState,
    op_kinds: &[OpKind],
) {
    let elapsed = state.bench_elapsed().min(total_duration);
    let n_data_rows = op_kinds.len().max(1) as u16;
    let table_height = n_data_rows + 2;

    // Per-contact-node panel only when the run fans across more than one node.
    let mut node_labels: Vec<String> = state.node_aggregates.keys().cloned().collect();
    node_labels.sort();
    let show_nodes = node_labels.len() > 1;
    // header(1) + bottom margin(1) + rows(n) + TOP border(1).
    let node_table_height = node_labels.len() as u16 + 3;

    let mut constraints = vec![Constraint::Length(1), Constraint::Length(table_height)];
    if show_nodes {
        constraints.push(Constraint::Length(node_table_height));
    }
    constraints.push(Constraint::Min(3));
    for _ in op_kinds {
        constraints.push(Constraint::Length(3));
    }
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    // chunks[0] = time bar, chunks[1] = op table, then the optional node table,
    // then the throughput sparkline, then one sparkline per op kind.
    let mut next = 2;
    let node_area = if show_nodes {
        let a = chunks[next];
        next += 1;
        Some(a)
    } else {
        None
    };
    let tp_idx = next;
    next += 1;
    let spark_base = next;

    // ── Time progress bar ────────────────────────────────────────────────────
    let op_label = match op_kinds.len() {
        0 => sentinel_op.as_str().to_owned(),
        1 => op_kinds[0].as_str().to_owned(),
        _ => "MIXED".to_owned(),
    };
    let ratio = (elapsed.as_secs_f64() / total_duration.as_secs_f64()).clamp(0.0, 1.0);
    let pct = (ratio * 100.0) as u16;
    let frame = elapsed.as_secs() as usize;
    let label = format!(
        "  {}  {}s / {}s  {}%",
        op_label,
        elapsed.as_secs(),
        total_duration.as_secs(),
        pct,
    );
    render_particle_bar(f, chunks[0], ratio, frame, NEON_GREEN, &label);

    // ── Stats table ──────────────────────────────────────────────────────────
    let header = Row::new(
        [
            "Op",
            "Ops",
            "4xx/s",
            "5xx/s",
            "Throughput",
            "Ops/s",
            "P50",
            "P90",
            "P99",
        ]
        .map(|h| {
            Cell::from(h).style(
                Style::default()
                    .fg(NEON_YELLOW)
                    .add_modifier(Modifier::BOLD),
            )
        }),
    )
    .height(1)
    .bottom_margin(1);

    let rows: Vec<Row> = op_kinds
        .iter()
        .map(|kind| {
            let agg = &state.aggregates[kind];
            let e4 = state.errors_4xx_per_sec.get(kind).copied().unwrap_or(0.0);
            let e5 = state.errors_5xx_per_sec.get(kind).copied().unwrap_or(0.0);
            Row::new([
                Cell::from(kind.as_str()).style(Style::default().fg(NEON_CYAN)),
                Cell::from(format!("{:>8}", agg.n_ops)).style(Style::default().fg(NORMAL_TEXT)),
                Cell::from(if e4 > 0.0 {
                    format!("{:>5.1}", e4)
                } else {
                    format!("{:>5}", "0")
                })
                .style(if e4 > 0.0 {
                    Style::default()
                        .fg(NEON_YELLOW)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(DIM_TEXT)
                }),
                Cell::from(if e5 > 0.0 {
                    format!("{:>5.1}", e5)
                } else {
                    format!("{:>5}", "0")
                })
                .style(if e5 > 0.0 {
                    Style::default().fg(ERROR_RED).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(DIM_TEXT)
                }),
                Cell::from(format!("{:>10.1} MiB/s", agg.throughput_mibps))
                    .style(Style::default().fg(NEON_GREEN).add_modifier(Modifier::BOLD)),
                Cell::from(format!("{:>6.0}", agg.ops_per_sec))
                    .style(Style::default().fg(NEON_PURPLE)),
                Cell::from(format!("{:>7}", ns_to_ms_str(agg.p50_ns)))
                    .style(Style::default().fg(NORMAL_TEXT)),
                Cell::from(format!("{:>7}", ns_to_ms_str(agg.p90_ns)))
                    .style(Style::default().fg(NORMAL_TEXT)),
                Cell::from(format!("{:>7}", ns_to_ms_str(agg.p99_ns)))
                    .style(Style::default().fg(NORMAL_TEXT)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(9),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(16),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::NONE))
    .column_spacing(1);
    f.render_widget(table, chunks[1]);

    // ── Per-node table (contact endpoint) ─────────────────────────────────────
    if let Some(area) = node_area {
        render_node_table(f, area, state, &node_labels);
    }

    // ── Throughput sparkline ─────────────────────────────────────────────────
    let tp_area = chunks[tp_idx];
    let tp_hist = rjust(&state.throughput_history, tp_area.width as usize);
    let tp_peak = tp_hist.iter().copied().max().unwrap_or(0);
    let tp_cur = state.throughput_history.back().copied().unwrap_or(0);
    let tp_spark = Sparkline::default()
        .block(
            Block::default()
                .title(Line::from(vec![
                    Span::styled(" Throughput MiB/s ", Style::default().fg(NEON_CYAN)),
                    Span::styled("now ", Style::default().fg(DIM_TEXT)),
                    Span::styled(
                        format!("{tp_cur}"),
                        Style::default().fg(NEON_GREEN).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("  peak ", Style::default().fg(DIM_TEXT)),
                    Span::styled(format!("{tp_peak} "), Style::default().fg(NEON_YELLOW)),
                ]))
                .borders(Borders::TOP)
                .border_style(Style::default().fg(DIM_BORDER)),
        )
        .data(&tp_hist)
        .style(Style::default().fg(NEON_GREEN));
    f.render_widget(tp_spark, tp_area);

    // ── Per-op ops/s sparklines ───────────────────────────────────────────────
    // Cycle through neon colors for multiple ops
    let spark_colors = [NEON_YELLOW, NEON_CYAN, NEON_PURPLE, NEON_GREEN];
    for (i, &op) in op_kinds.iter().enumerate() {
        let chunk_idx = spark_base + i;
        if chunk_idx >= chunks.len() {
            break;
        }
        let area = chunks[chunk_idx];
        let history = state.ops_history.get(&op);
        let current = history.and_then(|h| h.back().copied()).unwrap_or(0);
        let hist = history
            .map(|h| rjust(h, area.width as usize))
            .unwrap_or_else(|| vec![0u64; area.width as usize]);
        let peak = hist.iter().copied().max().unwrap_or(0);
        let color = spark_colors[i % spark_colors.len()];
        let spark = Sparkline::default()
            .block(
                Block::default()
                    .title(Line::from(vec![
                        Span::styled(
                            format!(" {} ops/s ", op.as_str()),
                            Style::default().fg(NEON_CYAN),
                        ),
                        Span::styled("now ", Style::default().fg(DIM_TEXT)),
                        Span::styled(
                            format!("{current}"),
                            Style::default().fg(color).add_modifier(Modifier::BOLD),
                        ),
                        Span::styled("  peak ", Style::default().fg(DIM_TEXT)),
                        Span::styled(format!("{peak} "), Style::default().fg(NEON_YELLOW)),
                    ]))
                    .borders(Borders::TOP)
                    .border_style(Style::default().fg(DIM_BORDER)),
            )
            .data(&hist)
            .style(Style::default().fg(color));
        f.render_widget(spark, area);
    }
}

/// Per-contact-node rollup table (cumulative over the run so far), mirroring the
/// op table's columns. `labels` is the sorted set of endpoint labels.
fn render_node_table(f: &mut Frame, area: Rect, state: &AppState, labels: &[String]) {
    let header = Row::new(
        [
            "Node",
            "Ops",
            "5xx",
            "Throughput",
            "Ops/s",
            "P50",
            "P90",
            "P99",
        ]
        .map(|h| {
            Cell::from(h).style(
                Style::default()
                    .fg(NEON_YELLOW)
                    .add_modifier(Modifier::BOLD),
            )
        }),
    )
    .height(1)
    .bottom_margin(1);

    let rows: Vec<Row> = labels
        .iter()
        .filter_map(|label| state.node_aggregates.get(label).map(|agg| (label, agg)))
        .map(|(label, agg)| {
            Row::new([
                Cell::from(format!("node {label}")).style(Style::default().fg(NEON_PINK)),
                Cell::from(format!("{:>8}", agg.n_ops)).style(Style::default().fg(NORMAL_TEXT)),
                Cell::from(format!("{:>5}", agg.n_errors_5xx)).style(if agg.n_errors_5xx > 0 {
                    Style::default().fg(ERROR_RED).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(DIM_TEXT)
                }),
                Cell::from(format!("{:>10.1} MiB/s", agg.throughput_mibps))
                    .style(Style::default().fg(NEON_GREEN).add_modifier(Modifier::BOLD)),
                Cell::from(format!("{:>6.0}", agg.ops_per_sec))
                    .style(Style::default().fg(NEON_PURPLE)),
                Cell::from(format!("{:>7}", ns_to_ms_str(agg.p50_ns)))
                    .style(Style::default().fg(NORMAL_TEXT)),
                Cell::from(format!("{:>7}", ns_to_ms_str(agg.p90_ns)))
                    .style(Style::default().fg(NORMAL_TEXT)),
                Cell::from(format!("{:>7}", ns_to_ms_str(agg.p99_ns)))
                    .style(Style::default().fg(NORMAL_TEXT)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(9),
            Constraint::Length(5),
            Constraint::Length(16),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(Span::styled(
                " PER-NODE (contact endpoint) ",
                Style::default().fg(NEON_PINK).add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::TOP)
            .border_style(Style::default().fg(DIM_BORDER)),
    )
    .column_spacing(1);
    f.render_widget(table, area);
}

fn render_statusbar(f: &mut Frame, area: Rect) {
    let bar = Paragraph::new(Line::from(vec![
        Span::styled(" // ", Style::default().fg(DIM_TEXT)),
        Span::styled(
            " q ",
            Style::default()
                .fg(NEON_CYAN)
                .bg(DIM_BORDER)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" quit", Style::default().fg(NORMAL_TEXT)),
    ]));
    f.render_widget(bar, area);
}

// ── Plain fallback (no TTY) ───────────────────────────────────────────────────
async fn plain_fallback(mut rx: mpsc::Receiver<DisplayMsg>, op: OpKind, total_duration: Duration) {
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    let mut bench_start: Option<Instant> = None;

    loop {
        let mut latest: Option<RunningSnapshot> = None;
        tokio::select! {
            _ = interval.tick() => {}
            msg = rx.recv() => {
                match msg {
                    None => break,
                    Some(DisplayMsg::Preparing { done, total }) => {
                        if done % 100 == 0 || done == total {
                            eprintln!("seeding {done}/{total}...");
                        }
                        continue;
                    }
                    Some(DisplayMsg::Running(snap)) => {
                        if bench_start.is_none() {
                            bench_start = Some(Instant::now());
                        }
                        latest = Some(snap);
                    }
                }
            }
        }
        while let Ok(DisplayMsg::Running(snap)) = rx.try_recv() {
            latest = Some(snap);
        }
        let elapsed = bench_start.map_or(Duration::ZERO, |s| s.elapsed());
        if elapsed >= total_duration {
            break;
        }
        if let Some(snap) = latest {
            let agg = snap.ops.get(&op);
            eprintln!(
                "y2q-warp  {op}  {}s/{}s | {}",
                elapsed.as_secs(),
                total_duration.as_secs(),
                agg.map(|a| format!(
                    "{:.1} MiB/s  {:.0} ops/s  {} errors",
                    a.throughput_mibps, a.ops_per_sec, a.n_errors
                ))
                .unwrap_or_else(|| "--".to_owned()),
            );
            // Per-contact-node line for multi-node fan-out runs.
            if snap.nodes.len() > 1 {
                let mut labels: Vec<&String> = snap.nodes.keys().collect();
                labels.sort();
                let parts: Vec<String> = labels
                    .iter()
                    .map(|l| {
                        let a = &snap.nodes[*l];
                        format!("n{l} {:.0}MiB/s", a.throughput_mibps)
                    })
                    .collect();
                eprintln!("          per-node | {}", parts.join("  "));
            }
        }
    }
}
