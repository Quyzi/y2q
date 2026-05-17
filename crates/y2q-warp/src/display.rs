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
use ratatui::widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Sparkline, Table};
use tokio::sync::mpsc;

use crate::metrics::{Aggregate, ns_to_ms_str};
use crate::ops::OpKind;

const HISTORY_CAP: usize = 256;
const TICK_MS: u64 = 100;
const SAMPLE_INTERVAL_MS: u128 = 1_000;

/// Messages sent to the display task from bench orchestration and the recorder.
pub enum DisplayMsg {
    Preparing { done: u32, total: u32 },
    Running(HashMap<OpKind, Aggregate>),
}

enum Phase {
    Preparing { done: u32, total: u32 },
    Running,
}

struct AppState {
    phase: Phase,
    aggregates: HashMap<OpKind, Aggregate>,
    throughput_history: VecDeque<u64>,
    ops_history: HashMap<OpKind, VecDeque<u64>>,
    errors_4xx_per_sec: HashMap<OpKind, f64>,
    errors_5xx_per_sec: HashMap<OpKind, f64>,
    prev_bytes: u64,
    prev_ops: HashMap<OpKind, u64>,
    prev_errors_4xx: HashMap<OpKind, u64>,
    prev_errors_5xx: HashMap<OpKind, u64>,
    last_sample: Instant,
    bench_start: Option<Instant>,
}

impl AppState {
    fn new() -> Self {
        Self {
            phase: Phase::Preparing { done: 0, total: 0 },
            aggregates: HashMap::new(),
            throughput_history: VecDeque::with_capacity(HISTORY_CAP + 1),
            ops_history: HashMap::new(),
            errors_4xx_per_sec: HashMap::new(),
            errors_5xx_per_sec: HashMap::new(),
            prev_bytes: 0,
            prev_ops: HashMap::new(),
            prev_errors_4xx: HashMap::new(),
            prev_errors_5xx: HashMap::new(),
            last_sample: Instant::now(),
            bench_start: None,
        }
    }

    fn handle_msg(&mut self, msg: DisplayMsg) {
        match msg {
            DisplayMsg::Preparing { done, total } => {
                self.phase = Phase::Preparing { done, total };
            }
            DisplayMsg::Running(agg) => {
                if self.bench_start.is_none() {
                    self.bench_start = Some(Instant::now());
                }
                self.phase = Phase::Running;
                self.aggregates = agg;
                self.tick_sample();
            }
        }
    }

    fn tick(&mut self) {
        if matches!(self.phase, Phase::Running) {
            self.tick_sample();
        }
    }

    fn tick_sample(&mut self) {
        let dt = self.last_sample.elapsed();
        if dt.as_millis() < SAMPLE_INTERVAL_MS {
            return;
        }
        let dt_s = dt.as_secs_f64();

        let total_bytes: u64 = self.aggregates.values().map(|a| a.total_bytes).sum();
        let byte_delta = total_bytes.saturating_sub(self.prev_bytes);
        push_cap(
            &mut self.throughput_history,
            (byte_delta as f64 / (1_048_576.0 * dt_s)).round() as u64,
        );
        self.prev_bytes = total_bytes;

        for (&op, agg) in &self.aggregates {
            let prev_ops = *self.prev_ops.get(&op).unwrap_or(&0);
            let ops_delta = agg.n_ops.saturating_sub(prev_ops);
            push_cap(
                self.ops_history.entry(op).or_default(),
                (ops_delta as f64 / dt_s).round() as u64,
            );
            self.prev_ops.insert(op, agg.n_ops);

            let prev_4xx = *self.prev_errors_4xx.get(&op).unwrap_or(&0);
            let delta_4xx = agg.n_errors_4xx.saturating_sub(prev_4xx);
            self.errors_4xx_per_sec.insert(op, delta_4xx as f64 / dt_s);
            self.prev_errors_4xx.insert(op, agg.n_errors_4xx);

            let prev_5xx = *self.prev_errors_5xx.get(&op).unwrap_or(&0);
            let delta_5xx = agg.n_errors_5xx.saturating_sub(prev_5xx);
            self.errors_5xx_per_sec.insert(op, delta_5xx as f64 / dt_s);
            self.prev_errors_5xx.insert(op, agg.n_errors_5xx);
        }

        self.last_sample = Instant::now();
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

/// Right-justify sparkline data into exactly `width` slots.
/// Pads the left with zeros so the newest sample is always on the right edge.
fn rjust(data: &VecDeque<u64>, width: usize) -> Vec<u64> {
    if width == 0 {
        return vec![];
    }
    let skip = data.len().saturating_sub(width);
    let zeros = width.saturating_sub(data.len());
    std::iter::repeat(0)
        .take(zeros)
        .chain(data.iter().skip(skip).copied())
        .collect()
}

/// Run the TUI display loop. Returns `true` if the user quit early with `q`.
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
                if let Some(Ok(Event::Key(key))) = event {
                    if key.kind == KeyEventKind::Press {
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

fn render(f: &mut Frame, sentinel_op: OpKind, total_duration: Duration, state: &AppState) {
    let area = f.area();
    let outer = Block::default()
        .title(" y2q-warp ")
        .title_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
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
    let pct = if total > 0 {
        ((done as f64 / total as f64) * 100.0).clamp(0.0, 100.0) as u16
    } else {
        0
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(area);

    let title = Paragraph::new(Line::from(vec![
        Span::styled("Seeding   ", Style::default().fg(Color::Yellow)),
        Span::styled(
            format!("{done} / {total}"),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
    ]));
    f.render_widget(title, chunks[0]);

    let gauge = Gauge::default()
        .gauge_style(Style::default().fg(Color::Yellow).bg(Color::DarkGray))
        .percent(pct)
        .label(format!(" {pct}% "));
    f.render_widget(gauge, chunks[1]);
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
    let table_height = n_data_rows + 2; // header row + bottom_margin

    let mut constraints = vec![
        Constraint::Length(1),            // progress gauge
        Constraint::Length(table_height), // stats table
        Constraint::Min(3),               // throughput sparkline
    ];
    for _ in op_kinds {
        constraints.push(Constraint::Length(3)); // one row per op's ops/s sparkline
    }
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    // --- Progress gauge ---
    let op_label = match op_kinds.len() {
        0 => sentinel_op.as_str().to_owned(),
        1 => op_kinds[0].as_str().to_owned(),
        _ => "MIXED".to_owned(),
    };
    let pct =
        ((elapsed.as_secs_f64() / total_duration.as_secs_f64()) * 100.0).clamp(0.0, 100.0) as u16;
    let gauge = Gauge::default()
        .gauge_style(Style::default().fg(Color::Green).bg(Color::DarkGray))
        .percent(pct)
        .label(format!(
            " {}   {}s / {}s   {}% ",
            op_label,
            elapsed.as_secs(),
            total_duration.as_secs(),
            pct,
        ));
    f.render_widget(gauge, chunks[0]);

    // --- Stats table ---
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
                    .fg(Color::Yellow)
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
                Cell::from(kind.as_str()),
                Cell::from(format!("{:>8}", agg.n_ops)),
                Cell::from(if e4 > 0.0 {
                    format!("{:>5.1}", e4)
                } else {
                    format!("{:>5}", "0")
                })
                .style(if e4 > 0.0 {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                }),
                Cell::from(if e5 > 0.0 {
                    format!("{:>5.1}", e5)
                } else {
                    format!("{:>5}", "0")
                })
                .style(if e5 > 0.0 {
                    Style::default().fg(Color::Red)
                } else {
                    Style::default()
                }),
                Cell::from(format!("{:>10.1} MiB/s", agg.throughput_mibps))
                    .style(Style::default().fg(Color::Cyan)),
                Cell::from(format!("{:>6.0}", agg.ops_per_sec)),
                Cell::from(format!("{:>7}", ns_to_ms_str(agg.p50_ns))),
                Cell::from(format!("{:>7}", ns_to_ms_str(agg.p90_ns))),
                Cell::from(format!("{:>7}", ns_to_ms_str(agg.p99_ns))),
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

    // --- Throughput sparkline ---
    let tp_area = chunks[2];
    let tp_hist = rjust(&state.throughput_history, tp_area.width as usize);
    let tp_peak = tp_hist.iter().copied().max().unwrap_or(0);
    let tp_spark = Sparkline::default()
        .block(
            Block::default()
                .title(format!(" Throughput MiB/s  peak {tp_peak} "))
                .title_style(Style::default().fg(Color::Cyan))
                .borders(Borders::TOP)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .data(&tp_hist)
        .style(Style::default().fg(Color::Green));
    f.render_widget(tp_spark, tp_area);

    // --- Per-op ops/s sparklines (one row each, stacked vertically) ---
    for (i, &op) in op_kinds.iter().enumerate() {
        let chunk_idx = 3 + i;
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
        let spark = Sparkline::default()
            .block(
                Block::default()
                    .title(format!(
                        " {} ops/s  now {}  peak {} ",
                        op.as_str(),
                        current,
                        peak
                    ))
                    .title_style(Style::default().fg(Color::Cyan))
                    .borders(Borders::TOP)
                    .border_style(Style::default().fg(Color::DarkGray)),
            )
            .data(&hist)
            .style(Style::default().fg(Color::Yellow));
        f.render_widget(spark, area);
    }
}

fn render_statusbar(f: &mut Frame, area: Rect) {
    let bar = Paragraph::new(Line::from(vec![
        Span::styled(
            "  q",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" quit", Style::default().fg(Color::DarkGray)),
    ]));
    f.render_widget(bar, area);
}

async fn plain_fallback(mut rx: mpsc::Receiver<DisplayMsg>, op: OpKind, total_duration: Duration) {
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    let mut bench_start: Option<Instant> = None;

    loop {
        let mut latest: Option<HashMap<OpKind, Aggregate>> = None;
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
                    Some(DisplayMsg::Running(m)) => {
                        if bench_start.is_none() {
                            bench_start = Some(Instant::now());
                        }
                        latest = Some(m);
                    }
                }
            }
        }
        while let Ok(DisplayMsg::Running(m)) = rx.try_recv() {
            latest = Some(m);
        }
        let elapsed = bench_start.map_or(Duration::ZERO, |s| s.elapsed());
        if elapsed >= total_duration {
            break;
        }
        if let Some(agg_map) = latest {
            let agg = agg_map.get(&op);
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
        }
    }
}
