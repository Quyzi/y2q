use std::collections::{HashMap, VecDeque};
use std::io::stdout;
use std::time::{Duration, Instant};

use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Frame;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Cell, Gauge, Row, Sparkline, Table};
use tokio::sync::mpsc;

use crate::metrics::{Aggregate, ns_to_ms_str};
use crate::ops::OpKind;

const HISTORY_CAP: usize = 120;
const TICK_MS: u64 = 100;
const SAMPLE_INTERVAL_MS: u128 = 1000;

struct AppState {
    aggregates: HashMap<OpKind, Aggregate>,
    history: VecDeque<u64>,
    prev_total_bytes: u64,
    last_sample: Instant,
}

impl AppState {
    fn new() -> Self {
        Self {
            aggregates: HashMap::new(),
            history: VecDeque::with_capacity(HISTORY_CAP + 1),
            prev_total_bytes: 0,
            last_sample: Instant::now(),
        }
    }

    fn update(&mut self, aggregates: HashMap<OpKind, Aggregate>) {
        self.aggregates = aggregates;
        self.tick_sample();
    }

    fn tick_sample(&mut self) {
        let dt = self.last_sample.elapsed();
        if dt.as_millis() < SAMPLE_INTERVAL_MS {
            return;
        }
        let total_bytes: u64 = self.aggregates.values().map(|a| a.total_bytes).sum();
        let delta = total_bytes.saturating_sub(self.prev_total_bytes);
        let mibps = (delta as f64 / (1024.0 * 1024.0)) / dt.as_secs_f64();
        while self.history.len() >= HISTORY_CAP {
            self.history.pop_front();
        }
        self.history.push_back(mibps.round() as u64);
        self.prev_total_bytes = total_bytes;
        self.last_sample = Instant::now();
    }
}

pub async fn run_display(
    mut rx: mpsc::Receiver<HashMap<OpKind, Aggregate>>,
    op: OpKind,
    total_duration: Duration,
    start: Instant,
) {
    if enable_raw_mode().is_err() {
        plain_fallback(rx, op, total_duration, start).await;
        return;
    }
    let mut out = stdout();
    if execute!(out, EnterAlternateScreen).is_err() {
        let _ = disable_raw_mode();
        plain_fallback(rx, op, total_duration, start).await;
        return;
    }
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = match ratatui::Terminal::new(backend) {
        Ok(t) => t,
        Err(_) => {
            let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
            let _ = disable_raw_mode();
            plain_fallback(rx, op, total_duration, start).await;
            return;
        }
    };
    let _ = terminal.clear();

    let mut state = AppState::new();
    let mut ticker = tokio::time::interval(Duration::from_millis(TICK_MS));

    'outer: loop {
        let mut latest = None;
        tokio::select! {
            _ = ticker.tick() => {}
            maybe = rx.recv() => {
                match maybe {
                    None => break 'outer,
                    Some(m) => latest = Some(m),
                }
            }
        }
        while let Ok(m) = rx.try_recv() {
            latest = Some(m);
        }
        if let Some(m) = latest {
            state.update(m);
        } else {
            state.tick_sample();
        }

        let elapsed = start.elapsed();
        if elapsed >= total_duration {
            break;
        }
        let _ = terminal.draw(|f| render(f, op, elapsed, total_duration, &state));
    }

    // Final frame at 100%
    let _ = terminal.draw(|f| render(f, op, total_duration, total_duration, &state));
    tokio::time::sleep(Duration::from_millis(200)).await;

    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = disable_raw_mode();
}

fn render(
    f: &mut Frame,
    sentinel_op: OpKind,
    elapsed: Duration,
    total: Duration,
    state: &AppState,
) {
    let area = f.area();

    let outer = Block::default()
        .title(" y2q-warp ")
        .title_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = outer.inner(area);
    f.render_widget(outer, area);

    // Determine op label from what's actually in the aggregates map.
    let op_label = match state.aggregates.len() {
        0 => sentinel_op.as_str().to_owned(),
        1 => state.aggregates.keys().next().unwrap().as_str().to_owned(),
        _ => "MIXED".to_owned(),
    };

    let n_data_rows = state.aggregates.len().max(1) as u16;
    // header row (1) + bottom_margin on header (1) + data rows
    let table_height = n_data_rows + 2;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),            // gauge
            Constraint::Length(table_height), // stats table
            Constraint::Min(3),               // sparkline
        ])
        .split(inner);

    // --- Progress gauge ---
    let pct = ((elapsed.as_secs_f64() / total.as_secs_f64()) * 100.0).clamp(0.0, 100.0) as u16;
    let gauge_label = format!(
        " {}   {}s / {}s   {}% ",
        op_label,
        elapsed.as_secs(),
        total.as_secs(),
        pct,
    );
    let gauge = Gauge::default()
        .gauge_style(Style::default().fg(Color::Green).bg(Color::DarkGray))
        .percent(pct)
        .label(gauge_label);
    f.render_widget(gauge, chunks[0]);

    // --- Stats table ---
    let header = Row::new(
        ["Op", "Ops", "Errors", "Throughput", "Ops/s", "P50", "P90", "P99"]
            .map(|h| Cell::from(h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
    )
    .height(1)
    .bottom_margin(1);

    let mut op_kinds: Vec<OpKind> = state.aggregates.keys().copied().collect();
    op_kinds.sort_by_key(|k| k.as_str());

    let rows: Vec<Row> = op_kinds
        .iter()
        .map(|kind| {
            let agg = &state.aggregates[kind];
            let err_style = if agg.n_errors > 0 {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::Green)
            };
            Row::new([
                Cell::from(kind.as_str()),
                Cell::from(format!("{:>8}", agg.n_ops)),
                Cell::from(format!("{:>8}", agg.n_errors)).style(err_style),
                Cell::from(format!("{:>10.1} MiB/s", agg.throughput_mibps))
                    .style(Style::default().fg(Color::Cyan)),
                Cell::from(format!("{:>6.0}", agg.ops_per_sec)),
                Cell::from(format!("{:>7}", ns_to_ms_str(agg.p50_ns))),
                Cell::from(format!("{:>7}", ns_to_ms_str(agg.p90_ns))),
                Cell::from(format!("{:>7}", ns_to_ms_str(agg.p99_ns))),
            ])
        })
        .collect();

    let col_widths = [
        Constraint::Length(8),
        Constraint::Length(9),
        Constraint::Length(9),
        Constraint::Length(16),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(8),
    ];
    let table = Table::new(rows, col_widths)
        .header(header)
        .block(Block::default().borders(Borders::NONE))
        .column_spacing(1);
    f.render_widget(table, chunks[1]);

    // --- Sparkline ---
    let hist: Vec<u64> = state.history.iter().copied().collect();
    let peak = hist.iter().copied().max().unwrap_or(0);
    let spark_title = format!(
        " Throughput MiB/s  ·  peak {}  ·  {} samples ",
        peak,
        hist.len()
    );
    let sparkline = Sparkline::default()
        .block(
            Block::default()
                .title(spark_title)
                .title_style(Style::default().fg(Color::Cyan))
                .borders(Borders::TOP)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .data(&hist)
        .style(Style::default().fg(Color::Green));
    f.render_widget(sparkline, chunks[2]);
}

async fn plain_fallback(
    mut rx: mpsc::Receiver<HashMap<OpKind, Aggregate>>,
    op: OpKind,
    total_duration: Duration,
    start: Instant,
) {
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    loop {
        let mut latest = None;
        tokio::select! {
            _ = interval.tick() => {}
            maybe = rx.recv() => {
                match maybe {
                    None => break,
                    Some(m) => latest = Some(m),
                }
            }
        }
        while let Ok(m) = rx.try_recv() {
            latest = Some(m);
        }
        let elapsed = start.elapsed();
        if elapsed >= total_duration {
            break;
        }
        if let Some(agg_map) = latest {
            let agg = agg_map.get(&op);
            eprintln!(
                "y2q-warp  {op}  {}s / {}s | {} | {}",
                elapsed.as_secs(),
                total_duration.as_secs(),
                agg.map(|a| format!(
                    "{:.1} MiB/s  {:.0} ops/s  {} errors",
                    a.throughput_mibps, a.ops_per_sec, a.n_errors
                ))
                .unwrap_or_else(|| "--".to_owned()),
                agg.map(|a| format!(
                    "P50={}  P90={}  P99={}",
                    ns_to_ms_str(a.p50_ns),
                    ns_to_ms_str(a.p90_ns),
                    ns_to_ms_str(a.p99_ns),
                ))
                .unwrap_or_else(|| "--".to_owned()),
            );
        }
    }
}
