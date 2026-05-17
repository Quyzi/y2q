pub mod plain;
pub mod tui;

use std::collections::VecDeque;
use std::io::IsTerminal;
use std::time::{Duration, Instant};

pub trait ProgressReporter: Send {
    fn start(&mut self, label: &str, total_bytes: Option<u64>);
    fn update(&mut self, bytes_done: u64, speed_bps: u64);
    fn finish(&mut self, bytes_done: u64);
}

pub fn make_reporter(label: &str, total_bytes: Option<u64>) -> Box<dyn ProgressReporter> {
    if std::io::stderr().is_terminal() {
        let mut r = tui::TuiProgressReporter::new();
        r.start(label, total_bytes);
        Box::new(r)
    } else {
        let mut r = plain::PlainProgressReporter::new();
        r.start(label, total_bytes);
        Box::new(r)
    }
}

/// Measures streaming throughput, producing samples every 100ms.
pub struct SpeedMeter {
    window_start: Instant,
    window_bytes: u64,
    pub samples: VecDeque<u64>,
}

impl SpeedMeter {
    pub fn new() -> Self {
        Self {
            window_start: Instant::now(),
            window_bytes: 0,
            samples: VecDeque::with_capacity(60),
        }
    }

    /// Record `bytes` transferred. Returns current speed sample if 100ms window elapsed.
    pub fn record(&mut self, bytes: u64) -> Option<u64> {
        self.window_bytes += bytes;
        let elapsed = self.window_start.elapsed();
        if elapsed >= Duration::from_millis(100) {
            let speed = (self.window_bytes as f64 / elapsed.as_secs_f64()) as u64;
            if self.samples.len() >= 60 {
                self.samples.pop_front();
            }
            self.samples.push_back(speed);
            self.window_bytes = 0;
            self.window_start = Instant::now();
            Some(speed)
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub fn current_speed(&self) -> u64 {
        self.samples.back().copied().unwrap_or(0)
    }
}

impl Default for SpeedMeter {
    fn default() -> Self {
        Self::new()
    }
}

/// Wraps a tokio AsyncRead to count bytes and report progress.
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct CountingReader<R> {
    inner: R,
    bytes_done: u64,
    speed: SpeedMeter,
    reporter: Box<dyn ProgressReporter>,
}

impl<R> CountingReader<R> {
    pub fn new(inner: R, reporter: Box<dyn ProgressReporter>) -> Self {
        Self {
            inner,
            bytes_done: 0,
            speed: SpeedMeter::new(),
            reporter,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for CountingReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let poll = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            let after = buf.filled().len();
            let n = (after - before) as u64;
            if n > 0 {
                this.bytes_done += n;
                if let Some(speed) = this.speed.record(n) {
                    this.reporter.update(this.bytes_done, speed);
                }
            }
        }
        poll
    }
}

impl<R> Drop for CountingReader<R> {
    fn drop(&mut self) {
        self.reporter.finish(self.bytes_done);
    }
}

/// Wraps a tokio AsyncWrite to count bytes written and report progress.
pub struct CountingWriter<W> {
    inner: W,
    bytes_done: u64,
    speed: SpeedMeter,
    reporter: Box<dyn ProgressReporter>,
}

impl<W> CountingWriter<W> {
    pub fn new(inner: W, reporter: Box<dyn ProgressReporter>) -> Self {
        Self {
            inner,
            bytes_done: 0,
            speed: SpeedMeter::new(),
            reporter,
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for CountingWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &poll {
            let n = *n as u64;
            if n > 0 {
                this.bytes_done += n;
                if let Some(speed) = this.speed.record(n) {
                    this.reporter.update(this.bytes_done, speed);
                }
            }
        }
        poll
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.reporter.finish(this.bytes_done);
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}
