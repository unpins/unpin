//! Single-render-thread progress UI (The Elm Architecture).
//!
//! Replaces the per-bar `indicatif` model. **One** render thread owns the
//! terminal and the whole `Model`; workers never touch stderr. They send
//! [`Msg`]s (state transitions) over an mpsc channel and bump per-row byte
//! atomics ([`RowBytes`]); the render thread recomputes the *entire* frame
//! from the Model on every change and repaints it atomically (move to the top
//! of the live block, clear-to-end-of-screen, rewrite). Because there is a
//! single writer and a single source of truth, the redraw-coordination bugs of
//! the old model are gone by construction:
//!
//!   - alignment can't tear (one frame, computed once at a known width);
//!   - a prompt renders *below* the bars, which keep animating: while a prompt
//!     is open the thread repaints only the bar region above it, bracketed in
//!     cursor save/restore so the question and the user's typed input are left
//!     alone (see `Paint::repaint_above`);
//!   - Ctrl-C preserves finished rows and clears in-progress ones (the final
//!     frame is just the Model filtered to its `Done` rows).
//!
//! The split that keeps this testable: [`render_lines`] is a **pure** function
//! `Model → Vec<String>` (unit-tested with `color = false`); the thin paint
//! step that emits cursor-control bytes is exercised only by the pty smoke.

use std::collections::VecDeque;
use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use crate::github::ByteSink;
use crate::install::prompt::{PromptResult, plain_pick, plain_yes_no};

/// Spinner frames (braille), advanced once per render tick.
const SPIN: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
/// Download bar width in cells. Matches the old `{bar:14}` template.
const BAR_W: usize = 14;
/// Narrowest bar still worth drawing. Below this the bar is dropped entirely
/// rather than shrunk to a meaningless stub.
const MIN_BAR: usize = 4;
/// Render tick. Drives spinner animation and rate sampling.
const TICK: Duration = Duration::from_millis(80);
/// Window the displayed download rate is averaged over. Long enough to smooth
/// out lumpy arrivals (TLS records, throttled links), short enough to still
/// track a real speed change within a few seconds.
const RATE_WINDOW: Duration = Duration::from_secs(3);

// ---------------------------------------------------------------------------
// Shared byte counters (the one thing workers mutate concurrently)
// ---------------------------------------------------------------------------

/// Per-download counters shared between a worker (writer) and the render
/// thread (reader). `total == 0` means "length unknown" → spinner-mode bar.
/// `rate` is a bytes/sec figure the render thread writes each tick (stored as
/// `f64` bits) and `render_lines` reads — keeping rate out of the Model so the
/// pure renderer stays a function of explicit inputs.
pub struct RowBytes {
    done: AtomicU64,
    total: AtomicU64,
    rate: AtomicU64,
    /// `(timestamp, done)` samples within the rate window, touched only by the
    /// render thread (in `sample_rates`). The displayed rate is the average
    /// over this window — see [`RATE_WINDOW`] — which is far steadier than an
    /// instantaneous figure when bytes arrive in lumps (TLS records, throttled
    /// links). The `Mutex` is uncontended (workers never read it).
    samples: Mutex<VecDeque<(Instant, u64)>>,
}

impl RowBytes {
    fn new(hint: u64) -> Arc<Self> {
        Arc::new(Self {
            done: AtomicU64::new(0),
            total: AtomicU64::new(hint),
            rate: AtomicU64::new(0),
            samples: Mutex::new(VecDeque::new()),
        })
    }
    fn done(&self) -> u64 {
        self.done.load(Ordering::Relaxed)
    }
    fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }
    fn rate(&self) -> f64 {
        f64::from_bits(self.rate.load(Ordering::Relaxed))
    }
    fn set_rate(&self, r: f64) {
        self.rate.store(r.to_bits(), Ordering::Relaxed);
    }
    /// Record `done` at `now`, drop samples older than [`RATE_WINDOW`], and
    /// recompute the windowed average rate. Render-thread only.
    fn sample_rate(&self, now: Instant) {
        let done = self.done();
        let mut w = self.samples.lock().unwrap_or_else(|e| e.into_inner());
        w.push_back((now, done));
        while let Some(&(t, _)) = w.front() {
            if now.duration_since(t) > RATE_WINDOW {
                w.pop_front();
            } else {
                break;
            }
        }
        let rate = match (w.front(), w.back()) {
            (Some(&(t0, b0)), Some(&(t1, b1))) => {
                let secs = t1.duration_since(t0).as_secs_f64();
                if secs > 0.0 {
                    b1.saturating_sub(b0) as f64 / secs
                } else {
                    0.0
                }
            }
            _ => 0.0,
        };
        self.set_rate(rate);
    }
}

impl ByteSink for RowBytes {
    fn hint(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }
    fn set_total(&self, total: u64) {
        self.total.store(total, Ordering::Relaxed);
    }
    fn set_unknown(&self) {
        self.total.store(0, Ordering::Relaxed);
    }
    fn add(&self, n: u64) {
        self.done.fetch_add(n, Ordering::Relaxed);
    }
    fn loaded(&self) -> u64 {
        self.done.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

/// Terminal outcome of a row. Drives the final glyph + color.
pub enum Outcome {
    /// Green ✓ — installed/updated/up-to-date.
    Ok(String),
    /// Yellow ⚠ — installed, but the download had no published checksum to
    /// verify against.
    Warn(String),
    /// Yellow ⊘ — user-skipped, non-fatal.
    Skip(String),
    /// Red ✗ — hard failure.
    Fail(String),
}

/// What a row is doing right now.
enum Phase {
    /// Spinner + free-text message (Queued / Resolving / Linking / Waiting…).
    Idle(String),
    /// Live download against shared counters.
    Download(Arc<RowBytes>),
    /// Frozen red bar at the failure point (run-path primary, companion error).
    DownloadFailed(Arc<RowBytes>, String),
    /// Settled final state.
    Done(Outcome),
    /// Row removed from the display (single-package `run` after a clean
    /// download — the binary then runs, so no leftover line).
    Cleared,
}

struct Row {
    prefix: String,
    phase: Phase,
}

/// Everything on screen. The render thread owns the only instance; workers
/// mutate it indirectly via [`Msg`]. A companion (data tarball) download is a
/// transient extra row appended after the fixed per-request rows.
struct Model {
    rows: Vec<Row>,
    companions: Vec<(u64, Row)>,
    /// Extra lines rendered *below* the bars while a prompt is open.
    prompt: Option<Vec<String>>,
}

impl Model {
    /// Bounds-checked so a stale or out-of-range `idx` from a worker drops the
    /// update instead of panicking the render thread — a panic there would tear
    /// down the channel and silently freeze the whole UI (every `tx.send`
    /// becomes a no-op) with no diagnostic.
    fn row_mut(&mut self, idx: usize) -> Option<&mut Row> {
        self.rows.get_mut(idx)
    }
}

// ---------------------------------------------------------------------------
// Pure rendering: Model -> lines
// ---------------------------------------------------------------------------

/// A colour applied to one text segment. `Plain` is left uncoloured.
#[derive(Clone, Copy)]
enum C {
    Plain,
    Cyan,
    Green,
    Yellow,
    Red,
    Blue,
}

/// Honour `NO_COLOR` (https://no-color.org/): when the variable is present —
/// regardless of its value — colour output is disabled. We decide this
/// ourselves rather than leaning on `console`'s implicit detection, which keys
/// off stdout while the live block writes to stderr.
fn colors_enabled() -> bool {
    std::env::var_os("NO_COLOR").is_none()
}

fn style_seg(s: &str, c: C, color: bool) -> String {
    if !color {
        return s.to_string();
    }
    use console::style;
    match c {
        C::Plain => s.to_string(),
        C::Cyan => style(s).cyan().to_string(),
        C::Green => style(s).green().to_string(),
        C::Yellow => style(s).yellow().to_string(),
        C::Red => style(s).red().to_string(),
        C::Blue => style(s).blue().to_string(),
    }
}

/// Join coloured segments into one line clamped to `width` *display* columns
/// (truncating the plain text of each segment, never an ANSI escape mid-
/// sequence). A cut is **always** signalled with a single trailing `…`: when
/// the segments overflow we fill to `width - 1` and append the marker, so even
/// the case where an earlier segment lands exactly on `width` and a later one
/// would otherwise be dropped still gets a `…` rather than vanishing silently.
/// Download rows pre-fit their segments (see [`fit_download`]) so they take the
/// fits-whole path; this fallback mostly catches over-long idle/done messages.
fn compose(segs: &[(String, C)], width: usize, color: bool) -> String {
    if width == 0 {
        return String::new();
    }
    let total: usize = segs
        .iter()
        .map(|(t, _)| console::measure_text_width(t))
        .sum();
    if total <= width {
        // Fits whole — emit every segment untouched.
        let mut out = String::new();
        for (text, c) in segs {
            out.push_str(&style_seg(text, *c, color));
        }
        return out;
    }
    // Overflow: reserve the last column for the marker, fill the rest, append `…`.
    let budget = width - 1;
    let mut out = String::new();
    let mut used = 0usize;
    for (text, c) in segs {
        if used >= budget {
            break;
        }
        let w = console::measure_text_width(text);
        let piece = if used + w <= budget {
            text.clone()
        } else {
            console::truncate_str(text, budget - used, "").into_owned()
        };
        used += console::measure_text_width(&piece);
        out.push_str(&style_seg(&piece, *c, color));
    }
    out.push_str(&style_seg("…", C::Plain, color));
    out
}

/// Truncate `s` to at most `width` display columns, appending `…` when (and
/// only when) it had to cut — never trailing the marker onto text that fit.
fn ellipsize(s: &str, width: usize) -> String {
    if console::measure_text_width(s) <= width {
        s.to_string()
    } else {
        console::truncate_str(s, width, "…").into_owned()
    }
}

/// Binary-unit byte formatter (`1.50 KiB`), shared with the asset picker.
pub fn human_bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.2} {}", U[i])
    }
}

fn rate_str(r: f64) -> String {
    if r > 0.5 {
        format!("{}/s", human_bytes(r as u64))
    } else {
        String::new()
    }
}

/// `bar_w`-cell bar split into filled (green) + empty (blue) segments.
fn bar_segs(done: u64, total: u64, bar_w: usize, fill: C, rest: C) -> [(String, C); 2] {
    let frac = if total > 0 {
        (done as f64 / total as f64).clamp(0.0, 1.0)
    } else {
        0.0
    };
    let filled = (frac * bar_w as f64).round() as usize;
    let filled = filled.min(bar_w);
    [
        ("▰".repeat(filled), fill),
        ("▱".repeat(bar_w - filled), rest),
    ]
}

fn pct(done: u64, total: u64) -> u64 {
    if total > 0 {
        ((done as u128 * 100 / total as u128) as u64).min(100)
    } else {
        0
    }
}

/// Right-pad `s` with spaces to `width` display columns (never truncates).
fn pad_to(s: &str, width: usize) -> String {
    let w = console::measure_text_width(s);
    if w >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - w))
    }
}

/// Total display width of a segment list.
fn segs_width(segs: &[(String, C)]) -> usize {
    segs.iter()
        .map(|(t, _)| console::measure_text_width(t))
        .sum()
}

/// Build the segments for a known-length download at a chosen level of detail:
/// `bar` is the bar width (`None` drops the bar), `bytes`/`rate` toggle the
/// `done/total` and rate columns. Used by [`fit_download`] to try successively
/// terser layouts until one fits.
fn dl_known_segs(
    p: &str,
    done: u64,
    total: u64,
    rate: f64,
    bar: Option<usize>,
    bytes: bool,
    rate_on: bool,
) -> Vec<(String, C)> {
    let mut segs = vec![(format!("  {p}  "), C::Cyan)];
    match bar {
        Some(bw) => {
            let [fseg, eseg] = bar_segs(done, total, bw, C::Green, C::Blue);
            segs.push(fseg);
            segs.push(eseg);
            segs.push((format!(" {:>3}%", pct(done, total)), C::Plain));
        }
        None => segs.push((format!("{:>3}%", pct(done, total)), C::Plain)),
    }
    if bytes {
        segs.push((
            format!("  {:>9}/{:<9}", human_bytes(done), human_bytes(total)),
            C::Plain,
        ));
    }
    if rate_on {
        let r = rate_str(rate);
        if !r.is_empty() {
            segs.push((format!("  {r}"), C::Plain));
        }
    }
    segs
}

/// Build the segments for an unknown-length download (spinner + byte count,
/// no bar) at a chosen level of detail.
fn dl_unknown_segs(
    p: &str,
    spin: &str,
    done: u64,
    rate: f64,
    bytes: bool,
    rate_on: bool,
) -> Vec<(String, C)> {
    let mut segs = vec![
        (format!("  {p}  "), C::Cyan),
        (format!("{spin}  "), C::Plain),
    ];
    if bytes {
        segs.push((format!("{:>9}", human_bytes(done)), C::Plain));
    }
    if rate_on {
        let r = rate_str(rate);
        if !r.is_empty() {
            segs.push((format!("  {r}"), C::Plain));
        }
    }
    segs
}

/// The minimal download row: prefix + percentage, with the prefix ellipsized
/// when even that doesn't fit. The floor every other layout degrades toward —
/// it never silently truncates (the `…` from [`ellipsize`] signals the cut).
fn dl_minimal_segs(p: &str, done: u64, total: u64, width: usize) -> Vec<(String, C)> {
    let pct_s = format!("{:>3}%", pct(done, total));
    let pct_w = pct_s.chars().count();
    let reserve = 2 + 2 + pct_w; // indent + gap + percentage
    if width > reserve {
        let pe = ellipsize(p.trim_end(), width - reserve);
        vec![(format!("  {pe}  "), C::Cyan), (pct_s, C::Plain)]
    } else {
        // Too narrow even for the percentage: prefix alone, ellipsized.
        vec![(ellipsize(p.trim_end(), width), C::Cyan)]
    }
}

/// Fit a download row into `width` columns by trying progressively terser
/// layouts and taking the first that fits: full detail → drop rate → drop
/// byte counts → shrink the bar down to [`MIN_BAR`] → drop the bar (prefix +
/// percentage) → ellipsize the prefix. The bar shrinks before it vanishes and
/// no text is ever cut without a `…`, so a narrow terminal degrades gracefully
/// instead of hard-truncating.
fn fit_download(
    p: &str,
    spin: &str,
    done: u64,
    total: u64,
    rate: f64,
    width: usize,
) -> Vec<(String, C)> {
    if total == 0 {
        for (bytes, rate_on) in [(true, true), (true, false), (false, false)] {
            let segs = dl_unknown_segs(p, spin, done, rate, bytes, rate_on);
            if segs_width(&segs) <= width {
                return segs;
            }
        }
        return dl_unknown_segs(p, spin, done, rate, false, false);
    }
    // Richest first, then peel off rate, then byte counts, then narrow the bar.
    let mut attempts: Vec<(Option<usize>, bool, bool)> = vec![
        (Some(BAR_W), true, true),
        (Some(BAR_W), true, false),
        (Some(BAR_W), false, false),
    ];
    attempts.extend((MIN_BAR..BAR_W).rev().map(|bw| (Some(bw), false, false)));
    attempts.push((None, false, false));
    for (bar, bytes, rate_on) in attempts {
        let segs = dl_known_segs(p, done, total, rate, bar, bytes, rate_on);
        if segs_width(&segs) <= width {
            return segs;
        }
    }
    dl_minimal_segs(p, done, total, width)
}

/// Render one row, its prefix padded to `pad` columns so the spinner/bar/glyph
/// column lines up with every other row in the frame.
fn render_row(row: &Row, width: usize, frame: usize, color: bool, pad: usize) -> String {
    let spin = SPIN[frame % SPIN.len()];
    let p = pad_to(&row.prefix, pad);
    let segs: Vec<(String, C)> = match &row.phase {
        Phase::Idle(msg) => vec![
            (format!("  {p}  "), C::Cyan),
            (format!("{spin}  "), C::Green),
            (msg.clone(), C::Plain),
        ],
        Phase::Download(b) => {
            // Width-aware: shrink/drop the bar and trailing columns to fit
            // rather than letting `compose` hard-cut the line.
            fit_download(&p, spin, b.done(), b.total(), b.rate(), width)
        }
        Phase::DownloadFailed(b, msg) => {
            let [fseg, eseg] = bar_segs(b.done(), b.total(), BAR_W, C::Red, C::Red);
            vec![
                (format!("  {p}  "), C::Red),
                fseg,
                eseg,
                (format!(" {:>3}%  ", pct(b.done(), b.total())), C::Red),
                (msg.clone(), C::Red),
            ]
        }
        Phase::Done(Outcome::Ok(msg)) => {
            vec![(format!("  {p}  ✓  "), C::Green), (msg.clone(), C::Green)]
        }
        Phase::Done(Outcome::Warn(msg)) => {
            vec![(format!("  {p}  ⚠  "), C::Yellow), (msg.clone(), C::Yellow)]
        }
        Phase::Done(Outcome::Skip(msg)) => {
            vec![(format!("  {p}  ⊘  "), C::Yellow), (msg.clone(), C::Yellow)]
        }
        Phase::Done(Outcome::Fail(msg)) => {
            vec![(format!("  {p}  ✗  "), C::Red), (msg.clone(), C::Red)]
        }
        // Filtered out by `render_lines`; never composed.
        Phase::Cleared => Vec::new(),
    };
    compose(&segs, width, color)
}

/// Pure frame: the whole live block as plain (or coloured) lines. Unit-tested
/// with `color = false`; the render thread calls it with `color = true`.
///
/// Prefixes are padded to a single column width computed over *this frame's*
/// visible rows (+ companions) — left-aligned bars with no fixed/hardcoded
/// width. Because the frame is computed once, the alignment can never tear: the
/// pad either fits every row or none, never a mix.
#[cfg(test)]
fn render_lines(model: &Model, width: usize, frame: usize, color: bool) -> Vec<String> {
    let mut lines = render_block(model, width, frame, color);
    lines.extend(render_prompt(model, width, color));
    lines
}

/// Clamp a frame (bar `block` lines + `prompt` lines) to the viewport,
/// **bottom-anchored**: the prompt and the most recent rows always stay
/// visible; when the frame is taller than `height`, the earliest bar rows are
/// dropped and replaced with a one-line "… N more above" marker.
///
/// This is the load-bearing invariant for correctness: the drawn region is
/// kept to `height - 1` lines, so the cursor-up in every repaint can always
/// reach the region's true top (it never hits the terminal's top margin), and
/// the clear-to-end-of-screen therefore always wipes the *whole* previous
/// frame. Without it, once the region scrolls past the top of the screen the
/// relative cursor math drifts and earlier frames strand on screen.
///
/// Returns the lines to draw plus how many trailing lines are the prompt (so
/// the in-place prompt repaint knows which lines to leave alone).
fn clamp_frame(block: Vec<String>, prompt: Vec<String>, height: usize) -> (Vec<String>, usize) {
    let p = prompt.len();
    // One spare line so a stray scroll can't push the top off the screen.
    let cap = height.saturating_sub(1).max(1);
    if block.len() + p <= cap {
        let mut lines = block;
        lines.extend(prompt);
        return (lines, p);
    }
    // Overflow: a marker + as many trailing bar rows as fit + the whole prompt.
    let keep = cap.saturating_sub(p + 1);
    let dropped = block.len().saturating_sub(keep);
    let mut lines = Vec::with_capacity(cap);
    lines.push(format!("  … {dropped} more above"));
    lines.extend(block.into_iter().skip(dropped));
    lines.extend(prompt);
    (lines, p)
}

/// Render the prompt lines (empty when no prompt is open).
fn render_prompt(model: &Model, width: usize, color: bool) -> Vec<String> {
    model
        .prompt
        .iter()
        .flatten()
        .map(|l| compose(&[(l.clone(), C::Plain)], width, color))
        .collect()
}

/// Just the bar rows (+ companions), without the prompt lines. The render
/// thread repaints *only* this region while a prompt is open, leaving the
/// prompt + the user's typed input untouched (via cursor save/restore) so the
/// bars keep animating during the prompt.
fn render_block(model: &Model, width: usize, frame: usize, color: bool) -> Vec<String> {
    let live = || {
        model
            .rows
            .iter()
            .filter(|r| !matches!(r.phase, Phase::Cleared))
            .chain(model.companions.iter().map(|(_, r)| r))
    };
    let pad = live()
        .map(|r| console::measure_text_width(&r.prefix))
        .max()
        .unwrap_or(0);
    live()
        .map(|r| render_row(r, width, frame, color, pad))
        .collect()
}

// ---------------------------------------------------------------------------
// Messages (worker -> render thread)
// ---------------------------------------------------------------------------

enum Msg {
    /// Append a Queued row (Model construction stays on the render thread).
    Init(String),
    Phase(usize, Phase),
    Prefix(usize, String),
    AddCompanion(u64, String, Arc<RowBytes>),
    FinishCompanion(u64, Result<(), String>),
    Log(String),
    /// Show prompt lines below the bars; ack once drawn + paused.
    PromptShow(Vec<String>, mpsc::Sender<()>),
    /// Clear the prompt and resume; ack once redrawn.
    PromptHide(mpsc::Sender<()>),
    /// Final freeze frame (keep `Done` rows, print "interrupted"); ack.
    Interrupt(mpsc::Sender<()>),
    /// Clean teardown (trailing newline so the shell prompt is fresh); ack.
    Shutdown(mpsc::Sender<()>),
}

// ---------------------------------------------------------------------------
// Screen abstraction (real terminal vs. null for non-TTY)
// ---------------------------------------------------------------------------

struct Screen {
    /// `None` when stderr isn't a terminal — every paint is a no-op.
    term: Option<console::Term>,
    /// Whether ANSI colour is emitted. False on a non-terminal *and* whenever
    /// `NO_COLOR` is set (https://no-color.org/), even on a real TTY.
    color: bool,
}

impl Screen {
    fn new(tty: bool) -> Self {
        Self {
            term: tty.then(console::Term::stderr),
            color: tty && colors_enabled(),
        }
    }
    fn size(&self) -> (usize, usize) {
        match &self.term {
            Some(t) => {
                let (rows, cols) = t.size();
                (rows as usize, (cols as usize).max(1))
            }
            None => (24, 80),
        }
    }
    fn is_null(&self) -> bool {
        self.term.is_none()
    }
    fn write(&self, s: &str) {
        // Bypass console's line buffering; we emit raw cursor-control bytes.
        let mut err = io::stderr().lock();
        let _ = err.write_all(s.as_bytes());
        let _ = err.flush();
    }
}

/// Paint bookkeeping: how many lines the live block last occupied and where
/// the cursor sits relative to the block top.
struct Paint {
    drawn: usize,
    cursor_row: usize,
}

impl Paint {
    fn new() -> Self {
        Self {
            drawn: 0,
            cursor_row: 0,
        }
    }

    /// Repaint the whole frame, optionally scrolling `logs` into history above
    /// it. Algorithm: move to the region top, clear to end of screen, write the
    /// log lines (each ends a line so it stays as scrollback), then the new
    /// frame. `lines` must already be clamped to the viewport (see
    /// [`clamp_frame`]) so the move-up always reaches the true top — a single
    /// writer + clear-to-EOS then means no per-line diffing and no torn frames.
    fn repaint(&mut self, screen: &Screen, lines: &[String], logs: &mut Vec<String>) {
        if screen.is_null() {
            logs.clear();
            return;
        }
        let mut out = String::new();
        if self.cursor_row > 0 {
            out.push_str(&format!("\x1b[{}A", self.cursor_row));
        }
        out.push('\r');
        out.push_str("\x1b[J"); // clear from cursor to end of screen
        for log in logs.drain(..) {
            out.push_str(&log);
            out.push_str("\x1b[K\n");
        }
        for (i, l) in lines.iter().enumerate() {
            out.push_str(l);
            if i + 1 < lines.len() {
                out.push('\n');
            }
        }
        self.drawn = lines.len();
        self.cursor_row = lines.len().saturating_sub(1);
        screen.write(&out);
    }

    /// Refresh only the bar region *above* an open prompt, leaving the prompt
    /// lines and the user's typed input untouched. `shown` is the full clamped
    /// frame and `n_prompt` how many of its trailing lines are the prompt; only
    /// the leading `shown.len() - n_prompt` bar lines are rewritten.
    ///
    /// Brackets the redraw in cursor save/restore (`ESC 7`/`ESC 8`): save where
    /// the user is typing, jump up to the region top, rewrite each bar line
    /// (clear-to-EOL, never clear-to-EOS — that would wipe the prompt), restore
    /// the cursor. Needs the bar-line count stable, which the loop guarantees by
    /// deferring companion add/remove while a prompt is open. A keystroke echoed
    /// into the bar region during the tiny redraw window self-heals next tick.
    fn repaint_above(&self, screen: &Screen, shown: &[String], n_prompt: usize) {
        let bars = shown.len().saturating_sub(n_prompt);
        if screen.is_null() || self.cursor_row == 0 || bars == 0 {
            return;
        }
        let mut out = String::from("\x1b7"); // save cursor (typing position)
        out.push_str(&format!("\x1b[{}A\r", self.cursor_row)); // up to region top
        for (i, l) in shown.iter().take(bars).enumerate() {
            out.push_str(l);
            out.push_str("\x1b[K");
            if i + 1 < bars {
                out.push('\n');
            }
        }
        out.push_str("\x1b8"); // restore cursor
        screen.write(&out);
    }

    /// Emit a trailing newline so the cursor leaves the block and the shell
    /// prompt starts on a fresh line — unless the block is empty (every row
    /// cleared), in which case the cursor already sits on a clean line.
    fn finish(&mut self, screen: &Screen) {
        if !screen.is_null() && self.drawn > 0 {
            screen.write("\n");
        }
    }
}

// ---------------------------------------------------------------------------
// Render thread
// ---------------------------------------------------------------------------

fn render_loop(rx: mpsc::Receiver<Msg>, tty: bool) {
    let screen = Screen::new(tty);
    let mut model = Model {
        rows: Vec::new(),
        companions: Vec::new(),
        prompt: None,
    };
    let mut paint = Paint::new();
    let mut logs: Vec<String> = Vec::new();
    // Companion add/remove that arrives while a prompt is open. Applying it
    // live would change the bar-line count under the prompt and break the
    // in-place `repaint_above`; held here and flushed when the prompt closes.
    let mut deferred: Vec<Msg> = Vec::new();
    let mut frame = 0usize;

    loop {
        match rx.recv_timeout(TICK) {
            Ok(m) => {
                if process_one(
                    m,
                    &mut model,
                    &mut paint,
                    &screen,
                    &mut logs,
                    &mut deferred,
                    frame,
                ) {
                    return; // Interrupt/Shutdown handled the final frame.
                }
                while let Ok(m) = rx.try_recv() {
                    if process_one(
                        m,
                        &mut model,
                        &mut paint,
                        &screen,
                        &mut logs,
                        &mut deferred,
                        frame,
                    ) {
                        return;
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
        frame = frame.wrapping_add(1);
        sample_rates(&model);
        let (shown, n_prompt) = full_frame(&model, &screen, frame);
        if model.prompt.is_some() {
            // Prompt open: animate only the bars above it, leave the question
            // and the user's typed input alone.
            paint.repaint_above(&screen, &shown, n_prompt);
        } else {
            paint.repaint(&screen, &shown, &mut logs);
        }
    }
}

/// The clamped, viewport-fitted frame the render thread draws: bar block +
/// prompt, bottom-anchored to the terminal height. Returns the lines plus how
/// many trailing lines are the prompt.
fn full_frame(model: &Model, screen: &Screen, frame: usize) -> (Vec<String>, usize) {
    let (height, width) = screen.size();
    let block = render_block(model, width, frame, screen.color);
    let prompt = render_prompt(model, width, screen.color);
    clamp_frame(block, prompt, height)
}

/// Dispatch one message, with two loop-level concerns layered over [`handle`]:
/// defer structural companion changes while a prompt is open (so the
/// bar-line count under the prompt stays put), and flush those deferred
/// changes the moment the prompt closes.
fn process_one(
    m: Msg,
    model: &mut Model,
    paint: &mut Paint,
    screen: &Screen,
    logs: &mut Vec<String>,
    deferred: &mut Vec<Msg>,
    frame: usize,
) -> bool {
    if model.prompt.is_some() && matches!(m, Msg::AddCompanion(..) | Msg::FinishCompanion(..)) {
        deferred.push(m);
        return false;
    }
    let was_prompt = model.prompt.is_some();
    let exit = handle(m, model, paint, screen, logs, frame);
    if was_prompt && model.prompt.is_none() {
        for dm in std::mem::take(deferred) {
            handle(dm, model, paint, screen, logs, frame);
        }
    }
    exit
}

/// Re-sample each live download's rate from its sliding window (see
/// [`RowBytes::sample_rate`]). The displayed figure is the average over
/// [`RATE_WINDOW`], which stays steady even when bytes arrive in lumps.
fn sample_rates(model: &Model) {
    let now = Instant::now();
    for r in &model.rows {
        if let Phase::Download(b) = &r.phase {
            b.sample_rate(now);
        }
    }
    for (_, r) in &model.companions {
        if let Phase::Download(b) = &r.phase {
            b.sample_rate(now);
        }
    }
}

/// Collapse the Model to its interrupt freeze frame: keep only finished rows,
/// drop every in-progress row, companion, and open prompt. The user's "preserve
/// finished lines, clear what's in flight" Ctrl-C contract, made testable.
fn freeze_model(model: &mut Model) {
    model.rows.retain(|r| matches!(r.phase, Phase::Done(_)));
    model.companions.clear();
    model.prompt = None;
}

/// Handle one message. Returns `true` when the loop should exit (the final
/// frame has been painted).
fn handle(
    m: Msg,
    model: &mut Model,
    paint: &mut Paint,
    screen: &Screen,
    logs: &mut Vec<String>,
    frame: usize,
) -> bool {
    match m {
        Msg::Init(prefix) => model.rows.push(Row {
            prefix,
            phase: Phase::Idle("Queued".into()),
        }),
        Msg::Phase(idx, phase) => {
            if let Some(r) = model.row_mut(idx) {
                r.phase = phase;
            }
        }
        Msg::Prefix(idx, p) => {
            if let Some(r) = model.row_mut(idx) {
                r.prefix = p;
            }
        }
        Msg::AddCompanion(id, prefix, bytes) => model.companions.push((
            id,
            Row {
                prefix,
                phase: Phase::Download(bytes),
            },
        )),
        Msg::FinishCompanion(id, result) => match result {
            Ok(()) => model.companions.retain(|(cid, _)| *cid != id),
            Err(e) => {
                if let Some((_, row)) = model.companions.iter_mut().find(|(cid, _)| *cid == id)
                    && let Phase::Download(b) = &row.phase
                {
                    row.phase = Phase::DownloadFailed(b.clone(), e);
                }
            }
        },
        Msg::Log(line) => logs.push(line),
        Msg::PromptShow(lines, ack) => {
            // Draw the question as the last block line(s) and park the cursor
            // there. From now the loop repaints only the bars *above* this, so
            // they keep animating while the user reads/types.
            model.prompt = Some(lines);
            let (shown, _) = full_frame(model, screen, frame);
            paint.repaint(screen, &shown, logs);
            let _ = ack.send(());
            return false;
        }
        Msg::PromptHide(ack) => {
            model.prompt = None;
            // The user's Enter dropped the cursor one line below the block.
            paint.cursor_row += 1;
            let (shown, _) = full_frame(model, screen, frame);
            paint.repaint(screen, &shown, logs);
            let _ = ack.send(());
            return false;
        }
        Msg::Interrupt(ack) => {
            // Keep finished rows, drop in-progress ones, and leave the cursor
            // on a fresh line. The SIGINT handler prints "interrupted" itself
            // (exactly once) so a slow ack here can't double the message.
            freeze_model(model);
            let (shown, _) = full_frame(model, screen, frame);
            paint.repaint(screen, &shown, logs);
            paint.finish(screen);
            let _ = ack.send(());
            return true;
        }
        Msg::Shutdown(ack) => {
            let (shown, _) = full_frame(model, screen, frame);
            paint.repaint(screen, &shown, logs);
            paint.finish(screen);
            let _ = ack.send(());
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Reporter / Handle / Ui (worker-facing API)
// ---------------------------------------------------------------------------

/// Global hook the SIGINT handler uses to ask the live render thread for a
/// freeze frame before the process exits. `None` when no UI is running.
static INTERRUPT_HOOK: Mutex<Option<mpsc::Sender<Msg>>> = Mutex::new(None);

/// Cloneable worker-side handle to the live render thread. Every method is a
/// thin message send; byte progress flows through the [`RowBytes`] this hands
/// back from [`Reporter::start_download`].
#[derive(Clone)]
pub struct Reporter {
    tx: mpsc::Sender<Msg>,
    /// stderr is a terminal (bars are actually drawn). Prompts fall back to a
    /// plain stdin read when this is false.
    tty: bool,
    next_companion: Arc<AtomicU64>,
}

impl Reporter {
    /// Switch a row to a spinner + message (Queued / Resolving / Linking…).
    pub fn working(&self, idx: usize, msg: impl Into<String>) {
        let _ = self.tx.send(Msg::Phase(idx, Phase::Idle(msg.into())));
    }
    pub fn set_prefix(&self, idx: usize, prefix: impl Into<String>) {
        let _ = self.tx.send(Msg::Prefix(idx, prefix.into()));
    }
    /// Switch a row to a live download bar. Returns the shared counters to
    /// hand to [`crate::github::download_stream_into`].
    pub fn start_download(
        &self,
        idx: usize,
        prefix: impl Into<String>,
        hint: u64,
    ) -> Arc<RowBytes> {
        let bytes = RowBytes::new(hint);
        let _ = self.tx.send(Msg::Prefix(idx, prefix.into()));
        let _ = self
            .tx
            .send(Msg::Phase(idx, Phase::Download(bytes.clone())));
        bytes
    }
    /// Freeze a primary download row as a red bar at the failure point (the
    /// single-package `run` path; the pipeline uses [`Reporter::done_fail`]).
    pub fn download_failed(&self, idx: usize, bytes: Arc<RowBytes>, msg: impl Into<String>) {
        let _ = self
            .tx
            .send(Msg::Phase(idx, Phase::DownloadFailed(bytes, msg.into())));
    }
    pub fn done_ok(&self, idx: usize, msg: impl Into<String>) {
        let _ = self
            .tx
            .send(Msg::Phase(idx, Phase::Done(Outcome::Ok(msg.into()))));
    }
    /// Installed, but the download had no published checksum (yellow ⚠).
    pub fn done_warn(&self, idx: usize, msg: impl Into<String>) {
        let _ = self
            .tx
            .send(Msg::Phase(idx, Phase::Done(Outcome::Warn(msg.into()))));
    }
    pub fn done_skip(&self, idx: usize, msg: impl Into<String>) {
        let _ = self
            .tx
            .send(Msg::Phase(idx, Phase::Done(Outcome::Skip(msg.into()))));
    }
    pub fn done_fail(&self, idx: usize, msg: impl Into<String>) {
        let _ = self
            .tx
            .send(Msg::Phase(idx, Phase::Done(Outcome::Fail(msg.into()))));
    }
    /// Remove a row from the display (run-path success: the binary runs next).
    pub fn clear(&self, idx: usize) {
        let _ = self.tx.send(Msg::Phase(idx, Phase::Cleared));
    }
    /// Add a transient companion (data tarball) download row. Returns its id
    /// (for [`Reporter::finish_companion`]) and shared counters.
    pub fn add_companion(&self, prefix: impl Into<String>, hint: u64) -> (u64, Arc<RowBytes>) {
        let id = self.next_companion.fetch_add(1, Ordering::Relaxed);
        let bytes = RowBytes::new(hint);
        let _ = self
            .tx
            .send(Msg::AddCompanion(id, prefix.into(), bytes.clone()));
        (id, bytes)
    }
    /// Clear a companion row on success, or freeze it red on failure.
    pub fn finish_companion(&self, id: u64, result: Result<(), String>) {
        let _ = self.tx.send(Msg::FinishCompanion(id, result));
    }
    /// Print a line into history *above* the live block.
    pub fn log(&self, msg: impl Into<String>) {
        let _ = self.tx.send(Msg::Log(msg.into()));
    }

    /// Yes/no prompt rendered below the bars (they stay visible). Falls back to
    /// a plain stderr prompt when stderr isn't a terminal; auto-skips a
    /// non-interactive stdin.
    fn prompt_yes_no(&self, question: &str) -> PromptResult<bool> {
        if !io::stdin().is_terminal() {
            return PromptResult::Skip;
        }
        if !self.tty {
            return plain_yes_no(question);
        }
        self.with_prompt(vec![format!("{question} [y/N] ")], || {
            let mut line = String::new();
            if io::stdin().read_line(&mut line).is_err() || line.is_empty() {
                return PromptResult::Skip;
            }
            match line.trim_start().chars().next() {
                Some('y') | Some('Y') => PromptResult::Got(true),
                _ => PromptResult::Got(false),
            }
        })
    }

    /// Numbered picker rendered below the bars. Type a number + Enter; an empty
    /// or out-of-range line skips. (The live path is numeric rather than
    /// arrow-driven so the render thread fully owns every drawn line and can
    /// clear it exactly — no `dialoguer` redraws racing the bars.)
    fn prompt_pick(&self, header: &str, items: &[String]) -> PromptResult<usize> {
        if items.is_empty() || !io::stdin().is_terminal() {
            return PromptResult::Skip;
        }
        if !self.tty {
            return plain_pick(header, items);
        }
        let mut lines = vec![header.to_string()];
        for (i, it) in items.iter().enumerate() {
            lines.push(format!("  {}) {it}", i + 1));
        }
        lines.push(format!("Enter number [1-{}]: ", items.len()));
        let n = items.len();
        self.with_prompt(lines, || {
            let mut line = String::new();
            if io::stdin().read_line(&mut line).is_err() {
                return PromptResult::Skip;
            }
            match line.trim().parse::<usize>() {
                Ok(k) if (1..=n).contains(&k) => PromptResult::Got(k - 1),
                _ => PromptResult::Skip,
            }
        })
    }

    /// Drive the show → read → hide handshake with the render thread. The acks
    /// are bounded so a wedged render thread can't hang the worker forever: the
    /// thread acks within a tick in practice, so on a timeout we just proceed
    /// (read stdin anyway / return) rather than block indefinitely. `read`
    /// itself blocks on the user's input — that's the expected wait, not this.
    fn with_prompt<T>(&self, lines: Vec<String>, read: impl FnOnce() -> T) -> T {
        let (ack_tx, ack_rx) = mpsc::channel();
        let _ = self.tx.send(Msg::PromptShow(lines, ack_tx));
        let _ = ack_rx.recv_timeout(Duration::from_secs(2));
        let result = read();
        let (h_tx, h_rx) = mpsc::channel();
        let _ = self.tx.send(Msg::PromptHide(h_tx));
        let _ = h_rx.recv_timeout(Duration::from_secs(2));
        result
    }
}

/// Owner of the render thread. Dropping it (via [`Handle::finish`]) tears the
/// thread down cleanly and prints the trailing newline.
pub struct Handle {
    tx: mpsc::Sender<Msg>,
    join: Option<thread::JoinHandle<()>>,
}

impl Handle {
    /// Clean teardown: final repaint + trailing newline, then join.
    pub fn finish(mut self) {
        // Detach the SIGINT freeze hook *before* tearing down. Otherwise a
        // Ctrl-C landing between the render thread exiting and the hook being
        // cleared would make `interrupt_freeze` send `Interrupt` to a gone
        // receiver, time out on the ack, and flip a successful run's exit code
        // to 130 with a spurious "interrupted". Cleared first, a late Ctrl-C
        // just falls through to the handler's plain exit.
        *INTERRUPT_HOOK.lock().unwrap() = None;
        let (ack_tx, ack_rx) = mpsc::channel();
        if self.tx.send(Msg::Shutdown(ack_tx)).is_ok() {
            let _ = ack_rx.recv_timeout(Duration::from_secs(2));
        }
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// Spawn the render thread for `prefixes` rows (all start Queued). Registers
/// the SIGINT freeze hook for the lifetime of the returned [`Handle`].
pub fn start(prefixes: Vec<String>) -> (Reporter, Handle) {
    let tty = io::stderr().is_terminal();
    let (tx, rx) = mpsc::channel::<Msg>();
    let join = thread::spawn(move || render_loop(rx, tty));
    // Grow the Model to one Queued row per prefix. Messages are processed in
    // order, so every later `Phase(idx, …)` lands on an existing row.
    for p in prefixes {
        let _ = tx.send(Msg::Init(p));
    }
    *INTERRUPT_HOOK.lock().unwrap() = Some(tx.clone());
    let reporter = Reporter {
        tx: tx.clone(),
        tty,
        next_companion: Arc::new(AtomicU64::new(0)),
    };
    let handle = Handle {
        tx,
        join: Some(join),
    };
    (reporter, handle)
}

/// SIGINT-side freeze: ask the live render thread to keep finished rows, drop
/// in-progress ones, and leave the cursor on a fresh line. Returns `true` if a
/// UI was running and handled the frame — the caller (SIGINT handler) then
/// prints "interrupted" itself, so the message appears exactly once regardless
/// of whether a UI was up. Times out fast so a wedged render thread can't
/// block exit (on timeout we return `false` and the caller still prints).
pub fn interrupt_freeze() -> bool {
    let hook = INTERRUPT_HOOK.lock().unwrap().clone();
    let Some(tx) = hook else {
        return false;
    };
    let (ack_tx, ack_rx) = mpsc::channel();
    if tx.send(Msg::Interrupt(ack_tx)).is_err() {
        return false;
    }
    ack_rx.recv_timeout(Duration::from_millis(500)).is_ok()
}

/// What a prompt/log call site holds: either the live render thread or a plain
/// terminal (no bars — single-package `run` after download, `info`, group
/// collisions). The two share one surface so callers don't branch.
#[derive(Clone)]
pub enum Ui {
    Plain,
    Live(Reporter),
}

impl Ui {
    pub fn println(&self, msg: impl Into<String>) {
        match self {
            // No live block: a plain stderr line (matches the old hidden
            // MultiProgress, whose println was a no-op only because nothing
            // was drawn — here we surface it).
            Ui::Plain => eprintln!("{}", msg.into()),
            Ui::Live(r) => r.log(msg),
        }
    }
    pub fn prompt_yes_no(&self, question: &str) -> PromptResult<bool> {
        match self {
            Ui::Plain => plain_yes_no(question),
            Ui::Live(r) => r.prompt_yes_no(question),
        }
    }
    pub fn prompt_pick(&self, header: &str, items: &[String]) -> PromptResult<usize> {
        match self {
            Ui::Plain => plain_pick(header, items),
            Ui::Live(r) => r.prompt_pick(header, items),
        }
    }
    /// Clear a companion row (live only; a no-op without bars).
    pub fn finish_companion(&self, id: u64, result: Result<(), String>) {
        if let Ui::Live(r) = self {
            r.finish_companion(id, result);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idle(prefix: &str, msg: &str) -> Row {
        Row {
            prefix: prefix.into(),
            phase: Phase::Idle(msg.into()),
        }
    }
    fn download(prefix: &str, done: u64, total: u64, rate: f64) -> Row {
        let b = RowBytes::new(total);
        b.add(done);
        b.set_rate(rate);
        Row {
            prefix: prefix.into(),
            phase: Phase::Download(b),
        }
    }
    fn model(rows: Vec<Row>) -> Model {
        Model {
            rows,
            companions: Vec::new(),
            prompt: None,
        }
    }
    /// Render one row to plain text at a generous width (no truncation).
    fn line(row: Row, frame: usize) -> String {
        render_lines(&model(vec![row]), 200, frame, false)
            .pop()
            .unwrap()
    }
    /// Render one row at an explicit width.
    fn line_w(row: Row, width: usize) -> String {
        render_lines(&model(vec![row]), width, 0, false)
            .pop()
            .unwrap()
    }

    #[test]
    fn idle_row_is_prefix_spinner_message() {
        // Two-space indent, cyan prefix, spinner frame 0, message.
        assert_eq!(
            line(idle("owner/repo", "Resolving..."), 0),
            "  owner/repo  ⠋  Resolving..."
        );
        // Frame advances the spinner glyph.
        assert_eq!(line(idle("o/r", "Queued"), 1), "  o/r  ⠙  Queued");
    }

    #[test]
    fn done_rows_carry_their_glyph() {
        assert_eq!(
            line(
                Row {
                    prefix: "htop".into(),
                    phase: Phase::Done(Outcome::Ok("Installed v3.4.1-1".into()))
                },
                0
            ),
            "  htop  ✓  Installed v3.4.1-1"
        );
        assert_eq!(
            line(
                Row {
                    prefix: "x".into(),
                    phase: Phase::Done(Outcome::Skip("kept v1".into()))
                },
                0
            ),
            "  x  ⊘  kept v1"
        );
        assert_eq!(
            line(
                Row {
                    prefix: "y".into(),
                    phase: Phase::Done(Outcome::Fail("not found".into()))
                },
                0
            ),
            "  y  ✗  not found"
        );
    }

    #[test]
    fn download_known_length_has_bar_and_percent() {
        // 50% of 100 bytes → 7 of 14 cells filled.
        let l = line(download("pkg 1.0", 50, 100, 0.0), 0);
        assert!(l.starts_with("  pkg 1.0  "), "{l:?}");
        assert!(l.contains(&"▰".repeat(7)), "{l:?}");
        assert!(l.contains(&"▱".repeat(7)), "{l:?}");
        assert!(l.contains(" 50%  "), "{l:?}");
        assert!(l.contains("50 B/"), "{l:?}");
    }

    #[test]
    fn download_unknown_length_is_spinner_and_bytes() {
        // total == 0 → no bar, spinner + byte count + rate.
        let l = line(download("pkg 1.0", 4096, 0, 1024.0 * 1024.0), 0);
        assert!(!l.contains('▰'), "{l:?}");
        assert!(l.contains("4.00 KiB"), "{l:?}");
        assert!(l.contains("1.00 MiB/s"), "{l:?}");
    }

    #[test]
    fn full_bar_at_completion() {
        let l = line(download("p", 100, 100, 0.0), 0);
        assert!(l.contains(&"▰".repeat(14)), "{l:?}");
        assert!(l.contains("100%"), "{l:?}");
    }

    #[test]
    fn companion_and_prompt_lines_render_below_rows() {
        let mut m = model(vec![idle("a", "Queued")]);
        let cb = RowBytes::new(10);
        cb.add(5);
        m.companions.push((
            0,
            Row {
                prefix: "a 1.0 (data)".into(),
                phase: Phase::Download(cb),
            },
        ));
        m.prompt = Some(vec!["Replace? [y/N] ".into()]);
        let lines = render_lines(&m, 200, 0, false);
        assert_eq!(lines.len(), 3);
        // "a" is padded to the companion prefix width so both spinners align.
        assert!(lines[0].starts_with("  a "));
        assert!(lines[1].contains("(data)"));
        assert_eq!(lines[2], "Replace? [y/N] ");
    }

    #[test]
    fn lines_truncate_to_width_on_display_columns() {
        // Width 10 → exactly 10 display columns, never more (no wrap).
        let l = line(idle("verylongprefix", "and a long message"), 0);
        let truncated = render_lines(&model(vec![idle("verylongprefix", "msg")]), 10, 0, false)
            .pop()
            .unwrap();
        assert_eq!(console::measure_text_width(&truncated), 10, "{truncated:?}");
        assert!(l.len() > truncated.len());
    }

    #[test]
    fn prefixes_pad_so_the_bar_column_aligns() {
        // Ragged prefix widths in one frame: every row's content column must
        // start at the same display column (max prefix width + the fixed gaps).
        let m = model(vec![
            download("htop 3.4.1-1", 50, 100, 0.0),
            download("coreutils 9.5-2", 10, 100, 0.0),
            Row {
                prefix: "rg".into(),
                phase: Phase::Done(Outcome::Ok("Installed v14".into())),
            },
        ]);
        let lines = render_lines(&m, 200, 0, false);
        let bar_col = |l: &str| l.find(['▰', '✓']).unwrap();
        let cols: Vec<usize> = lines.iter().map(|l| bar_col(l)).collect();
        // Pad = len("coreutils 9.5-2") = 15; column = 2 (indent) + 15 + 2 = 19.
        assert!(
            cols.iter().all(|&c| c == cols[0]),
            "ragged columns: {cols:?}"
        );
        assert_eq!(cols[0], 19, "{:?}", lines);
    }

    #[test]
    fn clamp_frame_fits_viewport_keeping_prompt_and_recent_rows() {
        let block: Vec<String> = (0..8).map(|i| format!("row{i}")).collect();
        let prompt = vec!["Enter number: ".to_string()];
        // height 6 → cap 5: marker + 3 bar rows + 1 prompt = 5 ≤ 5.
        let (shown, n_prompt) = clamp_frame(block.clone(), prompt.clone(), 6);
        assert!(shown.len() <= 5, "{shown:?}");
        assert_eq!(n_prompt, 1);
        assert!(shown[0].contains("more above"), "{shown:?}");
        // The most recent bar rows survive; the earliest are dropped.
        assert!(shown.contains(&"row7".to_string()), "{shown:?}");
        assert!(!shown.contains(&"row0".to_string()), "{shown:?}");
        // The prompt is always the last line.
        assert_eq!(shown.last().unwrap(), "Enter number: ");
    }

    #[test]
    fn clamp_frame_passes_through_when_it_fits() {
        let block: Vec<String> = (0..3).map(|i| format!("row{i}")).collect();
        let (shown, n_prompt) = clamp_frame(block, vec!["q".into()], 40);
        assert_eq!(shown, vec!["row0", "row1", "row2", "q"]);
        assert_eq!(n_prompt, 1);
    }

    #[test]
    fn interrupt_freeze_keeps_done_rows_and_drops_the_rest() {
        let mut m = model(vec![
            Row {
                prefix: "done-pkg".into(),
                phase: Phase::Done(Outcome::Ok("Installed v1".into())),
            },
            download("busy-pkg 2.0", 30, 100, 0.0),
            Row {
                prefix: "skip-pkg".into(),
                phase: Phase::Done(Outcome::Skip("kept".into())),
            },
        ]);
        let cb = RowBytes::new(10);
        m.companions.push((
            0,
            Row {
                prefix: "x (data)".into(),
                phase: Phase::Download(cb),
            },
        ));
        m.prompt = Some(vec!["Replace? [y/N] ".into()]);

        freeze_model(&mut m);

        // Two finished rows survive; the in-progress download, the companion,
        // and the open prompt are all gone.
        let lines = render_lines(&m, 200, 0, false);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].contains("done-pkg  ✓"));
        assert!(lines[1].contains("skip-pkg  ⊘"));
        assert!(
            !lines
                .iter()
                .any(|l| l.contains("busy-pkg") || l.contains("data") || l.contains("Replace"))
        );
    }

    #[test]
    fn download_row_never_exceeds_requested_width() {
        // The load-bearing invariant: at *every* width the rendered line stays
        // within budget — it degrades, it never overflows.
        for w in 1..70 {
            let l = line_w(
                download("coreutils 9.5-2", 33, 100, 2.0 * 1024.0 * 1024.0),
                w,
            );
            assert!(
                console::measure_text_width(&l) <= w,
                "w={w}: got {} cols: {l:?}",
                console::measure_text_width(&l)
            );
        }
    }

    #[test]
    fn download_row_degrades_bar_then_columns_then_prefix() {
        let row = || download("coreutils 9.5-2", 33, 100, 2.0 * 1024.0 * 1024.0);
        // Wide: full detail — bar, percent, byte counts, rate.
        let wide = line_w(row(), 80);
        assert!(wide.contains('▰'), "{wide:?}");
        assert!(wide.contains("33%"), "{wide:?}");
        assert!(wide.contains('/'), "{wide:?}");
        assert!(wide.contains("MiB/s"), "{wide:?}");
        // Mid: bar + percent survive; byte/rate columns are dropped first.
        let mid = line_w(row(), 40);
        assert!(mid.contains('▰'), "{mid:?}");
        assert!(mid.contains("33%"), "{mid:?}");
        assert!(!mid.contains("MiB/s"), "{mid:?}");
        // Narrow: the bar is gone, the percentage is the surviving progress cue.
        let narrow = line_w(row(), 24);
        assert!(!narrow.contains('▰') && !narrow.contains('▱'), "{narrow:?}");
        assert!(narrow.contains("33%"), "{narrow:?}");
        // Tiny: the prefix itself is ellipsized — cut is always signalled.
        let tiny = line_w(row(), 10);
        assert!(tiny.contains('…'), "{tiny:?}");
    }

    #[test]
    fn truncation_always_signals_with_ellipsis() {
        // Boundary case: the spinner segment of an idle row ends exactly on
        // `width`, so the message would be dropped — it must still end in `…`,
        // never vanish silently, and never exceed the width.
        for w in 4..14 {
            let l = render_lines(&model(vec![idle("x", "a longer message")]), w, 0, false)
                .pop()
                .unwrap();
            assert!(l.ends_with('…'), "w={w}: {l:?}");
            assert!(console::measure_text_width(&l) <= w, "w={w}: {l:?}");
        }
        // Same for a Done row whose `  x  ✓  ` prefix lands on the boundary.
        let d = render_lines(
            &model(vec![Row {
                prefix: "x".into(),
                phase: Phase::Done(Outcome::Ok("Installed v1.2.3".into())),
            }]),
            8,
            0,
            false,
        )
        .pop()
        .unwrap();
        assert!(d.ends_with('…'), "{d:?}");
    }

    #[test]
    fn human_bytes_steps_through_units() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.00 KiB");
        assert_eq!(human_bytes(1536), "1.50 KiB");
        assert_eq!(human_bytes(1024 * 1024), "1.00 MiB");
    }
}
