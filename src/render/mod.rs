//! The shared terminal pager — one reflowing pager behind every doc verb.
//!
//! Before this module, `man` and `readme` were separate helper packages that
//! each carried a *copy* of the same pager, and `info` had none (it printed
//! raw). The seam that actually matters is not "builtin vs package" but
//! **pager (content-agnostic, small) vs renderer (content-specific)**. So the
//! pager lives here once, generic over a [`Reflow`] renderer: it pages
//! pre-rendered ANSI *lines* and, on a resize, asks the renderer for a fresh
//! render at the new width — true reflow, the way a man pager re-runs mandoc on
//! `SIGWINCH`. When stdout is not a tty it prints one plain render so
//! `unpin man pkg | grep` keeps working.
//!
//! Two renderers plug in today: [`man`] (roff→ANSI via the `mandoc-sys` crate)
//! and [`readme`] (markdown→ANSI via termimad). A future doc verb is just
//! another `Reflow` impl.

use std::io::{self, IsTerminal, Write};

use termimad::crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute, queue,
    style::{Attribute, Print, SetAttribute},
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};

pub mod man;
pub mod readme;

pub use man::man;
pub use readme::readme;

/// A document that can re-render itself to ANSI text wrapped to a given width.
/// The width is the full terminal width; the renderer leaves its own gutter if
/// it wants one (man keeps man(1)'s one-column right margin; markdown does not).
/// A width of 0 means "the renderer's own default".
pub trait Reflow {
    fn render(&self, width: u16) -> String;
}

/// Render `doc` and show it. On a tty, page it with the reflowing pager;
/// otherwise print one plain render (ANSI stripped) so a pipe stays clean.
pub fn page(doc: &dyn Reflow) {
    if !io::stdout().is_terminal() {
        print_plain(doc);
        return;
    }
    // On any pager/terminal failure, fall back to a plain print so the document
    // is still shown (e.g. a terminal that rejects raw mode).
    if run_pager(doc).is_err() {
        print_plain(doc);
    }
}

/// One plain render at the current width (80 when unknown), with SGR styling
/// stripped so `unpin man pkg | grep` (or `readme`) stays clean. Used when
/// stdout is redirected and as the non-interactive fallback.
fn print_plain(doc: &dyn Reflow) {
    let cols = terminal::size().map(|(w, _)| w).unwrap_or(80);
    print!("{}", strip_ansi(&doc.render(cols)));
}

/// Drop CSI SGR sequences (`ESC [ … m`) — enough to plain-text our own output.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip a `[ … m` sequence; tolerate a bare ESC by stopping at the
            // first non-parameter byte.
            if chars.as_str().starts_with('[') {
                chars.next();
                for p in chars.by_ref() {
                    if !matches!(p, '0'..='9' | ';') {
                        break; // consumes the final byte (the `m`)
                    }
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Enter the alternate screen + raw mode, run the pager loop, and always restore
/// the terminal afterwards — even if the loop errors.
fn run_pager(doc: &dyn Reflow) -> io::Result<()> {
    let mut out = io::stdout();
    terminal::enable_raw_mode()?;
    queue!(
        out,
        EnterAlternateScreen,
        cursor::Hide,
        Clear(ClearType::All)
    )?;
    out.flush()?;

    let res = pager_loop(&mut out, doc);

    let _ = execute!(out, cursor::Show, LeaveAlternateScreen);
    let _ = terminal::disable_raw_mode();
    res
}

/// The pager event loop: draw, block for an event, scroll/resize/quit, repeat.
fn pager_loop<W: Write>(out: &mut W, doc: &dyn Reflow) -> io::Result<()> {
    let (mut cols, mut rows) = terminal::size().unwrap_or((80, 24));
    let mut lines = render_lines(doc, cols);
    let mut top: usize = 0;

    loop {
        draw(out, &lines, top, cols, rows)?;
        out.flush()?;

        match event::read()? {
            Event::Resize(c, r) => {
                cols = c;
                rows = r;
                // Re-render at the new width — the reflow seam. The renderer
                // honours the width, so the text itself is re-wrapped, not just
                // the window.
                lines = render_lines(doc, cols);
                top = top.min(max_top(lines.len(), rows));
                queue!(out, Clear(ClearType::All))?;
            }
            // Ignore key-release events (kitty protocol); act on press/repeat.
            // `handle_key` returns false to quit (only called for non-release).
            Event::Key(key)
                if key.kind != KeyEventKind::Release
                    && !handle_key(&mut top, key, lines.len(), rows) =>
            {
                return Ok(());
            }
            _ => {}
        }
    }
}

/// Render `doc` at `cols` and split into display lines.
fn render_lines(doc: &dyn Reflow, cols: u16) -> Vec<String> {
    doc.render(cols).lines().map(str::to_owned).collect()
}

/// The top index past which there is nothing more to scroll to.
fn max_top(nlines: usize, rows: u16) -> usize {
    let content = rows.saturating_sub(1) as usize;
    nlines.saturating_sub(content)
}

/// Apply a key to the scroll position. Returns `false` to quit, `true` to keep
/// paging.
fn handle_key(top: &mut usize, key: KeyEvent, nlines: usize, rows: u16) -> bool {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let content = rows.saturating_sub(1) as usize;
    let half = (content / 2).max(1) as isize;
    let page_step = content.saturating_sub(1).max(1) as isize;
    let max = max_top(nlines, rows);
    let mut scroll = |delta: isize| {
        *top = (*top as isize + delta).clamp(0, max as isize) as usize;
    };
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => return false,
        KeyCode::Char('c') if ctrl => return false,
        KeyCode::Down | KeyCode::Char('j') | KeyCode::Enter => scroll(1),
        KeyCode::Up | KeyCode::Char('k') => scroll(-1),
        KeyCode::Char('d') if ctrl => scroll(half),
        KeyCode::Char('u') if ctrl => scroll(-half),
        KeyCode::PageDown | KeyCode::Char(' ') | KeyCode::Char('f') => scroll(page_step),
        KeyCode::PageUp | KeyCode::Char('b') => scroll(-page_step),
        KeyCode::Home | KeyCode::Char('g') => *top = 0,
        KeyCode::End | KeyCode::Char('G') => *top = max,
        _ => {}
    }
    true
}

/// Draw the visible window of lines, then the status row.
fn draw<W: Write>(
    out: &mut W,
    lines: &[String],
    top: usize,
    cols: u16,
    rows: u16,
) -> io::Result<()> {
    let content = rows.saturating_sub(1);
    for r in 0..content {
        queue!(out, cursor::MoveTo(0, r))?;
        if let Some(line) = lines.get(top + r as usize) {
            queue!(out, Print(line))?;
        }
        // Erase to end-of-line so a shorter line over a longer one leaves no
        // stale cells (the window is redrawn in place, not on a cleared screen).
        queue!(out, Clear(ClearType::UntilNewLine))?;
    }
    draw_status(out, lines.len(), top, cols, rows)
}

/// A reverse-video status/help line across the bottom row.
fn draw_status<W: Write>(
    out: &mut W,
    nlines: usize,
    top: usize,
    cols: u16,
    rows: u16,
) -> io::Result<()> {
    if rows < 1 {
        return Ok(());
    }
    let width = cols.max(1) as usize;
    let content = rows.saturating_sub(1) as usize;
    let bot = (top + content).min(nlines);
    let pct = (bot * 100).checked_div(nlines).unwrap_or(100);
    let first = if nlines == 0 { 0 } else { top + 1 };
    let hint = format!(
        " {first}-{bot}/{nlines} ({pct}%)  q quit · ↑/↓ j/k · Space/b page · g/G top/bottom ",
    );
    // Set Reverse first, then erase-to-end-of-line: the terminal fills the
    // cleared cells with the current rendition, so the whole row is painted
    // reverse in one move — no manual space-padding, no char-vs-column width
    // guesswork. `take(width)` is a safety cap so it can't wrap a narrow row.
    let line: String = hint.chars().take(width).collect();
    queue!(
        out,
        cursor::MoveTo(0, rows - 1),
        SetAttribute(Attribute::Reverse),
        Clear(ClearType::UntilNewLine),
        Print(line),
        SetAttribute(Attribute::Reset),
    )?;
    Ok(())
}
