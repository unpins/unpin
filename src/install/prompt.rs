//! Plain (no-live-bars) prompt helpers and the shared [`PromptResult`] type.
//!
//! These are the implementations used when there is **no** live progress block
//! on screen — the single-package `run`/`info` paths, group-collision picks,
//! and any [`crate::progress::Ui::Plain`] call site. When a live block *is*
//! drawn, [`crate::progress::Reporter`] renders the prompt below the bars
//! itself (so it can clear it precisely) and only borrows the read logic.
//!
//! The shared contract across every prompt:
//!
//! - **Cancel skips this package**: Esc/q at the picker (or any interaction
//!   error) and a bare "no" at a yes/no both let the run continue with the
//!   rest of its work. The dispatcher marks the job skipped (non-fatal);
//!   single-package callers map `Skip` to a clean error.
//! - **Non-TTY auto-skips**: piped stdin can't answer, so we return `Skip`
//!   rather than hang.

use std::io::{self, IsTerminal, Write};

use dialoguer::Select;

/// What the user picked at a prompt. `Got` carries the parsed value; `Skip`
/// means "drop this package and continue with the rest" (Esc/q, a bare "no",
/// or EOF/non-TTY).
pub enum PromptResult<T> {
    Got(T),
    Skip,
}

/// Plain arrow-key picker (no live bars). Returns the chosen 0-based index;
/// Esc/q, an empty list, or non-TTY stdin → `Skip`.
pub fn plain_pick(header: &str, items: &[String]) -> PromptResult<usize> {
    if items.is_empty() || !io::stdin().is_terminal() {
        return PromptResult::Skip;
    }
    // `interact_opt` reads from `Term::stderr()` (matching where the rest of
    // our prompts write). Esc/q → Ok(None); a terminal/IO error → Err. Both
    // mean "couldn't choose" here, so collapse them to Skip.
    match Select::new()
        .with_prompt(header)
        .items(items)
        .default(0)
        .interact_opt()
    {
        Ok(Some(i)) => PromptResult::Got(i),
        Ok(None) | Err(_) => PromptResult::Skip,
    }
}

/// Plain yes/no defaulting to no. `y`/`Y` → `Got(true)`; any other input,
/// including `n`/`N` and a bare Enter → `Got(false)`. A non-TTY stdin or EOF
/// (Ctrl-D) yields `Skip`.
pub fn plain_yes_no(question: &str) -> PromptResult<bool> {
    if !io::stdin().is_terminal() {
        return PromptResult::Skip;
    }
    eprint!("{question} [y/N] ");
    io::stderr().flush().ok();
    let mut line = String::new();
    if io::stdin().read_line(&mut line).is_err() || line.is_empty() {
        return PromptResult::Skip;
    }
    match line.trim_start().chars().next() {
        Some('y') | Some('Y') => PromptResult::Got(true),
        _ => PromptResult::Got(false),
    }
}
