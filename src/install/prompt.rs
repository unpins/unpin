//! Fault-tolerant prompt helpers shared by every interactive prompt (the
//! asset picker, missing-checksum confirm, replace-active-version, the
//! version-conflict and multi-executable pickers). The shared contract:
//!
//! - **`prompt_pick_with_skip` drives a `dialoguer::Select`**: arrow-key
//!   navigation (↑/↓ or k/j), Enter to choose, Esc/q to cancel. It's the one
//!   picker both `install`/`update` and the legacy `run`/`info` paths route
//!   through — there is no second numeric implementation to keep in sync.
//! - **Cancel skips this package**: Esc/q (or any interaction error) returns
//!   `PromptResult::Skip`. The dispatcher marks the job skipped (non-fatal)
//!   and proceeds with the rest of the run; single-package callers map Skip
//!   to a clean error.
//! - **`MultiProgress::suspend()` wraps the I/O**: indicatif's bar render
//!   loop pauses while the prompt owns the terminal, so a TTY doesn't tear or
//!   interleave bar redraws with the picker.
//! - **Non-TTY auto-skips**: piped stdin can't answer; returning `Skip`
//!   matches the existing `prompt_yes_no` behavior (refuse) without
//!   hanging the pipeline.

use std::io::{self, IsTerminal, Write};

use dialoguer::Select;
use indicatif::MultiProgress;

/// What the user picked at a prompt. `Got` carries the parsed value; `Skip`
/// means "drop this package and continue with the rest" (typed `s`, or
/// EOF/non-TTY).
pub enum PromptResult<T> {
    Got(T),
    Skip,
}

/// Prompt the user to pick one of `items`, returning the chosen 0-based index.
/// Arrow keys (or k/j) move, Enter selects, Esc/q cancels → `Skip`. Empty list
/// or non-TTY stdin also returns `Skip` without prompting. Wrapped in
/// `multi.suspend()` so the bar render loop pauses while the picker owns the
/// terminal.
pub fn prompt_pick_with_skip(
    multi: &MultiProgress,
    header: &str,
    items: &[String],
) -> PromptResult<usize> {
    if items.is_empty() {
        return PromptResult::Skip;
    }
    if !io::stdin().is_terminal() {
        return PromptResult::Skip;
    }
    multi.suspend(|| {
        // `interact_opt` reads from `Term::stderr()` (matching where the rest
        // of our prompts write). Esc/q → Ok(None); a terminal/IO error → Err.
        // Both mean "couldn't choose" here, so collapse them to Skip.
        match Select::new()
            .with_prompt(header)
            .items(items)
            .default(0)
            .interact_opt()
        {
            Ok(Some(i)) => PromptResult::Got(i),
            Ok(None) | Err(_) => PromptResult::Skip,
        }
    })
}

/// Yes/no prompt defaulting to no. `y`/`Y` → `Got(true)`; any other input,
/// including `n`/`N` and a bare Enter → `Got(false)`. A non-TTY stdin or EOF
/// (Ctrl-D) yields `Skip`, so a non-interactive caller skips the package rather
/// than silently taking the default. Wrapped in `multi.suspend()`.
///
/// (The interactive prompt offers only `[y/N]`: every caller treats `Skip` and
/// `Got(false)` identically, so a separate keystroke for it would advertise a
/// distinction that doesn't exist. `Skip` survives only for the non-TTY/EOF
/// path above, where there's no keystroke to read.)
pub fn prompt_yes_no_with_skip(multi: &MultiProgress, question: &str) -> PromptResult<bool> {
    if !io::stdin().is_terminal() {
        return PromptResult::Skip;
    }
    multi.suspend(|| {
        // Single read: `prompt_yes_no` legacy never retried, and there's
        // no "invalid" outcome here — any non-y input is a valid "no".
        // We only loop if we wanted to require an explicit choice, which
        // the contract doesn't.
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
    })
}
