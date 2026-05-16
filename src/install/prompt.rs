//! Fault-tolerant prompt helpers for the unified pipeline.
//!
//! Every interactive prompt in `run_pipeline_v2` (asset picker, missing-
//! checksum confirm, replace-active-version) goes through one of these
//! helpers. The shared contract:
//!
//! - **Retry on invalid input**: the user can't make the pipeline error
//!   by typing a non-number or a non-y/n character. The helper prints
//!   "invalid; try again" and loops.
//! - **`s` skips this package**: typing `s` (or `S`, or Ctrl-D / EOF on
//!   stdin) returns `PromptResult::Skip`. The dispatcher marks the job as
//!   skipped (non-fatal) and proceeds with the rest of the run.
//! - **`MultiProgress::suspend()` wraps the I/O**: indicatif's bar render
//!   loop pauses while the prompt reads stdin, so a TTY doesn't tear or
//!   interleave bar redraws with the user's typed input.
//! - **Non-TTY auto-skips**: piped stdin can't answer; returning `Skip`
//!   matches the existing `prompt_yes_no` behavior (refuse) without
//!   hanging the pipeline.

use std::io::{self, IsTerminal, Write};

use indicatif::MultiProgress;

/// What the user picked at a prompt. `Got` carries the parsed value; `Skip`
/// means "drop this package and continue with the rest" (typed `s`, or
/// EOF/non-TTY).
pub enum PromptResult<T> {
    Got(T),
    Skip,
}

/// Prompt the user to pick one of `items` (1-based in the UI, 0-based in
/// the returned index). Loops on invalid input; `s`/EOF returns `Skip`.
/// Wrapped in `multi.suspend()` so the bar render loop pauses while
/// stdin is being read.
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
        loop {
            eprintln!("{header}");
            for (n, item) in items.iter().enumerate() {
                eprintln!("  [{}] {}", n + 1, item);
            }
            eprint!("Pick [1-{}, s=skip]: ", items.len());
            io::stderr().flush().ok();
            let mut line = String::new();
            if io::stdin().read_line(&mut line).is_err() || line.is_empty() {
                // EOF or read error — treat as skip rather than crash.
                return PromptResult::Skip;
            }
            let trimmed = line.trim();
            if matches!(trimmed, "s" | "S" | "skip") {
                return PromptResult::Skip;
            }
            match trimmed.parse::<usize>() {
                Ok(n) if (1..=items.len()).contains(&n) => return PromptResult::Got(n - 1),
                _ => {
                    eprintln!("invalid choice; try again (or `s` to skip)");
                    continue;
                }
            }
        }
    })
}

/// Yes/no prompt with a skip option. `y`/`Y` → `Got(true)`; anything else
/// non-empty (including `n`, `N`) → `Got(false)`; empty (default) →
/// `Got(false)`; `s`/`S`/EOF → `Skip`. Wrapped in `multi.suspend()`.
pub fn prompt_yes_no_with_skip(multi: &MultiProgress, question: &str) -> PromptResult<bool> {
    if !io::stdin().is_terminal() {
        return PromptResult::Skip;
    }
    multi.suspend(|| {
        // Single read: `prompt_yes_no` legacy never retried, and there's
        // no "invalid" outcome here — any non-y/n input is a valid "no".
        // We only loop if we wanted to require an explicit choice, which
        // the contract doesn't.
        eprint!("{question} [y/N/s] ");
        io::stderr().flush().ok();
        let mut line = String::new();
        if io::stdin().read_line(&mut line).is_err() || line.is_empty() {
            return PromptResult::Skip;
        }
        let first = line.trim_start().chars().next();
        match first {
            Some('s') | Some('S') => PromptResult::Skip,
            Some('y') | Some('Y') => PromptResult::Got(true),
            _ => PromptResult::Got(false),
        }
    })
}
