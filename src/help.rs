//! The hand-written parts of `--help` (banner, footer) and the DNS hint.
//!
//! clap renders the generated help colored (`color` feature) and wrapped to
//! the terminal (`wrap_help`); these printers follow the same two rules so the
//! seam between generated and hand-written output is invisible: section
//! headers are bold+underline, user-typeable literals are bold, prose re-wraps
//! to the width of the stream it goes to, and copy-pasteable example lines are
//! never wrapped. `console` (already used by the progress UI) supplies the
//! styling — it strips ANSI when the stream isn't a tty, like clap does.

use std::path::Path;

/// Column clap falls back to when the terminal width can't be detected
/// (output piped, no tty). Same constant clap's `wrap_help` uses.
const FALLBACK_WIDTH: usize = 100;

/// Below this many columns left for the description, drop it to its own
/// line instead of squeezing a one-word-per-line ribbon next to the term.
const MIN_DESC_WIDTH: usize = 25;

pub fn banner() {
    let out = Out { err: false };
    out.line(&format!(
        "{} — install programs from GitHub releases",
        out.bold(&format!("unpin {}", env!("CARGO_PKG_VERSION")))
    ));
    out.line("https://unpins.org");
}

/// Printed after clap's own top-level help: the bits that aren't flags —
/// auth env vars, the opt-in DNS fallback, and the config file's keys.
pub fn footer(config_path: Option<&Path>) {
    let out = Out { err: false };
    let w = out.width();

    out.line("");
    out.title(
        "Auth",
        " (optional, raises GitHub API rate limit from 60/h to 5000/h):",
        w,
    );
    out.items(
        w,
        2,
        &[
            ("GITHUB_TOKEN | GH_TOKEN", "token from env var"),
            ("use_gh_auth = true (in config)", "use `gh auth token`"),
        ],
    );

    out.line("");
    out.title("Networking", " (opt-in DNS fallback — off by default):", w);
    out.items(
        w,
        2,
        &[(
            "UNPIN_DNS=\"ip ...\"",
            "resolve through these DNS servers when the OS resolver can't be \
             reached (e.g. Android, a captive portal). Space-separated IPv4; a \
             one-shot override of the config `dns` key. Unset → no fallback \
             (the real resolver error is shown, with how to opt in).",
        )],
    );

    out.line("");
    let path = match config_path {
        Some(p) => p.display().to_string(),
        None => "(unresolved: $HOME not set)".to_owned(),
    };
    out.title("Config file", &format!(": {path}"), w);
    out.line(&format!(
        "  {}",
        wrapped(
            "Flat `key = value` with `#` comments. Recognized keys:",
            w,
            2,
            2
        )
    ));
    out.items(
        w,
        4,
        &[
            (
                "http_timeout = <seconds>",
                "API request deadline / download idle timeout (default: 30)",
            ),
            (
                "use_gh_auth  = true|false",
                "shell out to `gh auth token` (default: false)",
            ),
            (
                "data         = true|false",
                "download per-release data tarball (default: true)",
            ),
            (
                "aliases      = yes|no|ask",
                "install multi-call aliases declared by catalog packages \
                 (default: yes; non-catalog <owner>/<repo> installs always skip)",
            ),
            (
                "dns          = ip ...",
                "DNS servers for the fallback resolver, used when the OS \
                 resolver can't be reached (default: off; applies to every \
                 unpins program, not just unpin)",
            ),
        ],
    );
}

/// A short, hedged hint after a resolution-looking failure: the cause MAY be a
/// host with no working DNS (Android, minimal containers), and the opt-in
/// fallback is the fix. Teaching only — no prompt, no retry; the user opts in
/// and reruns the command themselves. The C shim (nix-lib/dns-fallback) picks
/// either source up on its own: `$UNPIN_DNS` from the environment, the `dns`
/// key straight from the config file (which is why the config line covers
/// every unpins program, not just unpin).
pub fn dns_hint(config: &Path) {
    let out = Out { err: true };
    let w = out.width();
    out.line("");
    out.line(&wrapped(
        "This may be a DNS problem. If this host can't reach a DNS server \
         (common on Android and in minimal containers), unpin can resolve \
         through a public one — it's off by default, so opt in and rerun the \
         command:",
        w,
        0,
        0,
    ));
    out.line("");
    // The opt-in lines are copy-paste material: bold, never wrapped.
    out.line(&format!(
        "  one run:   {}",
        out.bold("UNPIN_DNS=\"1.1.1.1 8.8.8.8\" unpin …")
    ));
    out.line(&format!(
        "  always:    add {} to {}",
        out.bold("dns = 1.1.1.1 8.8.8.8"),
        config.display()
    ));
    out.line("             (then every unpins program uses it)");
}

/// Which stream the text goes to — picks println!/eprintln!, which terminal's
/// width to wrap at, and which stream's tty-ness gates the ANSI styling.
struct Out {
    err: bool,
}

impl Out {
    fn line(&self, s: &str) {
        if self.err {
            eprintln!("{s}");
        } else {
            println!("{s}");
        }
    }

    fn width(&self) -> usize {
        let term = if self.err {
            console::Term::stderr()
        } else {
            console::Term::stdout()
        };
        term.size_checked()
            .map(|(_, cols)| cols as usize)
            .unwrap_or(FALLBACK_WIDTH)
            .max(40)
    }

    fn bold(&self, s: &str) -> String {
        let styled = console::style(s).bold();
        if self.err {
            styled.for_stderr().to_string()
        } else {
            styled.to_string()
        }
    }

    fn header(&self, s: &str) -> String {
        let styled = console::style(s).bold().underlined();
        if self.err {
            styled.for_stderr().to_string()
        } else {
            styled.to_string()
        }
    }

    /// Section title: a short styled head followed by plain prose (wrapped),
    /// e.g. `Networking` + ` (opt-in DNS fallback — off by default):`.
    fn title(&self, head: &str, rest: &str, width: usize) {
        let head_w = console::measure_text_width(head);
        self.line(&format!(
            "{}{}",
            self.header(head),
            wrapped_rest(rest, width, head_w, 2)
        ));
    }

    /// Two-column rows: bold term, plain description wrapped with a hanging
    /// indent at the description column. When the terminal is too narrow for
    /// a useful side column, the description moves below the term instead
    /// (clap's next-line-help, same idea).
    fn items(&self, width: usize, indent: usize, rows: &[(&str, &str)]) {
        let term_w = rows
            .iter()
            .map(|(t, _)| console::measure_text_width(t))
            .max()
            .unwrap_or(0);
        let desc_col = indent + term_w + 2;
        for (term, desc) in rows {
            if width.saturating_sub(desc_col) < MIN_DESC_WIDTH {
                self.line(&format!("{}{}", " ".repeat(indent), self.bold(term)));
                let ind = indent + 4;
                self.line(&format!(
                    "{}{}",
                    " ".repeat(ind),
                    wrapped(desc, width, ind, ind)
                ));
            } else {
                let pad = desc_col - indent - console::measure_text_width(term);
                self.line(&format!(
                    "{}{}{}{}",
                    " ".repeat(indent),
                    self.bold(term),
                    " ".repeat(pad),
                    wrapped(desc, width, desc_col, desc_col)
                ));
            }
        }
    }
}

/// Greedy word-wrap of plain text to `width` columns. The first line starts
/// at column `first` (whatever the caller already printed there); each
/// continuation line is indented by `indent` spaces. A token wider than the
/// room left gets a line to itself and overflows — paths and URLs stay whole.
fn wrapped(text: &str, width: usize, first: usize, indent: usize) -> String {
    let mut o = String::new();
    let mut col = first;
    let mut fresh = true; // nothing on the current line yet
    for tok in text.split_whitespace() {
        let w = console::measure_text_width(tok);
        if !fresh && col + 1 + w > width {
            o.push('\n');
            o.push_str(&" ".repeat(indent));
            col = indent;
            fresh = true;
        }
        if !fresh {
            o.push(' ');
            col += 1;
        }
        o.push_str(tok);
        col += w;
        fresh = false;
    }
    o
}

/// Like `wrapped`, but for text glued directly after a head at column `first`
/// (no separating space — the caller's `rest` starts with its own punctuation).
fn wrapped_rest(rest: &str, width: usize, first: usize, indent: usize) -> String {
    let lead: String = rest.chars().take_while(|c| !c.is_alphanumeric()).collect();
    let body = &rest[lead.len()..];
    if body.is_empty() {
        return lead;
    }
    format!(
        "{lead}{}",
        wrapped(
            body,
            width,
            first + console::measure_text_width(&lead),
            indent
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_breaks_at_width_with_hanging_indent() {
        let s = wrapped("aa bb cc dd", 8, 0, 3);
        assert_eq!(s, "aa bb cc\n   dd");
    }

    #[test]
    fn wrap_first_line_respects_starting_column() {
        // Column 6 already used: "aa" fits (6+1+2 ≤ 9), "bb" doesn't.
        let s = wrapped("aa bb", 9, 6, 2);
        assert_eq!(s, "aa\n  bb");
    }

    #[test]
    fn wrap_lets_long_tokens_overflow_whole() {
        let s = wrapped("x /a/very/long/unbreakable/path y", 10, 0, 2);
        assert_eq!(s, "x\n  /a/very/long/unbreakable/path\n  y");
    }

    #[test]
    fn wrap_collapses_internal_runs_of_spaces() {
        assert_eq!(wrapped("a  b\n c", 80, 0, 0), "a b c");
    }

    #[test]
    fn rest_keeps_leading_punctuation_glued() {
        // The " (" must stay on the head's line even though a plain wrap
        // would treat "(optional" as one token.
        let s = wrapped_rest(" (optional, things):", 80, 4, 2);
        assert_eq!(s, " (optional, things):");
    }
}
