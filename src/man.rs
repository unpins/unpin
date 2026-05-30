//! `unpin man` — read a binary's embedded man pages and report/dump them.
//!
//! Man pages live as `unpin/man/<name>.<section>[.<lang>]` entries in the
//! embedded-metadata ZIP (`docs/embedded-metadata.md`); `meta.rs` locates the
//! ZIP and hands back the raw entries, and this module builds a page index over
//! them, picks the right `(name, section, lang)`, and resolves `.so` redirects
//! (stored as ZIP symlink entries). Reading from a foreign binary is fine — man
//! is informational, not a security boundary.
//!
//! Terminal **rendering** of the roff is not implemented yet; it will arrive via
//! the pandoc port (Readers::Man + Writers::ANSI). Until then `unpin man`
//! reports the page it found and offers `--raw` to dump the roff source.

use std::path::PathBuf;

use crate::install;
use crate::meta::{self, Meta};
use crate::platform::Paths;

/// `.so` redirect chain depth limit.
const MAX_SO_DEPTH: u32 = 4;

enum Body {
    Roff(Vec<u8>),
    So { tgt_name: String, tgt_section: u8 },
}

struct Page {
    name: String,
    section: u8,
    lang: String,
    body: Body,
}

/// Parse the leading digits of a man section token (`"1"`, `"8"`, `"3pm"` → 3).
fn parse_section(s: &str) -> u8 {
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().unwrap_or(0)
}

/// Build the page index from `unpin/man/*` entries.
///
/// Path shape: `unpin/man/<name>.<section>` (lang `en`) or
/// `unpin/man/<lang>/<name>.<section>`. A symlink entry is a `.so` redirect whose
/// content names the target page (`vipw.8`, or `man8/vipw.8` — the basename is
/// used).
fn index(meta: &Meta) -> Result<Vec<Page>, String> {
    let mut pages = Vec::new();
    for e in meta.entries_under("unpin/man/") {
        let rel = &e.path["unpin/man/".len()..];
        let (lang, file) = match rel.split_once('/') {
            Some((l, f)) => (l, f),
            None => ("en", rel),
        };
        // Skip nested paths beyond a single lang dir, and dir-like entries.
        if file.is_empty() || file.contains('/') {
            continue;
        }
        let Some((name, sec)) = file.rsplit_once('.') else {
            continue; // no section suffix — not a man page entry
        };
        let section = parse_section(sec);
        let body = if e.is_symlink {
            let tgt = std::str::from_utf8(&e.data)
                .map_err(|_| format!("unpin man: non-UTF8 .so target in {}", e.path))?
                .trim();
            let base = tgt.rsplit('/').next().unwrap_or(tgt);
            let (tn, ts) = base
                .rsplit_once('.')
                .ok_or_else(|| format!("unpin man: malformed .so target {tgt:?}"))?;
            Body::So {
                tgt_name: tn.to_string(),
                tgt_section: parse_section(ts),
            }
        } else {
            Body::Roff(e.data.clone())
        };
        pages.push(Page {
            name: name.to_string(),
            section,
            lang: lang.to_string(),
            body,
        });
    }
    Ok(pages)
}

/// Pick the best page for `(name, section, lang)`: prefer the requested
/// language, fall back to `en`; with no section, take the lowest-numbered one.
fn pick<'a>(pages: &'a [Page], name: &str, section: Option<u8>, lang: &str) -> Option<&'a Page> {
    for want_lang in [lang, "en"] {
        let mut best: Option<&Page> = None;
        for p in pages {
            if p.name == name && p.lang == want_lang && section.is_none_or(|s| p.section == s) {
                best = match best {
                    Some(b) if b.section <= p.section => Some(b),
                    _ => Some(p),
                };
            }
        }
        if best.is_some() {
            return best;
        }
    }
    None
}

/// Resolve `(name, section, lang)` to roff bytes, following `.so` redirects up
/// to `MAX_SO_DEPTH`. Returns the resolved section alongside the bytes.
fn roff_for(
    pages: &[Page],
    name: &str,
    section: Option<u8>,
    lang: &str,
) -> Result<(u8, Vec<u8>), String> {
    let sec_str = |s: Option<u8>| s.map_or_else(|| "?".to_string(), |s| s.to_string());
    let mut seen: Vec<(String, Option<u8>)> = Vec::new();
    let mut cur_name = name.to_string();
    let mut cur_section = section;
    loop {
        if seen.iter().any(|(n, s)| n == &cur_name && *s == cur_section) {
            return Err(format!(
                "unpin man: circular .so redirect at {cur_name}({})",
                sec_str(cur_section)
            ));
        }
        if seen.len() as u32 >= MAX_SO_DEPTH {
            return Err(format!(
                "unpin man: .so redirect chain for {name} exceeds {MAX_SO_DEPTH} hops"
            ));
        }
        let redirected = !seen.is_empty();
        seen.push((cur_name.clone(), cur_section));

        let p = pick(pages, &cur_name, cur_section, lang).ok_or_else(|| {
            let sec = sec_str(cur_section);
            if redirected {
                format!("unpin man: broken .so redirect — {cur_name}({sec}) not found")
            } else {
                format!("unpin man: no page for {cur_name}({sec}) — try `unpin man --list`")
            }
        })?;
        match &p.body {
            Body::Roff(bytes) => return Ok((p.section, bytes.clone())),
            Body::So {
                tgt_name,
                tgt_section,
            } => {
                cur_name = tgt_name.clone();
                cur_section = Some(*tgt_section);
            }
        }
    }
}

/// Candidate binaries for `pkg`: the running binary for unpin's own manual,
/// else the installed package's binaries (primary first).
fn locate(paths: &Paths, pkg: Option<&str>) -> Result<Vec<PathBuf>, String> {
    match pkg {
        None | Some("unpin") => {
            let exe = std::env::current_exe()
                .map_err(|e| format!("unpin man: cannot locate own binary: {e}"))?;
            Ok(vec![exe])
        }
        Some(name) => {
            install::installed_binaries(paths, name).map_err(|e| format!("unpin man: {e}"))
        }
    }
}

/// `unpin man [PKG] [PAGE]` — read and report a binary's embedded manual.
pub fn run(
    paths: &Paths,
    list: bool,
    raw: bool,
    pkg: Option<String>,
    page: Option<String>,
) -> Result<(), String> {
    let label = pkg.as_deref().unwrap_or("unpin").to_string();
    let candidates = locate(paths, pkg.as_deref())?;

    // Use the first candidate that carries man pages. A corrupt/oversized
    // container surfaces as an error here.
    let mut pages = None;
    for cand in &candidates {
        if let Some(m) = meta::read(cand)? {
            let p = index(&m)?;
            if !p.is_empty() {
                pages = Some(p);
                break;
            }
        }
    }
    let pages = pages.ok_or_else(|| format!("unpin man: `{label}` has no embedded manual"))?;

    if list {
        for p in &pages {
            let what = match &p.body {
                Body::Roff(b) => format!("roff, {} bytes", b.len()),
                Body::So {
                    tgt_name,
                    tgt_section,
                } => format!("-> {tgt_name}({tgt_section})"),
            };
            println!("{}({}) [{}]  {what}", p.name, p.section, p.lang);
        }
        return Ok(());
    }

    let want = page.as_deref().unwrap_or(label.as_str());
    let lang = "en";
    let (section, roff) = roff_for(&pages, want, None, lang)?;

    if raw {
        use std::io::Write;
        return std::io::stdout()
            .write_all(&roff)
            .map_err(|e| format!("unpin man: write: {e}"));
    }

    // No renderer yet — confirm the read worked end-to-end and point at the
    // deferred work (the pandoc port).
    println!(
        "Found embedded manual: {want}({section}) [{lang}] — {} bytes of roff source.\n\n\
         Terminal rendering is not implemented yet — it will arrive via the pandoc\n\
         port (Readers::Man + Writers::ANSI). For now:\n  \
         unpin man --raw     dump the raw roff source\n  \
         unpin man --list    list the embedded manual pages",
        roff.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a page index directly (bypassing the ZIP layer, which `meta.rs`
    /// tests cover) from `(name, section, lang, body)` tuples.
    fn pages(specs: &[(&str, u8, &str, Result<&[u8], (&str, u8)>)]) -> Vec<Page> {
        specs
            .iter()
            .map(|(name, section, lang, body)| Page {
                name: name.to_string(),
                section: *section,
                lang: lang.to_string(),
                body: match body {
                    Ok(roff) => Body::Roff(roff.to_vec()),
                    Err((tn, ts)) => Body::So {
                        tgt_name: tn.to_string(),
                        tgt_section: *ts,
                    },
                },
            })
            .collect()
    }

    #[test]
    fn parses_section_digits() {
        assert_eq!(parse_section("1"), 1);
        assert_eq!(parse_section("8"), 8);
        assert_eq!(parse_section("3pm"), 3);
        assert_eq!(parse_section("x"), 0);
    }

    #[test]
    fn roff_lookup_and_lowest_section() {
        let p = pages(&[
            ("foo", 8, "en", Ok(b"section 8")),
            ("foo", 1, "en", Ok(b"section 1")),
        ]);
        let (sec, roff) = roff_for(&p, "foo", None, "en").unwrap();
        assert_eq!(sec, 1);
        assert_eq!(roff, b"section 1");
    }

    #[test]
    fn so_redirect_resolves() {
        let p = pages(&[
            ("vigr", 8, "en", Err(("vipw", 8))),
            ("vipw", 8, "en", Ok(b"vipw body")),
        ]);
        let (sec, roff) = roff_for(&p, "vigr", None, "en").unwrap();
        assert_eq!(sec, 8);
        assert_eq!(roff, b"vipw body");
    }

    #[test]
    fn so_cycle_is_detected() {
        let p = pages(&[
            ("a", 1, "en", Err(("b", 1))),
            ("b", 1, "en", Err(("a", 1))),
        ]);
        let err = roff_for(&p, "a", None, "en").unwrap_err();
        assert!(err.contains("circular"), "got: {err}");
    }

    #[test]
    fn dangling_so_redirect_is_named() {
        let p = pages(&[("a", 1, "en", Err(("ghost", 1)))]);
        let err = roff_for(&p, "a", None, "en").unwrap_err();
        assert!(
            err.contains("broken .so redirect") && err.contains("ghost"),
            "got: {err}"
        );
    }

    #[test]
    fn so_chain_too_deep_errors() {
        let p = pages(&[
            ("a", 1, "en", Err(("b", 1))),
            ("b", 1, "en", Err(("c", 1))),
            ("c", 1, "en", Err(("d", 1))),
            ("d", 1, "en", Err(("e", 1))),
            ("e", 1, "en", Ok(b"end")),
        ]);
        assert!(roff_for(&p, "a", None, "en").is_err());
    }

    #[test]
    fn missing_page_suggests_list() {
        let p = pages(&[("foo", 1, "en", Ok(b"x"))]);
        let err = roff_for(&p, "bar", None, "en").unwrap_err();
        assert!(err.contains("--list"), "got: {err}");
    }
}
