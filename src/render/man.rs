//! `unpin man` — render the manual pages a program carries inside itself.
//!
//! Given `man [pkg] [page]` (a missing pkg defaults to `unpin`, so a bare
//! `unpin man` shows unpin's own manual), it reads the package's embedded
//! `unpin/man/` pages out of the bundle in-process (via [`crate::bundle`] /
//! [`crate::meta`]), picks the right (name, section, lang), follows whole-page
//! `.so` redirects, and pages the roff with the shared reflowing pager — which
//! re-runs the `mandoc-sys` renderer on each resize for true reflow.
//!
//! This was the `unpins/unpin-man` package, which drove the same renderer over
//! a subprocess and read the bundle through `unpin bundle list/dump`. Folded in,
//! it reads the bundle directly and links the renderer — no fetch, no IPC,
//! offline. The page-resolution logic (parse / pick / `.so` follow) is ported
//! from that package.

use std::io::Read;

use super::{Reflow, page};
use crate::bundle;
use crate::install;
use crate::meta;
use crate::platform::Paths;

/// A roff document the pager re-renders at each width via `mandoc-sys`.
struct ManDoc {
    roff: String,
}

impl Reflow for ManDoc {
    fn render(&self, width: u16) -> String {
        // man(1)'s one-column right gutter (`ws_col - 1`); 0 ⇒ mandoc default.
        let w = if width > 1 { width - 1 } else { width };
        mandoc_sys::render(&self.roff, w)
    }
}

/// One embedded page enumerated from the bundle's `unpin/man/` entries.
#[derive(Clone)]
struct Entry {
    name: String,
    lang: String,
    section: u32,
    /// Full bundle path, e.g. `unpin/man/ls.1`.
    path: String,
    /// `Some((target_name, target_section))` for a `.so` whole-page redirect.
    redirect: Option<(String, u32)>,
}

/// Render and page `page` from `pkg`'s embedded manual. `pkg`/`page` already
/// have their defaults applied by the caller (pkg → `unpin`, page → pkg); `pkg`
/// of `-` reads roff straight from stdin (dev/testing — no bundle).
pub fn man(paths: &Paths, pkg: &str, page_name: &str) -> Result<(), String> {
    if pkg == "-" {
        let mut roff = String::new();
        std::io::stdin()
            .read_to_string(&mut roff)
            .map_err(|e| format!("man: reading stdin: {e}"))?;
        page(&ManDoc { roff });
        return Ok(());
    }

    // `unpin` itself is always readable (the running binary); any other package
    // must be installed — man is offline-only, so there's no fetch to fall back
    // on. A dedicated message points at the fix rather than a generic failure.
    if pkg != "unpin" && !install::is_installed(paths, pkg)? {
        return Err(format!(
            "`{pkg}` is not installed — run `unpin install {pkg}` to install it"
        ));
    }

    let Some(meta) = bundle::read_bundle(paths, pkg)? else {
        return Err(format!("`{pkg}` has no embedded manual"));
    };
    let ents: Vec<Entry> = meta
        .entries_under("unpin/man/")
        .filter_map(parse_entry)
        .collect();
    if ents.is_empty() {
        return Err(format!("`{pkg}` has no embedded manual"));
    }

    let entry_path = resolve(&ents, page_name, "en").map_err(|e| {
        // The requested page isn't here. A multicall package is named for its
        // bundle, not any one page (e.g. `binutils` ships `ar`, `ld`, …), so a
        // bare `unpin man binutils` lands here — list what's available and how
        // to ask for it rather than a dead-end "not found". Only enrich when the
        // page itself is absent; a broken internal `.so` keeps resolve's message.
        if pick(&ents, page_name, None, "en").is_some() {
            return e; // page exists; resolve failed on a broken `.so` — keep its msg
        }
        let mut names: Vec<&str> = ents
            .iter()
            .filter(|e| e.lang == "en")
            .map(|e| e.name.as_str())
            .collect();
        names.sort_unstable();
        names.dedup();
        if names.is_empty() {
            return e; // nothing renderable in `en` (resolve only serves en) — no list
        }
        format!(
            "`{pkg}` has no page named `{page_name}`\n     available: {}\n     view one with `unpin man {pkg} <page>`",
            names.join(", ")
        )
    })?;

    let roff = meta
        .entry(&entry_path)
        .map(|e| String::from_utf8_lossy(&e.data).into_owned())
        .ok_or_else(|| format!("man: internal: resolved entry {entry_path} vanished"))?;
    page(&ManDoc { roff });
    Ok(())
}

/// Leading decimal digits of a section token: `"1"` → 1, `"3pm"` → 3, `"x"` → 0.
fn parse_section(s: &str) -> u32 {
    s.bytes()
        .take_while(u8::is_ascii_digit)
        .fold(0, |n, b| n * 10 + u32::from(b - b'0'))
}

/// Parse one `unpin/man/` bundle entry into an [`Entry`], or `None` for a
/// non-page entry (nested beyond one lang dir, no section suffix). Paths:
///
/// ```text
/// unpin/man/ls.1            regular roff page
/// unpin/man/dir.1          (is_symlink) `.so` redirect — data is the target
/// unpin/man/pt_BR/ls.1      a non-default language page
/// ```
fn parse_entry(e: &meta::Entry) -> Option<Entry> {
    let rel = e.path.strip_prefix("unpin/man/")?;

    // `<lang>/<file>` or, with no slash, the default language `en`.
    let (lang, file) = match rel.split_once('/') {
        Some((lang, file)) => {
            if file.contains('/') {
                return None; // nested beyond one lang dir — skip
            }
            (lang.to_owned(), file)
        }
        None => ("en".to_owned(), rel),
    };

    let (name, sect) = file.rsplit_once('.')?; // no section suffix — not a page
    // A `.so` whole-page redirect is stored as a unix symlink; its data is the
    // target path (e.g. `ls.1`, possibly with a dir prefix).
    let redirect = e.is_symlink.then(|| {
        let tgt = String::from_utf8_lossy(&e.data);
        let tgt = tgt.trim();
        let base = tgt.rsplit(['/', '\\']).next().unwrap_or(tgt);
        let (tname, tsect) = base.rsplit_once('.').unwrap_or((base, ""));
        (tname.to_owned(), parse_section(tsect))
    });

    Some(Entry {
        name: name.to_owned(),
        lang,
        section: parse_section(sect),
        path: e.path.clone(),
        redirect,
    })
}

/// Pick the best page for (name, section, lang): prefer `lang`, fall back to
/// `en`; with `section == None` take the lowest-numbered one.
fn pick<'a>(ents: &'a [Entry], name: &str, section: Option<u32>, lang: &str) -> Option<&'a Entry> {
    for l in [lang, "en"] {
        let mut best: Option<&Entry> = None;
        for e in ents {
            if e.name != name || e.lang != l {
                continue;
            }
            if section.is_some_and(|s| e.section != s) {
                continue;
            }
            if best.is_none_or(|b| e.section < b.section) {
                best = Some(e);
            }
        }
        if best.is_some() {
            return best;
        }
        if lang == "en" {
            break; // lang == "en": don't scan twice
        }
    }
    None
}

/// Resolve (name, lang) to the bundle path of a roff page, following whole-page
/// `.so` redirects up to `MAX_SO_DEPTH` with cycle detection.
fn resolve(ents: &[Entry], name: &str, lang: &str) -> Result<String, String> {
    const MAX_SO_DEPTH: usize = 4;

    let mut cur_name = name.to_owned();
    let mut cur_section: Option<u32> = None; // unspecified
    let mut seen: Vec<(String, Option<u32>)> = Vec::new();

    loop {
        if seen
            .iter()
            .any(|(n, s)| *n == cur_name && *s == cur_section)
        {
            return Err(format!("circular .so redirect at {cur_name}"));
        }
        if seen.len() >= MAX_SO_DEPTH {
            return Err(format!(
                ".so redirect chain for {name} exceeds {MAX_SO_DEPTH} hops"
            ));
        }
        seen.push((cur_name.clone(), cur_section));

        let e = pick(ents, &cur_name, cur_section, lang).ok_or_else(|| {
            if seen.len() > 1 {
                format!("broken .so redirect — {cur_name} not found")
            } else {
                format!("no embedded manual page for {cur_name}")
            }
        })?;

        match &e.redirect {
            None => return Ok(e.path.clone()),
            Some((tname, tsect)) => {
                cur_name = tname.clone();
                cur_section = Some(*tsect);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ent(path: &str, redirect: Option<(&str, u32)>) -> Entry {
        let (is_symlink, data) = match redirect {
            Some((n, s)) => (true, format!("{n}.{s}").into_bytes()),
            None => (false, b"10".to_vec()),
        };
        parse_entry(&meta::Entry {
            path: path.to_owned(),
            is_symlink,
            data,
        })
        .unwrap()
    }

    fn me(path: &str, is_symlink: bool, data: &[u8]) -> meta::Entry {
        meta::Entry {
            path: path.to_owned(),
            is_symlink,
            data: data.to_vec(),
        }
    }

    #[test]
    fn parses_plain_default_lang() {
        let e = parse_entry(&me("unpin/man/ls.1", false, b"909")).unwrap();
        assert_eq!(e.name, "ls");
        assert_eq!(e.lang, "en");
        assert_eq!(e.section, 1);
        assert_eq!(e.path, "unpin/man/ls.1");
        assert!(e.redirect.is_none());
    }

    #[test]
    fn parses_lang_and_redirect() {
        let e = parse_entry(&me("unpin/man/pt_BR/ls.1", false, b"909")).unwrap();
        assert_eq!(e.lang, "pt_BR");
        assert_eq!(e.name, "ls");

        let r = parse_entry(&me("unpin/man/dir.1", true, b"ls.1\n")).unwrap();
        assert_eq!(r.redirect, Some(("ls".to_owned(), 1)));
    }

    #[test]
    fn skips_non_man_entries() {
        assert!(parse_entry(&me("unpin/aliases", false, b"foo")).is_none());
        assert!(parse_entry(&me("unpin/man/a/b/c.1", false, b"9")).is_none()); // nested
        assert!(parse_entry(&me("unpin/man/noext", false, b"9")).is_none()); // no section
    }

    #[test]
    fn picks_lowest_section_then_lang() {
        let ents = [ent("unpin/man/ls.5", None), ent("unpin/man/ls.1", None)];
        assert_eq!(pick(&ents, "ls", None, "en").unwrap().section, 1);
        assert_eq!(pick(&ents, "ls", Some(5), "en").unwrap().section, 5);
        assert!(pick(&ents, "nope", None, "en").is_none());
    }

    #[test]
    fn resolves_so_redirect_and_detects_cycles() {
        let ents = [
            ent("unpin/man/dir.1", Some(("ls", 1))),
            ent("unpin/man/ls.1", None),
        ];
        assert_eq!(resolve(&ents, "dir", "en").unwrap(), "unpin/man/ls.1");

        let cyc = [
            ent("unpin/man/a.1", Some(("b", 1))),
            ent("unpin/man/b.1", Some(("a", 1))),
        ];
        assert!(resolve(&cyc, "a", "en").is_err());
    }
}
