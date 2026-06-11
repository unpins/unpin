//! `unpin readme` — render a program's README markdown in the terminal, paged.
//!
//! Cheapest source first: `-` (stdin, for piping/testing), the package's
//! embedded `unpin/readme/README.md` bundle entry (offline, fast), then a fetch
//! from the upstream GitHub repo as a fallback (until READMEs are embedded). The
//! markdown is rendered with termimad and paged with the shared reflowing pager,
//! which re-renders at the live width on each resize.
//!
//! This was the `unpins/unpin-readme` package; folded in, it reads the bundle
//! directly instead of through `unpin bundle dump`. The repo-fetch fallback is
//! ported from that package.

use std::io::Read;

use termimad::MadSkin;

use super::{Reflow, page};
use crate::bundle;
use crate::install;
use crate::platform::Paths;

/// Markdown the pager re-renders at each width via termimad.
struct ReadmeDoc {
    md: String,
}

impl Reflow for ReadmeDoc {
    fn render(&self, width: u16) -> String {
        // termimad wraps to the given width and reflows on every call, so a
        // resize re-wraps the markdown itself, not pre-wrapped lines.
        format!(
            "{}",
            MadSkin::default().text(&self.md, Some(width.max(1) as usize))
        )
    }
}

/// Render and page `target`'s README. `target` is a package name, `owner/repo`,
/// or `-` (read markdown from stdin).
pub fn readme(paths: &Paths, target: &str) -> Result<(), String> {
    let md = load(paths, target)?;
    if md.trim().is_empty() {
        return Err(if target == "-" {
            "no README on standard input".to_owned()
        } else {
            format!("{target} has no README")
        });
    }
    page(&ReadmeDoc { md });
    Ok(())
}

/// Resolve the markdown for `target`, cheapest source first.
fn load(paths: &Paths, target: &str) -> Result<String, String> {
    if target == "-" {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| format!("reading stdin: {e}"))?;
        return Ok(s);
    }
    // Embedded bundle — the fast, offline path. Best-effort: any "not embedded"
    // / "not installed" / read failure just falls through to the repo fetch.
    if let Some(md) = embedded(paths, target) {
        return Ok(md);
    }
    repo_readme(target)
}

/// Read `unpin/readme/README.md` out of `target`'s embedded bundle, or `None` in
/// every "no embedded README here" case (entry absent, package not installed,
/// unreadable/corrupt bundle) so the caller falls through to the repo fetch. A
/// bare `owner/repo` (not an installed package) is simply never installed, so it
/// skips straight to the fetch.
fn embedded(paths: &Paths, target: &str) -> Option<String> {
    if target != "unpin" && !install::is_installed(paths, target).unwrap_or(false) {
        return None;
    }
    let meta = bundle::read_bundle(paths, target).ok().flatten()?;
    let e = meta.entry("unpin/readme/README.md")?;
    String::from_utf8(e.data.clone()).ok()
}

/// Fetch `pkg`'s README from its GitHub repo. A bare name resolves to
/// `unpins/<name>`; an explicit `owner/repo` is used as-is. Hits the API's readme
/// endpoint so it follows the default branch and finds the file regardless of
/// casing or extension.
fn repo_readme(pkg: &str) -> Result<String, String> {
    let (owner, repo) = split_repo(pkg);
    let url = format!("https://api.github.com/repos/{owner}/{repo}/readme");
    let mut req = minreq::get(&url)
        // `raw` media type returns the file bytes directly, not base64 JSON.
        .with_header("Accept", "application/vnd.github.raw+json")
        .with_header("User-Agent", "unpin")
        .with_timeout(30);
    if let Some(tok) = token() {
        req = req.with_header("Authorization", format!("Bearer {tok}"));
    }

    let resp = req
        .send()
        .map_err(|e| format!("fetching {owner}/{repo} README: {e}"))?;
    match resp.status_code {
        200 => resp
            .as_str()
            .map(str::to_owned)
            .map_err(|e| format!("decoding README: {e}")),
        404 => Err(format!("no README found for {owner}/{repo}")),
        403 => Err(format!(
            "GitHub rate-limited the README fetch for {owner}/{repo} \
             (set GITHUB_TOKEN to raise the 60/h limit)"
        )),
        c => Err(format!(
            "GitHub returned HTTP {c} for {owner}/{repo} README"
        )),
    }
}

/// `owner/repo` → `(owner, repo)`; a bare name → `("unpins", name)`. Any
/// `@version` suffix is dropped — a README isn't versioned here.
fn split_repo(pkg: &str) -> (String, String) {
    let pkg = pkg.split('@').next().unwrap_or(pkg);
    match pkg.split_once('/') {
        Some((owner, repo)) => (owner.to_owned(), repo.to_owned()),
        None => ("unpins".to_owned(), pkg.to_owned()),
    }
}

/// GitHub token from the same env vars unpin honors elsewhere, raising the API
/// limit from 60/h to 5000/h. Empty values are treated as unset.
fn token() -> Option<String> {
    ["GITHUB_TOKEN", "GH_TOKEN"]
        .into_iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::split_repo;

    #[test]
    fn bare_name_defaults_to_the_unpins_owner() {
        assert_eq!(split_repo("htop"), ("unpins".into(), "htop".into()));
    }

    #[test]
    fn explicit_owner_repo_is_kept() {
        assert_eq!(
            split_repo("BurntSushi/ripgrep"),
            ("BurntSushi".into(), "ripgrep".into())
        );
    }

    #[test]
    fn version_suffix_is_stripped() {
        assert_eq!(split_repo("htop@1.2.3"), ("unpins".into(), "htop".into()));
        assert_eq!(split_repo("owner/repo@v9"), ("owner".into(), "repo".into()));
    }
}
