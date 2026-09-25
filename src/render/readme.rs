//! `unpin readme` — render a program's README markdown in the terminal, paged.
//!
//! Cheapest source first: `-` (stdin, for piping/testing), the package's
//! embedded `unpin/readme/README.md` bundle entry (offline, fast), then a fetch
//! from the upstream GitHub repo as a fallback (until READMEs are embedded). The
//! markdown is rendered with termimad and paged with the shared reflowing pager,
//! which re-renders at the live width on each resize.
//!
//! This was the `unpins/unpin-readme` package, which shelled out to read the
//! bundle; folded in, it reads the bundle directly in-process. The repo-fetch
//! fallback is ported from that package.

use std::io::Read;

use nanoserde::DeJson;
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
    check_spelling(pkg, &owner, &repo)?;
    // `raw` media type returns the file bytes directly, not base64 JSON.
    let resp = api_get(
        &format!("https://api.github.com/repos/{owner}/{repo}/readme"),
        "application/vnd.github.raw+json",
    )
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

fn api_get(url: &str, accept: &str) -> Result<minreq::Response, minreq::Error> {
    let mut req = minreq::get(url)
        .with_header("Accept", accept)
        .with_header("User-Agent", "unpin")
        .with_timeout(30);
    if let Some(tok) = token() {
        req = req.with_header("Authorization", format!("Bearer {tok}"));
    }
    req.send()
}

#[derive(DeJson)]
struct RepoInfo {
    full_name: String,
}

/// GitHub answers `unpins/Tree` with the `unpins/tree` README, but a package is
/// named only as GitHub spells it, as in `unpin install`. Any failure to learn
/// the spelling is left to the README fetch to report.
fn check_spelling(pkg: &str, owner: &str, repo: &str) -> Result<(), String> {
    let Ok(resp) = api_get(
        &format!("https://api.github.com/repos/{owner}/{repo}"),
        "application/vnd.github+json",
    ) else {
        return Ok(());
    };
    if resp.status_code != 200 {
        return Ok(());
    }
    let Some(info) = resp
        .as_str()
        .ok()
        .and_then(|b| RepoInfo::deserialize_json(b).ok())
    else {
        return Ok(());
    };
    match misspelling(pkg, owner, repo, &info.full_name) {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// The error for `pkg` (resolved to `owner/repo`) when GitHub spells the repo
/// `full_name`, or `None` when the spellings agree.
fn misspelling(pkg: &str, owner: &str, repo: &str, full_name: &str) -> Option<String> {
    if full_name == format!("{owner}/{repo}") {
        return None;
    }
    let (name, version) = pkg.split_at(pkg.find('@').unwrap_or(pkg.len()));
    let right = match full_name.split_once('/') {
        Some(("unpins", repo)) if !name.contains('/') => repo,
        _ => full_name,
    };
    Some(format!(
        "no package named `{pkg}` (did you mean `{right}{version}`?)"
    ))
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
    use super::{misspelling, split_repo};

    #[test]
    fn repo_spelling_must_match_github() {
        assert_eq!(misspelling("tree", "unpins", "tree", "unpins/tree"), None);
        assert_eq!(
            misspelling("Tree", "unpins", "Tree", "unpins/tree").as_deref(),
            Some("no package named `Tree` (did you mean `tree`?)")
        );
        // A version is kept, as `unpin install` does.
        assert_eq!(
            misspelling("Tree@v1", "unpins", "Tree", "unpins/tree").as_deref(),
            Some("no package named `Tree@v1` (did you mean `tree@v1`?)")
        );
        assert_eq!(
            misspelling(
                "burntsushi/ripgrep",
                "burntsushi",
                "ripgrep",
                "BurntSushi/ripgrep"
            )
            .as_deref(),
            Some("no package named `burntsushi/ripgrep` (did you mean `BurntSushi/ripgrep`?)")
        );
    }

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
