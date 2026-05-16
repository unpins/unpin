//! Choosing one release asset to install and resolving its checksum.
//!
//! `pick_asset` is the main entry: filter by OS/arch keys, narrow when an
//! unambiguous match exists, prompt the user when `--pick` is set or when
//! ambiguity remains. `find_companion` pairs a primary asset with its data
//! tarball when the release ships one. `parse_sha256` + helpers consume the
//! checksum file the release publishes alongside the asset.

use std::io::{self, Write};

use crate::ctx::Ctx;
use crate::github::{self, Asset};
use crate::platform;

/// Classify an asset that should be excluded from the picker. Returns a short
/// human reason, or `None` if the asset is potentially installable.
pub fn classify_excluded(name_lower: &str) -> Option<&'static str> {
    if platform::other_os_keys()
        .iter()
        .any(|k| name_lower.contains(k))
    {
        return Some("other platform");
    }
    if platform::other_arch_keys()
        .iter()
        .any(|k| name_lower.contains(k))
    {
        return Some("other arch");
    }
    if platform::auxiliary_keys()
        .iter()
        .any(|k| name_lower.contains(k))
    {
        return Some("auxiliary");
    }
    if name_lower.contains(".bsdiff") {
        return Some("unsupported format");
    }
    // Data companion of another release asset: `<pkg>-<tag>-data.tar.zst`. One
    // per release (platform-agnostic runtime data, e.g. vim/share/vim/<ver>).
    // Excluded from the picker — preflight pairs it with the primary by tag.
    if name_lower.ends_with("-data.tar.zst") {
        return Some("data companion");
    }
    if !platform::current_os_keys()
        .iter()
        .any(|k| name_lower.contains(k))
    {
        return Some("no OS tag");
    }
    None
}

/// Filter+narrow the release's assets down to those that match the current
/// platform. Pure compute — never prompts and never touches stdin/stdout.
/// `pick_asset` wraps this with the interactive prompt when narrowing
/// leaves more than one candidate (or `--pick` forces a prompt).
///
/// Returns the final candidate list (always non-empty). When the list has
/// exactly one element and `!force_pick`, the caller can use it directly;
/// otherwise the caller must prompt. Errors only when no asset matches
/// the platform at all.
pub fn narrow_assets<'a>(
    assets: &'a [Asset],
    repo_name: &str,
    force_pick: bool,
    verbose: bool,
) -> Result<Vec<&'a Asset>, String> {
    let arch_keys = platform::current_arch_keys();

    let mut selectable: Vec<&Asset> = Vec::new();
    let mut ignored: Vec<(&Asset, &'static str)> = Vec::new();
    for a in assets {
        let l = a.name.to_ascii_lowercase();
        match classify_excluded(&l) {
            Some(reason) => ignored.push((a, reason)),
            None => selectable.push(a),
        }
    }

    // Tier 1: linux + explicit arch tag. Tier 2 (fallback): linux only.
    let with_arch: Vec<&Asset> = selectable
        .iter()
        .copied()
        .filter(|a| {
            let l = a.name.to_ascii_lowercase();
            arch_keys.iter().any(|k| l.contains(k))
        })
        .collect();
    let mut candidates = if with_arch.is_empty() {
        selectable.clone()
    } else {
        with_arch
    };

    // Narrow to `<repo>-<arch>` etc. when auto-picking; --pick keeps the
    // full selectable list so the user can choose alternates.
    if !force_pick && candidates.len() > 1 {
        let repo_lower = repo_name.to_ascii_lowercase();
        let narrowed: Vec<&Asset> = candidates
            .iter()
            .copied()
            .filter(|a| {
                let l = a.name.to_ascii_lowercase();
                let Some(rest) = l.strip_prefix(&repo_lower) else {
                    return false;
                };
                let Some(sep) = rest.chars().next() else {
                    return false;
                };
                if !matches!(sep, '-' | '_' | '.') {
                    return false;
                }
                let after_sep = &rest[sep.len_utf8()..];
                arch_keys.iter().any(|k| after_sep.starts_with(k))
            })
            .collect();
        if !narrowed.is_empty() {
            candidates = narrowed;
        }
    }

    if verbose && !ignored.is_empty() {
        let w = ignored.iter().map(|(a, _)| a.name.len()).max().unwrap_or(0);
        eprintln!("Ignored {} assets:", ignored.len());
        for (a, reason) in &ignored {
            eprintln!("  {:<w$}  ({reason})", a.name);
        }
    }

    if candidates.is_empty() {
        return Err(format!(
            "no matching {os} {arch} asset.\nAvailable assets:\n{list}",
            os = std::env::consts::OS,
            arch = std::env::consts::ARCH,
            list = assets
                .iter()
                .map(|a| format!("  {}", a.name))
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }
    Ok(candidates)
}

pub fn pick_asset<'a>(
    assets: &'a [Asset],
    repo_name: &str,
    force_pick: bool,
    verbose: bool,
) -> Result<&'a Asset, String> {
    let candidates = narrow_assets(assets, repo_name, force_pick, verbose)?;
    if !force_pick && candidates.len() == 1 {
        return Ok(candidates[0]);
    }
    prompt_pick(&candidates)
}

pub(super) fn prompt_pick<'a>(candidates: &[&'a Asset]) -> Result<&'a Asset, String> {
    let header = if candidates.len() == 1 {
        "Available asset:"
    } else {
        "Available assets:"
    };
    println!("{header}");
    let name_w = candidates.iter().map(|a| a.name.len()).max().unwrap_or(0);
    for (i, a) in candidates.iter().enumerate() {
        // GitHub-reported size on the right; some older API responses elide
        // it (size == 0), so suppress the column for those entries rather
        // than print a misleading "0 B".
        if a.size > 0 {
            println!(
                "  [{}] {:<name_w$}  ({})",
                i + 1,
                a.name,
                indicatif::HumanBytes(a.size),
            );
        } else {
            println!("  [{}] {}", i + 1, a.name);
        }
    }
    print!("Pick [1-{}]: ", candidates.len());
    io::stdout().flush().ok();
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("stdin: {e}"))?;
    let idx: usize = line
        .trim()
        .parse()
        .map_err(|_| "invalid choice".to_string())?;
    if idx < 1 || idx > candidates.len() {
        return Err("choice out of range".into());
    }
    Ok(candidates[idx - 1])
}

/// Find `<pkg>-<tag>-data.tar.zst` in the release's assets. Tries both raw
/// `tag` and `v`-stripped (GitHub releases typically tag as `v9.2.0` but our
/// build emits the data asset using the bare version). Returns `None` for
/// packages that don't ship a runtime tarball.
pub fn find_companion<'a>(pkg: &str, tag: &str, assets: &'a [Asset]) -> Option<&'a Asset> {
    let pkg_l = pkg.to_ascii_lowercase();
    let tag_l = tag.to_ascii_lowercase();
    let tag_v = tag_l.trim_start_matches('v');
    let candidates = [
        format!("{pkg_l}-{tag_l}-data.tar.zst"),
        format!("{pkg_l}-{tag_v}-data.tar.zst"),
    ];
    assets.iter().find(|a| {
        let n = a.name.to_ascii_lowercase();
        candidates.contains(&n)
    })
}

pub fn find_checksum_url(assets: &[Asset], asset_name: &str) -> Option<String> {
    for suffix in [".sha256", ".sha256sum"] {
        let want = format!("{asset_name}{suffix}");
        if let Some(a) = assets.iter().find(|a| a.name == want) {
            return Some(a.browser_download_url.clone());
        }
    }
    None
}

pub fn fetch_expected_sha256(ctx: &Ctx, url: &str) -> Result<String, String> {
    let body = github::download(ctx, url)?;
    let text = std::str::from_utf8(&body).map_err(|e| format!("checksum body: {e}"))?;
    parse_sha256(text)
}

/// Extract a SHA-256 digest from a per-asset checksum file. Some projects ship
/// `<hex>  <filename>` (sha256sum format); others wrap the digest in prose
/// (e.g. ripgrep's "SHA256 hash of ...zip:\n<hex>\n"). We look for the first
/// run of >= 64 consecutive ASCII-hex chars — short hex-looking words ("SHA",
/// "of") are what tripped a naive scanner.
fn parse_sha256(text: &str) -> Result<String, String> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_hexdigit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
            i += 1;
        }
        if i - start >= 64 {
            return Ok(text[start..start + 64].to_ascii_lowercase());
        }
    }
    Err("malformed checksum file".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_picks_up_other_os_assets() {
        #[cfg(target_os = "linux")]
        assert_eq!(
            classify_excluded("tool-darwin-x86_64.tar.gz"),
            Some("other platform")
        );
        #[cfg(target_os = "linux")]
        assert_eq!(
            classify_excluded("tool-windows-x86_64.zip"),
            Some("other platform")
        );
    }

    #[test]
    fn classify_filters_other_arch() {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        assert_eq!(
            classify_excluded("tool-linux-aarch64.tar.gz"),
            Some("other arch")
        );
    }

    #[test]
    fn classify_excludes_auxiliary() {
        assert_eq!(
            classify_excluded("rg-14.1.0-linux.tar.gz.sha256"),
            Some("auxiliary")
        );
        assert_eq!(
            classify_excluded("rg-14.1.0-linux.tar.gz.sig"),
            Some("auxiliary")
        );
        assert_eq!(classify_excluded("rg-14.1.0.deb"), Some("auxiliary"));
        assert_eq!(classify_excluded("rg-14.1.0.rpm"), Some("auxiliary"));
        assert_eq!(classify_excluded("rg-14.1.0.appimage"), Some("auxiliary"));
    }

    #[test]
    fn classify_excludes_bsdiff() {
        assert_eq!(
            classify_excluded("update.bsdiff"),
            Some("unsupported format")
        );
    }

    #[test]
    fn classify_accepts_bare_zst_binary() {
        #[cfg(target_os = "linux")]
        assert_eq!(classify_excluded("gvim-9.2.0-x86_64-linux.zst"), None);
        #[cfg(target_os = "linux")]
        assert!(classify_excluded("gvim-9.2.0-x86_64-windows.exe.zst").is_some());
    }

    #[test]
    fn classify_excludes_data_companion() {
        assert_eq!(
            classify_excluded("gvim-9.2.0-data.tar.zst"),
            Some("data companion")
        );
        assert_eq!(
            classify_excluded("gvim-v9.2.0-data.tar.zst"),
            Some("data companion")
        );
        assert_ne!(
            classify_excluded("rg-linux.tar.zst"),
            Some("data companion")
        );
    }

    #[test]
    fn classify_rejects_asset_with_no_os_tag() {
        #[cfg(target_os = "linux")]
        assert_eq!(classify_excluded("tool-generic.tar.gz"), Some("no OS tag"));
    }

    #[test]
    fn classify_accepts_current_os_asset() {
        #[cfg(target_os = "linux")]
        assert_eq!(classify_excluded("rg-14.1.0-x86_64-linux.tar.gz"), None);
        #[cfg(target_os = "macos")]
        assert_eq!(classify_excluded("rg-14.1.0-x86_64-darwin.tar.gz"), None);
    }

    #[test]
    fn find_companion_matches_tagged_data_asset() {
        let assets = vec![
            Asset {
                name: "gvim-9.2.0-x86_64-linux.zst".into(),
                browser_download_url: "u1".into(),
                size: 0,
            },
            Asset {
                name: "gvim-9.2.0-x86_64-windows.exe.zst".into(),
                browser_download_url: "u2".into(),
                size: 0,
            },
            Asset {
                name: "gvim-9.2.0-data.tar.zst".into(),
                browser_download_url: "u3".into(),
                size: 0,
            },
        ];
        let c = find_companion("gvim", "v9.2.0", &assets).unwrap();
        assert_eq!(c.name, "gvim-9.2.0-data.tar.zst");
        let c2 = find_companion("gvim", "9.2.0", &assets).unwrap();
        assert_eq!(c2.name, "gvim-9.2.0-data.tar.zst");
    }

    #[test]
    fn find_companion_returns_none_when_absent() {
        let assets = vec![Asset {
            name: "tree-2.2.1-x86_64-linux.zst".into(),
            browser_download_url: "u".into(),
            size: 0,
        }];
        assert!(find_companion("tree", "v2.2.1", &assets).is_none());
    }

    #[test]
    fn parse_sha256_accepts_sha256sum_format() {
        let body = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789  rg.tar.gz\n";
        let got = parse_sha256(body).unwrap();
        assert_eq!(
            got,
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        );
    }

    #[test]
    fn parse_sha256_handles_ripgrep_prose_format() {
        let body = "SHA256 hash of ripgrep-15.1.0-x86_64-pc-windows-gnu.zip:\r\n\
                    9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08\r\n";
        let got = parse_sha256(body).unwrap();
        assert_eq!(
            got,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[test]
    fn parse_sha256_lowercases_uppercase_hex() {
        let body = "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF";
        assert_eq!(
            parse_sha256(body).unwrap(),
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        );
    }

    #[test]
    fn parse_sha256_rejects_short_runs() {
        let body = "a".repeat(63);
        assert!(parse_sha256(&body).is_err());
    }

    #[test]
    fn parse_sha256_rejects_empty_and_no_hex() {
        assert!(parse_sha256("").is_err());
        assert!(parse_sha256("no digest here").is_err());
        assert!(parse_sha256("SHA256 hash of foo.zip:").is_err());
    }

    #[test]
    fn parse_sha256_ignores_long_runs_after_first_match() {
        let body = "1111111111111111111111111111111111111111111111111111111111111111\n\
                    2222222222222222222222222222222222222222222222222222222222222222";
        assert_eq!(
            parse_sha256(body).unwrap(),
            "1111111111111111111111111111111111111111111111111111111111111111"
        );
    }
}
