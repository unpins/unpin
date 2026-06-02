//! Choosing one release asset to install and resolving its checksum.
//!
//! `pick_asset` is the main entry: filter by OS/arch keys, narrow when an
//! unambiguous match exists, prompt the user when `--pick` is set or when
//! ambiguity remains. `find_companion` pairs a primary asset with its data
//! tarball when the release ships one. `parse_sha256` + helpers consume the
//! checksum file the release publishes alongside the asset.

use std::io::{self, IsTerminal};

use indicatif::{MultiProgress, ProgressDrawTarget};

use super::prompt::{PromptResult, prompt_pick_with_skip};
use crate::ctx::Ctx;
use crate::github::{self, Asset};
use crate::platform;

/// True if `key` occurs in `haystack` as a delimited token — not embedded in a
/// longer alphanumeric run. Every standard release-naming convention writes the
/// architecture as a delimited field (Rust target triples `-x86_64-`, Debian/Go
/// `-amd64.`, `armv7-…`), so a short key like `x64`/`arm64` should match those
/// but never a coincidental substring inside an unrelated word (`x64` within
/// `vbox64`). A boundary is the string edge or any non-`[a-z0-9]` byte
/// (`-`, `_`, `.`). A key may carry its own internal separator (`x86_64`) —
/// only the bytes surrounding the match are checked, never the interior.
/// Both arguments are expected lowercase ASCII (asset names are lowercased by
/// the callers; the key tables are ASCII literals).
fn contains_arch_token(haystack: &str, key: &str) -> bool {
    let (hb, kb) = (haystack.as_bytes(), key.as_bytes());
    if kb.is_empty() || kb.len() > hb.len() {
        return false;
    }
    let is_word = |b: u8| b.is_ascii_alphanumeric();
    let mut i = 0;
    while i + kb.len() <= hb.len() {
        if &hb[i..i + kb.len()] == kb {
            let before_ok = i == 0 || !is_word(hb[i - 1]);
            let end = i + kb.len();
            let after_ok = end == hb.len() || !is_word(hb[end]);
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Classify an asset that should be excluded from the picker. Returns a short
/// human reason, or `None` if the asset is potentially installable.
pub fn classify_excluded(name_lower: &str) -> Option<&'static str> {
    if platform::other_os_keys()
        .iter()
        .any(|k| name_lower.contains(k))
    {
        return Some("other platform");
    }
    // Arch tokens match on a delimiter boundary (unlike the OS/auxiliary keys
    // above and below, which are distinctive words or `.ext` patterns). This
    // stops a short arch token from a wrong-arch exclusion firing on a glued
    // substring — and keeps the include side (Tier-1 in `narrow_assets`)
    // symmetric with this exclude side.
    if platform::other_arch_keys()
        .iter()
        .any(|k| contains_arch_token(name_lower, k))
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
            arch_keys.iter().any(|k| contains_arch_token(&l, k))
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

    // Toolchain tiebreak: a repo shipping >1 build for this exact OS+arch
    // (e.g. windows `-gnu` *and* `-msvc`, or linux `-gnu` *and* `-musl`) is
    // otherwise an ambiguous pick. Prefer the portable variant so the common
    // case resolves without a prompt; `--pick` keeps the full list to choose.
    if !force_pick {
        candidates = apply_toolchain_preference(candidates, platform::preferred_toolchain_keys());
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

/// Tiebreak among same-OS/arch candidates by toolchain/libc preference
/// (`prefer`, e.g. `["musl"]` on Linux, `["msvc"]` on Windows). Narrows to the
/// subset whose name contains a preferred token — but **only** when that's a
/// strict, non-empty subset, so it disambiguates without ever excluding the
/// sole build a repo ships. A list that can't be narrowed this way is returned
/// untouched and falls through to the picker / ambiguity error. Pure; the
/// preference table lives in `platform::preferred_toolchain_keys`.
fn apply_toolchain_preference<'a>(candidates: Vec<&'a Asset>, prefer: &[&str]) -> Vec<&'a Asset> {
    if prefer.is_empty() || candidates.len() < 2 {
        return candidates;
    }
    let preferred: Vec<&Asset> = candidates
        .iter()
        .copied()
        .filter(|a| {
            let l = a.name.to_ascii_lowercase();
            prefer.iter().any(|k| l.contains(k))
        })
        .collect();
    if !preferred.is_empty() && preferred.len() < candidates.len() {
        preferred
    } else {
        candidates
    }
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

/// One menu line for an asset: name, plus the GitHub-reported size when known.
/// Size `0` means the API elided it (older responses do), so the column is
/// suppressed rather than printing a misleading "0 B".
fn asset_label(a: &Asset) -> String {
    if a.size > 0 {
        format!("{}  ({})", a.name, indicatif::HumanBytes(a.size))
    } else {
        a.name.clone()
    }
}

/// Single-package adapter over the shared `prompt_pick_with_skip`. `run` and
/// `info` resolve exactly one asset, so a skip (Esc/q, or non-interactive
/// stdin) becomes a clean error rather than dropping silently.
pub(super) fn prompt_pick<'a>(candidates: &[&'a Asset]) -> Result<&'a Asset, String> {
    // Keep an explicit non-TTY message here: the shared picker just returns
    // Skip, but for a single-package caller "stdin is not a terminal" is far
    // more actionable than a generic "no asset selected".
    if !io::stdin().is_terminal() {
        return Err("multiple assets match and stdin is not a terminal; \
             re-run on a terminal to pick one"
            .into());
    }
    let header = if candidates.len() == 1 {
        "Available asset"
    } else {
        "Available assets"
    };
    let items: Vec<String> = candidates.iter().map(|a| asset_label(a)).collect();
    let multi = MultiProgress::with_draw_target(ProgressDrawTarget::hidden());
    match prompt_pick_with_skip(&multi, header, &items) {
        PromptResult::Got(i) => Ok(candidates[i]),
        PromptResult::Skip => Err("no asset selected".into()),
    }
}

/// Error for a non-interactive run that matched more than one installable
/// asset. Pulled out (and unit-tested) so the install/update pipeline fails
/// loudly with the exact choices instead of silently skipping the package with
/// a success exit code — the catalog (`unpins/*`) ships one asset per OS/arch
/// and never hits this, but third-party repos that publish e.g. both a
/// `-gnu` and a `-msvc` Windows build do.
pub fn ambiguous_assets_error(candidate_names: &[String]) -> String {
    let list = candidate_names
        .iter()
        .map(|n| format!("  {n}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "{n} release assets match this {os}/{arch}; unpin won't guess between them:\n{list}\n\
         Re-run in an interactive terminal to choose one.",
        n = candidate_names.len(),
        os = std::env::consts::OS,
        arch = std::env::consts::ARCH,
    )
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
/// run of *exactly* 64 consecutive ASCII-hex chars — short hex-looking words
/// ("SHA", "of") are what tripped a naive scanner, and an over-long run is not
/// a SHA-256 (a SHA-512 digest is 128 chars). Truncating a longer run to 64
/// would yield a bogus digest that then fails the comparison with a misleading
/// "checksum mismatch" instead of an honest "no sha256 here", so we skip runs
/// whose length isn't exactly 64 and keep scanning.
//
// TODO: we only consume `.sha256`/`.sha256sum` sidecars and only hash with
// sha2::Sha256 (see find_checksum_url + pipeline's Hashing). If we ever accept
// other algorithms (e.g. a `.sha512` sidecar), this scanner must match the
// digest length implied by the sidecar suffix (64 OR 128, …) rather than a
// fixed 64 — the "exact length" rule generalizes, the literal `64` does not.
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
        // `start` and `start + 64` both land on ASCII-hex bytes (start..i are
        // all < 0x80), so this byte-index slice can never split a UTF-8 char.
        if i - start == 64 {
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
    fn arch_token_matches_standard_conventions_not_glued_substrings() {
        // Delimited arch fields from real conventions match.
        assert!(contains_arch_token(
            "ripgrep-15.1.0-x86_64-unknown-linux-musl.tar.gz",
            "x86_64"
        ));
        assert!(contains_arch_token(
            "pandoc-3.9.0.2-linux-amd64.tar.gz",
            "amd64"
        ));
        assert!(contains_arch_token(
            "ripgrep-15.1.0-armv7-unknown-linux-gnueabihf.tar.gz",
            "armv7"
        ));
        assert!(contains_arch_token("tool-x64-linux.zip", "x64"));
        assert!(contains_arch_token("tool_amd64.deb", "amd64")); // `_`/`.` are boundaries
        assert!(contains_arch_token("rg-x86_64", "x86_64")); // end-of-string boundary

        // A short key glued inside a longer word must NOT match (the bug).
        assert!(!contains_arch_token("tool-linux-vbox64.tar.gz", "x64"));
        assert!(!contains_arch_token("max64.bin", "x64"));
        // Internal separator in the key is fine, but a trailing word char isn't.
        assert!(!contains_arch_token("tool-x86_64bit.zip", "x86_64"));
    }

    // Catalog (unpins) htop ships armv7l/armv6l with the `uname -m` `l` suffix.
    // Boundary matching means `armv7` no longer catches `armv7l`, so other_arch
    // must carry the `l` variants explicitly; assert the exclusion fires.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn other_arch_excludes_catalog_armv7l_on_x86_64() {
        assert_eq!(
            classify_excluded("htop-3.4.1-1-armv7l-linux.zst"),
            Some("other arch")
        );
        // The native asset is still accepted.
        assert_eq!(classify_excluded("htop-3.4.1-1-x86_64-linux.zst"), None);
    }

    // The dev box and most CI runners are linux/x86_64; gate the end-to-end
    // resolution check on it so the expected pick is unambiguous.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn narrow_assets_picks_the_right_real_world_asset() {
        let mk = |names: &[&str]| -> Vec<Asset> {
            names
                .iter()
                .map(|n| Asset {
                    name: (*n).into(),
                    browser_download_url: "u".into(),
                    size: 0,
                })
                .collect()
        };

        // ripgrep 15.1.0 (Rust target-triple naming), incl. the s390x asset
        // whose arch isn't in our tables — Tier-1 must still narrow to musl.
        let rg = mk(&[
            "ripgrep-15.1.0-aarch64-unknown-linux-gnu.tar.gz",
            "ripgrep-15.1.0-armv7-unknown-linux-gnueabihf.tar.gz",
            "ripgrep-15.1.0-i686-unknown-linux-gnu.tar.gz",
            "ripgrep-15.1.0-s390x-unknown-linux-gnu.tar.gz",
            "ripgrep-15.1.0-x86_64-apple-darwin.tar.gz",
            "ripgrep-15.1.0-x86_64-pc-windows-msvc.zip",
            "ripgrep-15.1.0-x86_64-unknown-linux-musl.tar.gz",
            "ripgrep_15.1.0-1_amd64.deb",
        ]);
        let got = narrow_assets(&rg, "ripgrep", false, false).unwrap();
        assert_eq!(
            got.len(),
            1,
            "candidates: {:?}",
            got.iter().map(|a| &a.name).collect::<Vec<_>>()
        );
        assert_eq!(
            got[0].name,
            "ripgrep-15.1.0-x86_64-unknown-linux-musl.tar.gz"
        );

        // pandoc 3.9.0.2 (os-amd64 / Debian-style naming).
        let pd = mk(&[
            "pandoc-3.9.0.2-1-amd64.deb",
            "pandoc-3.9.0.2-arm64-macOS.zip",
            "pandoc-3.9.0.2-linux-amd64.tar.gz",
            "pandoc-3.9.0.2-linux-arm64.tar.gz",
            "pandoc-3.9.0.2-windows-x86_64.zip",
            "pandoc.wasm.zip",
        ]);
        let got = narrow_assets(&pd, "pandoc", false, false).unwrap();
        assert_eq!(
            got.len(),
            1,
            "candidates: {:?}",
            got.iter().map(|a| &a.name).collect::<Vec<_>>()
        );
        assert_eq!(got[0].name, "pandoc-3.9.0.2-linux-amd64.tar.gz");

        // unpins catalog htop v3.4.1-1: canonical <pkg>-<tag>-<arch>-<os>.zst,
        // incl. the armv7l/i686/ppc64le/riscv64 arms that must all be excluded.
        let ht = mk(&[
            "htop-3.4.1-1-aarch64-darwin.zst",
            "htop-3.4.1-1-aarch64-linux.zst",
            "htop-3.4.1-1-armv7l-linux.zst",
            "htop-3.4.1-1-data.tar.zst",
            "htop-3.4.1-1-i686-linux.zst",
            "htop-3.4.1-1-ppc64le-linux.zst",
            "htop-3.4.1-1-riscv64-linux.zst",
            "htop-3.4.1-1-x86_64-darwin.zst",
            "htop-3.4.1-1-x86_64-linux.zst",
        ]);
        let got = narrow_assets(&ht, "htop", false, false).unwrap();
        assert_eq!(
            got.len(),
            1,
            "candidates: {:?}",
            got.iter().map(|a| &a.name).collect::<Vec<_>>()
        );
        assert_eq!(got[0].name, "htop-3.4.1-1-x86_64-linux.zst");
    }

    // A repo that ships both glibc and musl x86_64-linux builds (sharkdp/fd,
    // eza, …) used to be an ambiguous pick; the musl preference now auto-picks
    // the static build, while `--pick` still surfaces both.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn narrow_prefers_musl_for_multivariant_linux_repo() {
        let mk = |names: &[&str]| -> Vec<Asset> {
            names
                .iter()
                .map(|n| Asset {
                    name: (*n).into(),
                    browser_download_url: "u".into(),
                    size: 0,
                })
                .collect()
        };
        let fd = mk(&[
            "fd-v10.4.2-aarch64-unknown-linux-musl.tar.gz",
            "fd-v10.4.2-x86_64-pc-windows-gnu.zip",
            "fd-v10.4.2-x86_64-unknown-linux-gnu.tar.gz",
            "fd-v10.4.2-x86_64-unknown-linux-musl.tar.gz",
        ]);
        let got = narrow_assets(&fd, "fd", false, false).unwrap();
        assert_eq!(
            got.len(),
            1,
            "candidates: {:?}",
            got.iter().map(|a| &a.name).collect::<Vec<_>>()
        );
        assert_eq!(got[0].name, "fd-v10.4.2-x86_64-unknown-linux-musl.tar.gz");

        // `--pick` keeps both x86_64-linux variants so the user can choose.
        let picked = narrow_assets(&fd, "fd", true, false).unwrap();
        assert!(
            picked.len() >= 2 && picked.iter().any(|a| a.name.contains("gnu")),
            "picked: {:?}",
            picked.iter().map(|a| &a.name).collect::<Vec<_>>()
        );
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
    fn prompt_pick_errors_clearly_when_stdin_is_not_a_terminal() {
        // Under `cargo test` stdin is piped, so prompt_pick can't read a
        // choice. It must fail with the non-TTY message — not the old
        // misleading "invalid choice" that EOF used to produce.
        let a = Asset {
            name: "tool-linux".into(),
            browser_download_url: "u1".into(),
            size: 0,
        };
        let b = Asset {
            name: "tool-mac".into(),
            browser_download_url: "u2".into(),
            size: 0,
        };
        let candidates = vec![&a, &b];
        let err = prompt_pick(&candidates).unwrap_err();
        assert!(err.contains("not a terminal"), "got: {err}");
    }

    #[test]
    fn toolchain_preference_narrows_to_preferred_subset() {
        let mk = |n: &str| Asset {
            name: n.into(),
            browser_download_url: "u".into(),
            size: 0,
        };
        // Windows split — preference passed explicitly, so this is
        // host-independent (the cfg table is exercised via narrow_assets below).
        let gnu = mk("ripgrep-15.1.0-x86_64-pc-windows-gnu.zip");
        let msvc = mk("ripgrep-15.1.0-x86_64-pc-windows-msvc.zip");
        let got = apply_toolchain_preference(vec![&gnu, &msvc], &["msvc"]);
        assert_eq!(got.len(), 1);
        assert!(got[0].name.contains("msvc"), "got: {}", got[0].name);

        // Linux split.
        let lg = mk("fd-x86_64-unknown-linux-gnu.tar.gz");
        let lm = mk("fd-x86_64-unknown-linux-musl.tar.gz");
        let got = apply_toolchain_preference(vec![&lg, &lm], &["musl"]);
        assert_eq!(got.len(), 1);
        assert!(got[0].name.contains("musl"), "got: {}", got[0].name);
    }

    #[test]
    fn toolchain_preference_is_a_noop_when_it_cannot_disambiguate() {
        let mk = |n: &str| Asset {
            name: n.into(),
            browser_download_url: "u".into(),
            size: 0,
        };
        let a = mk("tool-x86_64-linux-gnu.tar.gz");
        let b = mk("tool-x86_64-linux-uclibc.tar.gz");
        // No candidate carries the preferred token → unchanged, so a repo that
        // ships only non-preferred builds still installs (just stays ambiguous).
        assert_eq!(apply_toolchain_preference(vec![&a, &b], &["musl"]).len(), 2);
        // A single candidate is never touched, even if it lacks the token.
        assert_eq!(apply_toolchain_preference(vec![&a], &["musl"]).len(), 1);
        // Empty preference table (macOS) → unchanged.
        assert_eq!(apply_toolchain_preference(vec![&a, &b], &[]).len(), 2);
    }

    #[test]
    fn ambiguous_assets_error_lists_every_candidate() {
        // The non-interactive ambiguity failure must name each choice (so the
        // user can pick one on a terminal) and state the count — it replaced a
        // silent exit-0 skip, so the wording is the only signal the user gets.
        let names = vec![
            "ripgrep-15.1.0-x86_64-pc-windows-gnu.zip".to_owned(),
            "ripgrep-15.1.0-x86_64-pc-windows-msvc.zip".to_owned(),
        ];
        let msg = ambiguous_assets_error(&names);
        assert!(msg.contains("2 release assets"), "got: {msg}");
        assert!(msg.contains("windows-gnu.zip"), "got: {msg}");
        assert!(msg.contains("windows-msvc.zip"), "got: {msg}");
        assert!(msg.contains("interactive terminal"), "got: {msg}");
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

    #[test]
    fn parse_sha256_skips_overlong_run_and_finds_exact_64() {
        // A combined sidecar listing SHA-512 (128 hex) before SHA-256 (64 hex).
        // The old `>= 64` matched the first 64 chars of the 512 digest — a
        // bogus value. We must skip the over-long run and return the real 64.
        let sha512 = "a".repeat(128);
        let sha256 = "b".repeat(64);
        let body = format!("SHA512: {sha512}\nSHA256: {sha256}\n");
        assert_eq!(parse_sha256(&body).unwrap(), sha256);
    }

    #[test]
    fn parse_sha256_rejects_lone_overlong_run() {
        // Only a SHA-512 in the file: we can't derive a SHA-256 from it, so
        // fail honestly rather than truncate to a wrong digest.
        let body = "c".repeat(128);
        assert!(parse_sha256(&body).is_err());
    }

    #[test]
    fn parse_sha256_handles_non_ascii_without_panicking() {
        // The byte-index slice must never split a multi-byte UTF-8 char. Wrap a
        // valid digest in non-ASCII prose; the hex run is pure ASCII, so the
        // slice stays on char boundaries.
        let digest = "d".repeat(64);
        let body = format!("checksum café ☕ → {digest} ✓ naïve\n");
        assert_eq!(parse_sha256(&body).unwrap(), digest);
        // Non-ASCII only, no hex run of 64 → clean error, no panic.
        assert!(parse_sha256("résumé café ☕ ☃ 日本語").is_err());
    }
}
