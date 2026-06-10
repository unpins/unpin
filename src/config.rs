//! Flat `key = value` config with `#` comments. Loaded from
//! [`platform::config_path`]; a missing file is treated as empty so defaults
//! apply.
//!
//! Grammar (per line):
//!   `# ...`                  → comment, skipped
//!   blank                    → skipped
//!   `<key> = <value>`        → key/value pair; both sides trimmed
//!   anything after a `#`     → stripped as inline comment (values are scalars
//!                              like ints/bools, so `#` never appears inside;
//!                              a future key whose value could legitimately
//!                              contain `#` — a path or URL — would need
//!                              quoting support added here first)
//!
//! No sections, no quoting, no escapes — intentionally smaller than INI.
//! Unknown keys are kept in the map and silently ignored; bad values fall back
//! to the key's default (so a typo in `http_timeout` doesn't crash unpin).

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

use crate::aliases::AliasMode;

#[derive(Debug, Default)]
pub struct Config {
    map: HashMap<String, String>,
}

impl Config {
    /// Read and parse the user's config file. Missing file → empty `Config`.
    /// The path comes from the pre-resolved [`crate::platform::Paths`] so the
    /// env-var resolution (and its fail-loud check) happens once at startup.
    pub fn load(config_path: &Path) -> Self {
        let text = std::fs::read_to_string(config_path).unwrap_or_default();
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Self {
        let mut map = HashMap::new();
        for line in text.lines() {
            let line = match line.split_once('#') {
                Some((before, _)) => before,
                None => line,
            };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                map.insert(k.trim().to_owned(), v.trim().to_owned());
            }
        }
        Self { map }
    }

    fn get_bool(&self, key: &str) -> Option<bool> {
        let v = self.map.get(key)?.to_ascii_lowercase();
        match v.as_str() {
            "true" | "yes" | "1" => Some(true),
            "false" | "no" | "0" => Some(false),
            _ => None,
        }
    }

    /// Per-request HTTP timeout in seconds. Default 30.
    pub fn http_timeout(&self) -> u64 {
        self.map
            .get("http_timeout")
            .and_then(|s| s.parse().ok())
            .unwrap_or(30)
    }

    /// Opt into shelling out to `gh auth token` for GitHub auth. Default false
    /// (security-conservative: the `gh` login token usually carries broad
    /// scopes like `repo`+`workflow`, far wider than the read-only release
    /// metadata unpin actually needs).
    pub fn use_gh_auth(&self) -> bool {
        self.get_bool("use_gh_auth").unwrap_or(false)
    }

    /// Whether to download the per-release runtime data tarball
    /// (`<pkg>-<tag>-data.tar.zst`) alongside the primary binary. Default true.
    /// CLI `--no-data` overrides this to false for a single invocation.
    pub fn data(&self) -> bool {
        self.get_bool("data").unwrap_or(true)
    }

    /// How to handle multi-call aliases declared by a catalog package's
    /// embedded `unpin/aliases`. Default [`AliasMode::Yes`] — install them
    /// silently and print the list. CLI `--aliases` / `--no-aliases` and
    /// the per-install prompt (when `ask`) override this for a single
    /// invocation. Garbage values fall back to the default.
    ///
    /// Aliases are *always* off for non-catalog `<owner>/<repo>` installs
    /// regardless of this setting — the catalog gate is enforced at the
    /// install site, not here.
    pub fn aliases(&self) -> AliasMode {
        self.map
            .get("aliases")
            .and_then(|s| AliasMode::parse(s))
            .unwrap_or(AliasMode::Yes)
    }

    /// Opt-in resolver(s) for the built-in DNS fallback — space-separated IPv4
    /// literals. `None` (the default) leaves the fallback **off**: a host whose
    /// system resolver can't be reached surfaces the real error, and unpin then
    /// teaches the user how to turn this on (see [`crate::dns`]). The C shim
    /// (nix-lib/dns-fallback) reads this same key directly, so the setting
    /// applies to *every* unpins program, not just unpin.
    pub fn dns(&self) -> Option<String> {
        self.map.get("dns").filter(|s| !s.is_empty()).cloned()
    }
}

/// The `key` a config line declares, or `None` for a blank/comment/`=`-less
/// line. Mirrors [`Config::parse`]'s grammar (inline `#` comment, trim, split
/// on the first `=`) so [`write_dns`] can recognize — and drop — existing
/// entries for a key without disturbing any other line.
fn line_key(line: &str) -> Option<String> {
    let line = match line.split_once('#') {
        Some((before, _)) => before,
        None => line,
    };
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let (k, _) = line.split_once('=')?;
    Some(k.trim().to_owned())
}

/// Persist `dns = <value>` into the config file at `path`, preserving every
/// other line verbatim. Any prior `dns` line is dropped (so re-saving never
/// piles up duplicates) and one canonical line is appended. Creates the parent
/// directory if needed, and writes atomically via a temp file + rename so a
/// crash or full disk can't leave a half-written config behind.
pub fn write_dns(path: &Path, value: &str) -> io::Result<()> {
    let existing = fs::read_to_string(path).unwrap_or_default();
    let mut out = String::new();
    for line in existing.lines() {
        if line_key(line).as_deref() == Some("dns") {
            continue; // replaced by the canonical line appended below
        }
        out.push_str(line);
        out.push('\n');
    }
    out.push_str(&format!("dns = {value}\n"));

    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    // Temp + rename keeps the write atomic: a reader (including the C shim)
    // never sees a partial file. The temp lives in the same dir so the rename
    // stays on one filesystem; the leading dot and pid keep it out of the way
    // and collision-free against a concurrent save.
    let file_name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "config path has no file name")
    })?;
    let tmp = path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()));
    fs::write(&tmp, out.as_bytes())?;
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_skips_blank_and_comment_lines() {
        let cfg = Config::parse("\n# top\n  \n  # indented\n");
        assert!(cfg.map.is_empty());
    }

    #[test]
    fn parse_keeps_key_value_pairs() {
        let cfg = Config::parse("http_timeout = 60\nuse_gh_auth = true\n");
        assert_eq!(cfg.http_timeout(), 60);
        assert!(cfg.use_gh_auth());
    }

    #[test]
    fn parse_trims_whitespace_on_both_sides() {
        let cfg = Config::parse("   key   =   value with spaces   \n");
        assert_eq!(
            cfg.map.get("key").map(String::as_str),
            Some("value with spaces"),
        );
    }

    #[test]
    fn parse_strips_inline_comments() {
        let cfg = Config::parse("http_timeout = 30 # default\n");
        assert_eq!(cfg.http_timeout(), 30);
    }

    #[test]
    fn parse_last_wins_on_duplicate_keys() {
        // Common when a user appends an override at the bottom of the file.
        let cfg = Config::parse("http_timeout = 1\nhttp_timeout = 2\n");
        assert_eq!(cfg.http_timeout(), 2);
    }

    #[test]
    fn parse_ignores_lines_without_equals() {
        let cfg = Config::parse("garbage line\nuse_gh_auth = true\n");
        assert_eq!(cfg.map.len(), 1);
        assert!(cfg.use_gh_auth());
    }

    #[test]
    fn defaults_for_empty_config() {
        let cfg = Config::default();
        assert_eq!(cfg.http_timeout(), 30);
        assert!(!cfg.use_gh_auth());
        assert!(cfg.data());
        assert_eq!(cfg.aliases(), AliasMode::Yes);
    }

    #[test]
    fn aliases_parses_each_mode_and_falls_back_on_garbage() {
        for (text, want) in [
            ("aliases = yes\n", AliasMode::Yes),
            ("aliases = no\n", AliasMode::No),
            ("aliases = ask\n", AliasMode::Ask),
            ("aliases = ASK\n", AliasMode::Ask),
        ] {
            assert_eq!(Config::parse(text).aliases(), want, "parsing `{text}`");
        }
        // Garbage value falls back to default Yes — same forgiving model
        // as http_timeout.
        assert_eq!(Config::parse("aliases = maybe\n").aliases(), AliasMode::Yes);
    }

    #[test]
    fn http_timeout_falls_back_on_garbage_value() {
        let cfg = Config::parse("http_timeout = not_a_number\n");
        assert_eq!(cfg.http_timeout(), 30);
    }

    #[test]
    fn dns_reads_value_and_defaults_to_none() {
        assert_eq!(Config::default().dns(), None);
        // Empty value counts as unset, not as a configured-but-blank resolver.
        assert_eq!(Config::parse("dns =\n").dns(), None);
        assert_eq!(
            Config::parse("dns = 1.1.1.1 8.8.8.8\n").dns().as_deref(),
            Some("1.1.1.1 8.8.8.8"),
        );
        // Last-wins, same as every other key.
        assert_eq!(
            Config::parse("dns = 9.9.9.9\ndns = 1.0.0.1\n")
                .dns()
                .as_deref(),
            Some("1.0.0.1"),
        );
    }

    #[test]
    fn write_dns_appends_to_a_fresh_config() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("unpin").join("config");
        write_dns(&path, "1.1.1.1 8.8.8.8").unwrap();
        let cfg = Config::load(&path);
        assert_eq!(cfg.dns().as_deref(), Some("1.1.1.1 8.8.8.8"));
    }

    #[test]
    fn write_dns_replaces_prior_entry_and_keeps_other_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config");
        std::fs::write(
            &path,
            "# my config\nhttp_timeout = 60\ndns = 9.9.9.9\nuse_gh_auth = true\n",
        )
        .unwrap();
        write_dns(&path, "1.1.1.1").unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        // Exactly one dns line, the new value; the others survive untouched.
        assert_eq!(text.matches("dns =").count(), 1, "no duplicate dns lines");
        let cfg = Config::parse(&text);
        assert_eq!(cfg.dns().as_deref(), Some("1.1.1.1"));
        assert_eq!(cfg.http_timeout(), 60);
        assert!(cfg.use_gh_auth());
        assert!(text.contains("# my config"), "comment preserved");
    }

    #[test]
    fn write_dns_round_trips_through_the_reader() {
        // The on-disk text must parse back to the value the C shim would read.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config");
        write_dns(&path, "1.0.0.1").unwrap();
        write_dns(&path, "8.8.4.4").unwrap(); // overwrite, not append
        assert_eq!(Config::load(&path).dns().as_deref(), Some("8.8.4.4"));
        assert_eq!(
            std::fs::read_to_string(&path)
                .unwrap()
                .matches("dns =")
                .count(),
            1,
        );
    }

    #[test]
    fn bool_recognizes_truthy_and_falsy_spellings() {
        for v in ["true", "TRUE", "yes", "1"] {
            let cfg = Config::parse(&format!("use_gh_auth = {v}\n"));
            assert!(cfg.use_gh_auth(), "spelling `{v}` should be true");
        }
        for v in ["false", "FALSE", "no", "0"] {
            let cfg = Config::parse(&format!("data = {v}\n"));
            assert!(!cfg.data(), "spelling `{v}` should be false");
        }
        // Garbage falls back to default.
        let cfg = Config::parse("use_gh_auth = maybe\n");
        assert!(!cfg.use_gh_auth());
    }
}
