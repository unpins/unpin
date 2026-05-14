//! Flat `key = value` config with `#` comments. Loaded from
//! [`platform::config_path`]; a missing file is treated as empty so defaults
//! apply.
//!
//! Grammar (per line):
//!   `# ...`                  → comment, skipped
//!   blank                    → skipped
//!   `<key> = <value>`        → key/value pair; both sides trimmed
//!   anything after a `#`     → stripped as inline comment (values are scalars
//!                              like ints/bools, so `#` never appears inside)
//!
//! No sections, no quoting, no escapes — intentionally smaller than INI.
//! Unknown keys are kept in the map and silently ignored; bad values fall back
//! to the key's default (so a typo in `http_timeout` doesn't crash unpin).

use std::collections::HashMap;

use crate::platform;

#[derive(Debug, Default)]
pub struct Config {
    map: HashMap<String, String>,
}

impl Config {
    /// Read and parse the user's config file. Missing file → empty `Config`.
    pub fn load() -> Self {
        let text = std::fs::read_to_string(platform::config_path()).unwrap_or_default();
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
    }

    #[test]
    fn http_timeout_falls_back_on_garbage_value() {
        let cfg = Config::parse("http_timeout = not_a_number\n");
        assert_eq!(cfg.http_timeout(), 30);
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
