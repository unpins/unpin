//! Multi-call alias policy.
//!
//! Catalog packages can ship a multi-call binary that responds to several
//! invocation names (xz → xzcat/unxz/lzma/...). The list of extra names travels
//! baked into the binary as a `unpin/aliases` entry of the embedded-metadata ZIP
//! — reading it is `meta.rs`'s job (see `docs/embedded-metadata.md`). This
//! module owns the *policy*: the alias execution mode and the validation that
//! decides which declared names are safe to link.
//!
//! Security boundary: aliases create `PATH` links, so a malicious name could
//! shadow `sudo`/`ssh`/`git`. Two layers guard this, both upstream of the ZIP
//! reader — the catalog-owner gate in `install/linker.rs` (aliases honored only
//! for `unpins/<repo>`), and the blocklist + `validate_alias` here.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AliasMode {
    Yes,
    No,
    Ask,
}

impl AliasMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "yes" | "true" | "1" | "on" => Some(Self::Yes),
            "no" | "false" | "0" | "off" => Some(Self::No),
            "ask" | "prompt" => Some(Self::Ask),
            _ => None,
        }
    }
}

// Sized for busybox-class multicalls (~400 applets) with headroom.
pub const MAX_ALIASES: usize = 512;
pub const MAX_ALIAS_LEN: usize = 64;

/// Names we refuse to shadow even from a catalog package: shadowing `sudo`
/// or `ssh` would let a compromised release intercept credentials or
/// privilege escalation. The owner check (catalog-only) blocks this for
/// `<owner>/<repo>` installs entirely; the blocklist is the second layer
/// in case a curated package gets compromised in CI.
pub const BLOCKED_ALIAS_NAMES: &[&str] = &[
    // privilege escalation / remote shells
    "sudo",
    "su",
    "doas",
    "ssh",
    "scp",
    "sftp",
    "ssh-add",
    "ssh-agent",
    "ssh-keygen",
    // SCM / package upload
    "git",
    "gh",
    "hg",
    "svn",
    // crypto agents
    "gpg",
    "gpg2",
    "pinentry",
    "age",
    "rage",
    // language runtimes (shadowing them swaps the user's interpreter)
    "python",
    "python2",
    "python3",
    "node",
    "nodejs",
    "deno",
    "npm",
    "npx",
    "yarn",
    "pnpm",
    "cargo",
    "rustc",
    "rustup",
    "go",
    "java",
    "javac",
    "ruby",
    "gem",
    "bundle",
    "perl",
    "php",
    "lua",
    // shells (shadowing breaks login + scripts)
    "bash",
    "sh",
    "zsh",
    "fish",
    "ksh",
    "dash",
    "csh",
    "tcsh",
    "cmd",
    "powershell",
    "pwsh",
    // unpin itself
    "unpin",
];

/// Validate one declared alias name. Catches empty/overlong names, chars
/// outside `[a-z0-9._-]` (no path separators or whitespace), leading dot
/// or dash (POSIX hidden-file / option-flag confusion), Windows reserved
/// device names, and the credential/runtime blocklist.
pub fn validate_alias(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("empty alias name".into());
    }
    if name.len() > MAX_ALIAS_LEN {
        return Err(format!(
            "alias `{name}`: length {} exceeds limit {MAX_ALIAS_LEN}",
            name.len()
        ));
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if !matches!(first, 'a'..='z' | '0'..='9') {
        return Err(format!(
            "alias `{name}`: first char must be lowercase letter or digit"
        ));
    }
    for c in chars {
        if !matches!(c, 'a'..='z' | '0'..='9' | '.' | '_' | '-') {
            return Err(format!("alias `{name}`: char `{c}` not in [a-z0-9._-]"));
        }
    }
    if is_windows_reserved(name) {
        return Err(format!(
            "alias `{name}`: matches a Windows reserved device name"
        ));
    }
    if BLOCKED_ALIAS_NAMES
        .iter()
        .any(|b| b.eq_ignore_ascii_case(name))
    {
        return Err(format!(
            "alias `{name}`: blocked (would shadow a sensitive command)"
        ));
    }
    Ok(())
}

fn is_windows_reserved(name: &str) -> bool {
    let stem = name.split_once('.').map(|(s, _)| s).unwrap_or(name);
    let upper = stem.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_accepts_typical_unix_names() {
        for n in [
            "xzcat",
            "unxz",
            "lzma",
            "git-lfs",
            "py.test",
            "cmake_build",
            "x",
        ] {
            assert!(validate_alias(n).is_ok(), "{n} should be valid");
        }
    }

    #[test]
    fn validate_rejects_uppercase_and_path_chars() {
        for n in [
            "XZcat",
            "../etc/passwd",
            "foo/bar",
            "foo\\bar",
            "foo bar",
            "foo\tbar",
        ] {
            assert!(validate_alias(n).is_err(), "{n} should be invalid");
        }
    }

    #[test]
    fn validate_rejects_leading_dot_or_dash_or_underscore() {
        for n in [".hidden", "-flag", "_under"] {
            assert!(validate_alias(n).is_err(), "{n} should be rejected");
        }
    }

    #[test]
    fn validate_rejects_blocklist() {
        for n in [
            "sudo", "git", "ssh", "python", "cargo", "bash", "unpin", "SSH",
        ] {
            assert!(validate_alias(n).is_err(), "{n} should be blocked");
        }
    }

    #[test]
    fn validate_rejects_windows_reserved() {
        for n in ["con", "nul", "com1", "lpt1", "lpt9", "aux", "prn"] {
            assert!(validate_alias(n).is_err(), "{n} should be blocked");
        }
        // Reserved-name detection looks at the stem before the dot, so
        // `nul.exe` and `lpt1.txt` are both rejected — Windows treats them
        // as the device too.
        assert!(validate_alias("nul.exe").is_err());
        assert!(validate_alias("lpt1.txt").is_err());
    }

    #[test]
    fn validate_rejects_empty_and_overlong() {
        assert!(validate_alias("").is_err());
        let too_long = "a".repeat(MAX_ALIAS_LEN + 1);
        assert!(validate_alias(&too_long).is_err());
    }

    #[test]
    fn alias_mode_parses_yes_no_ask() {
        assert_eq!(AliasMode::parse("yes"), Some(AliasMode::Yes));
        assert_eq!(AliasMode::parse("YES"), Some(AliasMode::Yes));
        assert_eq!(AliasMode::parse("true"), Some(AliasMode::Yes));
        assert_eq!(AliasMode::parse("1"), Some(AliasMode::Yes));
        assert_eq!(AliasMode::parse("no"), Some(AliasMode::No));
        assert_eq!(AliasMode::parse("false"), Some(AliasMode::No));
        assert_eq!(AliasMode::parse("ask"), Some(AliasMode::Ask));
        assert_eq!(AliasMode::parse("prompt"), Some(AliasMode::Ask));
        assert_eq!(AliasMode::parse("garbage"), None);
        assert_eq!(AliasMode::parse(""), None);
    }
}
