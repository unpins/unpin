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
//! for `unpins/<repo>`), and, here, the structural `validate_alias` plus a
//! per-name confirmation (`alias_needs_confirmation`) for the small set of
//! credential/privilege-escalation names where silent shadowing is acutely
//! dangerous.

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

/// Names that, when shadowed, hand a hostile binary the user's secrets or a
/// root prompt: `sudo`/`su`/`doas` capture the login/sudo password, `ssh`
/// captures remote credentials, `gpg`/`gpg2` capture signing/encryption
/// passphrases. We don't *refuse* these — a legitimate catalog package may
/// genuinely own such a name — but linking an alias for one is gated behind an
/// explicit per-name confirmation (see [`alias_needs_confirmation`] and its use
/// in `install/linker.rs`).
///
/// The list is deliberately tiny: it covers only silent secret/credential theft
/// and privilege escalation. It intentionally does *not* list footguns like
/// `git`, `cargo`, `node`, or the shells — mis-shadowing those breaks things but
/// doesn't harvest credentials, and the catalog-owner gate (aliases honored only
/// for `unpins/<repo>`) is the real boundary. This confirmation is the second
/// layer for the handful of names where silent shadowing is acutely dangerous.
pub const CONFIRM_ALIAS_NAMES: &[&str] = &[
    // privilege escalation — capture the password
    "sudo", "su", "doas", //
    // remote shell / credentials
    "ssh", //
    // signing / encryption passphrases
    "gpg", "gpg2",
];

/// True when `name` would shadow a credential-bearing or privilege-escalation
/// command and so warrants explicit confirmation before its alias is linked.
/// Case-insensitive — on a case-insensitive filesystem `SUDO` would still
/// shadow `sudo`. See [`CONFIRM_ALIAS_NAMES`].
pub fn alias_needs_confirmation(name: &str) -> bool {
    CONFIRM_ALIAS_NAMES
        .iter()
        .any(|n| n.eq_ignore_ascii_case(name))
}

/// Chars we refuse anywhere in an alias name: path separators and the
/// Windows-invalid filename set. A name carrying any of these is not a single
/// PATH-entry filename — `/`/`\` would address another directory, the rest
/// (`: * ? " < > |`) are rejected by NTFS and double as shell glob/redirect
/// metacharacters. Rejecting them cross-platform keeps a binary's baked-in
/// alias list installable identically everywhere.
const FORBIDDEN_ALIAS_CHARS: &[char] = &['/', '\\', ':', '*', '?', '"', '<', '>', '|'];

/// Validate one declared alias name. We accept any printable-ASCII name so
/// multi-call applets with punctuation names link cleanly — coreutils ships
/// `[` (the `test` applet), and busybox-class binaries have similar oddities.
/// What we still hard-reject is the bytes that make a name *unsafe* as a PATH
/// entry rather than merely unusual:
///   - path separators / Windows-invalid chars ([`FORBIDDEN_ALIAS_CHARS`]) —
///     traversal and cross-directory writes;
///   - anything outside printable ASCII (control, whitespace, non-ASCII) —
///     terminal/PATH confusion and unicode-homoglyph shadowing of real commands;
///   - a leading `-` (option-flag confusion) or `.` (hidden file, and the
///     `.`/`..` traversal names);
///   - Windows reserved device names.
///
/// What this does *not* do is reject credential/privilege names like `sudo` or
/// `ssh` — those are structurally valid and a catalog package may own them;
/// they're instead gated by [`alias_needs_confirmation`] at link time.
///
/// Traversal is additionally refused at the syscall layer when the link is
/// created (`platform::create_alias_link` routes Unix symlinks through cap-std
/// `RESOLVE_BENEATH`), so the separator rule here is the first of two layers,
/// not the only one.
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
    let first = name.chars().next().unwrap();
    if first == '-' || first == '.' {
        return Err(format!("alias `{name}`: first char must not be `-` or `.`"));
    }
    for c in name.chars() {
        if !c.is_ascii_graphic() {
            return Err(format!(
                "alias `{name}`: char must be printable ASCII (no whitespace, control, or non-ASCII)"
            ));
        }
        if FORBIDDEN_ALIAS_CHARS.contains(&c) {
            return Err(format!("alias `{name}`: char `{c}` not allowed"));
        }
    }
    if is_windows_reserved(name) {
        return Err(format!(
            "alias `{name}`: matches a Windows reserved device name"
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
            // Removed from the blocklist so the catalog `python` package can
            // claim its interpreter names.
            "python",
            "python3",
        ] {
            assert!(validate_alias(n).is_ok(), "{n} should be valid");
        }
    }

    #[test]
    fn validate_accepts_punctuation_applet_names() {
        // The whole point of the relaxed charset: real multi-call binaries ship
        // applets whose names aren't `[a-z0-9._-]`. coreutils' `[` is the
        // canonical case; uppercase and a leading underscore are now fine too.
        for n in ["[", "]", "@reboot", "v2.0+git", "FOO", "_internal", "g++"] {
            assert!(validate_alias(n).is_ok(), "{n} should be valid");
        }
    }

    #[test]
    fn validate_rejects_separators_and_windows_invalid_chars() {
        // Path separators (traversal) plus the NTFS-invalid set, which also
        // covers shell glob/redirect metacharacters.
        for n in [
            "../etc/passwd",
            "foo/bar",
            "foo\\bar",
            "a:b",
            "a*b",
            "a?b",
            "a\"b",
            "a<b",
            "a>b",
            "a|b",
        ] {
            assert!(validate_alias(n).is_err(), "{n} should be invalid");
        }
    }

    #[test]
    fn validate_rejects_non_printable_and_non_ascii() {
        for n in [
            "foo bar",
            "foo\tbar",
            "foo\nbar",
            "café",
            "naïve",
            "emoji😀",
        ] {
            assert!(validate_alias(n).is_err(), "{n} should be invalid");
        }
    }

    #[test]
    fn validate_rejects_leading_dot_or_dash() {
        // Leading `-` (option-flag confusion) and `.` (hidden file / the
        // `.`/`..` traversal names) stay rejected; a leading `_` does not.
        for n in [".hidden", "-flag", ".", ".."] {
            assert!(validate_alias(n).is_err(), "{n} should be rejected");
        }
        assert!(validate_alias("_under").is_ok(), "_under should be valid");
    }

    #[test]
    fn validate_no_longer_rejects_sensitive_or_footgun_names() {
        // These are structurally fine now — the credential/privilege ones are
        // gated by `alias_needs_confirmation` at link time, not refused here,
        // and the footgun names (git/cargo/node/bash) carry no special gate.
        for n in [
            "sudo", "ssh", "gpg", "git", "node", "cargo", "bash", "unpin", "SSH",
        ] {
            assert!(validate_alias(n).is_ok(), "{n} should pass validation");
        }
    }

    #[test]
    fn confirmation_flags_only_credential_and_privesc_names() {
        // Gated (credential theft / privilege escalation), case-insensitive.
        for n in ["sudo", "su", "doas", "ssh", "gpg", "gpg2", "SUDO", "Gpg"] {
            assert!(alias_needs_confirmation(n), "{n} should need confirmation");
        }
        // Footguns and ordinary applets are NOT gated — the owner gate covers them.
        for n in [
            "git", "cargo", "node", "bash", "sh", "scp", "ssh-add", "xzcat", "[",
        ] {
            assert!(
                !alias_needs_confirmation(n),
                "{n} should not need confirmation"
            );
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
