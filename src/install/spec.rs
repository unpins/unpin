//! Parsing and validation of `<owner>/<name>[@version]` package specs.
//!
//! `parse_spec` is the single entry point. Owner/name/version each route
//! through `validate_path_component` before they're allowed to flow into a
//! filesystem path or URL — the same validator runs on `tag_name` returned
//! by the GitHub API in `fetch_release`.

/// Owner under which curated unpins-org packages live. Aliases declared by an
/// embedded UNPIN_META block are honored only when `spec.owner` matches this —
/// `<owner>/<repo>` installs from arbitrary publishers always skip aliases,
/// even with `--aliases` on the CLI. The catalog-only gate is the primary
/// defense against PATH-shadow attacks via a malicious release.
pub const CATALOG_OWNER: &str = "unpins";

#[derive(Clone, PartialEq, Eq)]
pub struct Spec {
    pub owner: String,
    pub name: String,
    pub version: Option<String>,
}

impl Spec {
    pub fn repo(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
}

pub fn parse_spec(input: &str) -> Result<Spec, String> {
    let (base, version) = match input.split_once('@') {
        Some((b, v)) => (b, Some(v.to_owned())),
        None => (input, None),
    };
    if let Some(ref v) = version {
        validate_path_component(v, "version")?;
    }
    if let Some((owner, name)) = base.split_once('/') {
        if owner.is_empty() || name.is_empty() || name.contains('/') {
            return Err(format!("invalid package spec: `{input}`"));
        }
        validate_path_component(owner, "owner")?;
        validate_path_component(name, "name")?;
        return Ok(Spec {
            owner: owner.to_owned(),
            name: name.to_owned(),
            version,
        });
    }
    if base.is_empty() {
        return Err("empty package name".into());
    }
    validate_path_component(base, "name")?;
    Ok(Spec {
        owner: CATALOG_OWNER.to_owned(),
        name: base.to_owned(),
        version,
    })
}

/// Reject strings that aren't safe to use as a single filesystem-path
/// component. Catches empty/dot/dotdot, leading `-` (option-flag confusion),
/// path separators, and control bytes. Applied to user-supplied owner/name/
/// version AND to `tag_name` returned by the GitHub API — a malicious release
/// could otherwise smuggle traversal into `version_dir(...)`.
pub fn validate_path_component(s: &str, what: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err(format!("empty {what}"));
    }
    if s == "." || s == ".." {
        return Err(format!("invalid {what}: `{s}`"));
    }
    if s.starts_with('-') {
        return Err(format!("invalid {what} (starts with `-`): `{s}`"));
    }
    for b in s.bytes() {
        if b < 0x20 || b == 0x7f || b == b'/' || b == b'\\' || b == b':' {
            return Err(format!("invalid {what} (forbidden byte): `{s}`"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_spec_owner_repo() {
        let s = parse_spec("BurntSushi/ripgrep").unwrap();
        assert_eq!(s.owner, "BurntSushi");
        assert_eq!(s.name, "ripgrep");
        assert_eq!(s.version, None);
    }

    #[test]
    fn parse_spec_with_version() {
        let s = parse_spec("BurntSushi/ripgrep@14.1.0").unwrap();
        assert_eq!(s.owner, "BurntSushi");
        assert_eq!(s.name, "ripgrep");
        assert_eq!(s.version.as_deref(), Some("14.1.0"));
    }

    #[test]
    fn parse_spec_bare_name_defaults_to_unpins_owner() {
        let s = parse_spec("sgleam").unwrap();
        assert_eq!(s.owner, "unpins");
        assert_eq!(s.name, "sgleam");
        assert_eq!(s.version, None);
    }

    #[test]
    fn parse_spec_bare_name_with_version() {
        let s = parse_spec("sgleam@v0.7.0").unwrap();
        assert_eq!(s.owner, "unpins");
        assert_eq!(s.name, "sgleam");
        assert_eq!(s.version.as_deref(), Some("v0.7.0"));
    }

    #[test]
    fn parse_spec_rejects_empty() {
        assert!(parse_spec("").is_err());
        assert!(parse_spec("@1.0").is_err());
    }

    #[test]
    fn parse_spec_rejects_empty_owner_or_repo() {
        assert!(parse_spec("/repo").is_err());
        assert!(parse_spec("owner/").is_err());
    }

    #[test]
    fn parse_spec_rejects_extra_slashes() {
        // split_once splits on the FIRST '/', so "a/b/c" leaves "b/c" as repo —
        // rejected because repo contains '/'.
        assert!(parse_spec("a/b/c").is_err());
    }

    #[test]
    fn parse_spec_rejects_path_traversal_in_owner_or_name() {
        // The downstream `version_dir(owner, name, tag)` joins these into a
        // filesystem path. Refuse `.`/`..`/leading-dash/control bytes so user
        // typos or sloppy scripts don't accidentally escape `data_dir`.
        for input in [
            "../foo",
            "foo/..",
            "./foo",
            "foo/.",
            "-bad/repo",
            "owner/-bad",
            "foo\\bar/x",
            "owner/foo:bar",
        ] {
            assert!(parse_spec(input).is_err(), "{input} should fail");
        }
    }

    #[test]
    fn parse_spec_rejects_bad_version() {
        // `@version` is forwarded to a URL path component and (when the API
        // echoes it back as tag_name) to a filesystem path.
        assert!(parse_spec("foo/bar@..").is_err());
        assert!(parse_spec("foo/bar@-v1").is_err());
        assert!(parse_spec("foo/bar@v1/2").is_err());
    }

    #[test]
    fn validate_path_component_accepts_typical_names() {
        for s in ["foo", "BurntSushi", "ripgrep", "v1.2.3", "release_v1"] {
            assert!(validate_path_component(s, "x").is_ok(), "{s}");
        }
    }

    #[test]
    fn validate_path_component_rejects_traversal_and_control() {
        for s in [
            "", ".", "..", "-leading", "foo/bar", "foo\\bar", "foo:bar", "foo\0bar", "foo\nbar",
        ] {
            assert!(validate_path_component(s, "x").is_err(), "{s:?}");
        }
    }
}
