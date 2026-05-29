//! Embedded multi-call alias metadata.
//!
//! Catalog packages can ship a multi-call binary that responds to several
//! invocation names (xz → xzcat/unxz/lzma/...). The list of extra names
//! travels baked into the binary itself as a string-mágica block bracketed
//! by non-printable sentinels — the same parser works on ELF/PE/Mach-O
//! without per-format readers, and shipping the data alongside the bytes
//! keeps the "single artifact" promise honest.
//!
//! Format on disk:
//! ```text
//!   <MARKER_BEGIN>\nKEY=VALUE\n[KEY=VALUE\n...]<MARKER_END>\n
//! ```
//!
//! The 0xff-0xff sentinel sequences are invalid UTF-8, so accidental hits
//! in compiled code or embedded text data are essentially impossible. We
//! still treat *multiple* BEGIN matches as fatal — a binary that bundles
//! another binary (e.g. git embedding dash) could otherwise smuggle a
//! second alias set past the first.

use std::collections::HashSet;
use std::fs;
use std::io::{self, Read};
use std::path::Path;

/// Chunk size for the streaming binary scan. 64 KB is one filesystem read
/// on most systems and dwarfs the marker length, so the per-iteration
/// overhead from the boundary-overlap copy is negligible.
const SCAN_CHUNK: usize = 64 * 1024;

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

pub const MARKER_BEGIN: &[u8] = b"\xff\xffUNPIN_META_v1_7f3a4e\xff\xff";
pub const MARKER_END: &[u8] = b"\xff\xffUNPIN_META_END_7f3a4e\xff\xff";

/// Hard caps so a malformed (or malicious) marker can't blow up memory or
/// flood `bin_dir/` with junk entries.
pub const MAX_PAYLOAD_BYTES: usize = 8 * 1024;
// Sized for busybox-class multicalls (~400 applets) with headroom.
// Payload size is the actual bound — at ~10 chars + comma per alias, 512
// names fit in well under MAX_PAYLOAD_BYTES (8 KB allows ~800).
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

#[derive(Clone, Debug, Default)]
pub struct Meta {
    pub aliases: Vec<String>,
}

/// Read `path` and look for an embedded UNPIN meta block.
/// `Ok(None)` = no marker; `Ok(Some(meta))` = parsed payload; `Err(e)` =
/// marker found but malformed (or duplicated). The malformed case is fatal
/// so we don't silently install a partial alias set.
///
/// The scan is **streaming with a sliding window** — peak memory is bounded
/// to ~64 KB regardless of binary size, so a 50 MB ffmpeg costs the same
/// resident memory as a 100 KB tool. We pay the I/O of reading until we
/// find the END marker (or to EOF when there's no marker, or to EOF in
/// phase 3 when verifying no second BEGIN exists), but we never hold the
/// whole file in RAM.
pub fn read_meta(path: &Path) -> Result<Option<Meta>, String> {
    let f = fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    stream_scan(io::BufReader::with_capacity(SCAN_CHUNK, f))
}

fn stream_scan<R: Read>(mut reader: R) -> Result<Option<Meta>, String> {
    let mut acc: Vec<u8> = Vec::with_capacity(SCAN_CHUNK + MARKER_BEGIN.len());

    // Phase 1: locate the first BEGIN marker. Compacts after each chunk so
    // memory stays bounded even for binaries where the marker lives deep
    // in .rodata (typically MBs into the file).
    let begin_pos = match find_in_chunks(&mut reader, &mut acc, MARKER_BEGIN, SCAN_CHUNK)? {
        Some(p) => p,
        None => return Ok(None),
    };
    acc.drain(..begin_pos + MARKER_BEGIN.len());

    // Phase 2: locate END marker; bytes between BEGIN and END are the
    // payload. This phase does NOT compact (the payload is the data we
    // want) — instead, a soft cap caps memory at MAX_PAYLOAD_BYTES + one
    // chunk, so a marker pair without a properly-bracketed END can't OOM.
    let end_pos = extend_until_found(
        &mut reader,
        &mut acc,
        MARKER_END,
        MAX_PAYLOAD_BYTES + MARKER_END.len(),
        SCAN_CHUNK,
    )?
    .ok_or_else(|| "UNPIN_META begin marker has no matching end marker".to_string())?;
    if end_pos > MAX_PAYLOAD_BYTES {
        return Err(format!(
            "UNPIN_META payload too large: {end_pos} bytes (max {MAX_PAYLOAD_BYTES})"
        ));
    }
    let payload = acc[..end_pos].to_vec();
    acc.drain(..end_pos + MARKER_END.len());

    // Phase 3: confirm no second BEGIN marker exists in the remainder.
    // Defense against a binary that bundles another binary which itself
    // carries a marker (e.g. git embedding dash). Compaction here keeps
    // memory bounded — we read to EOF but never hold more than ~CHUNK +
    // overlap bytes.
    if find_in_chunks(&mut reader, &mut acc, MARKER_BEGIN, SCAN_CHUNK)?.is_some() {
        return Err("found multiple UNPIN_META begin markers in binary — refusing to guess".into());
    }
    parse_payload(&payload).map(Some)
}

/// Stream `reader` in chunks, appending into `acc`, searching for `needle`.
/// Compacts `acc` between iterations down to `needle.len()-1` bytes (the
/// minimum needed to detect a needle straddling chunk boundaries). Returns
/// the offset within `acc` (post-compaction) of the match, or Ok(None) if
/// EOF arrives without a match.
fn find_in_chunks<R: Read>(
    reader: &mut R,
    acc: &mut Vec<u8>,
    needle: &[u8],
    chunk_size: usize,
) -> Result<Option<usize>, String> {
    // Pre-existing acc bytes (leftover from a previous phase) might already
    // contain the needle; check before any new I/O.
    if let Some(pos) = find_subsequence(acc, needle) {
        return Ok(Some(pos));
    }
    let overlap = needle.len().saturating_sub(1);
    let mut tmp = vec![0u8; chunk_size];
    loop {
        let n = reader.read(&mut tmp).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Ok(None);
        }
        let search_start = acc.len().saturating_sub(overlap);
        acc.extend_from_slice(&tmp[..n]);
        if let Some(rel) = find_subsequence(&acc[search_start..], needle) {
            return Ok(Some(search_start + rel));
        }
        // Compact: keep only the trailing `overlap` bytes for the next
        // iteration (they might be the start of the needle continuing
        // into the next chunk). Drops everything else from RAM.
        if acc.len() > overlap {
            acc.drain(..acc.len() - overlap);
        }
    }
}

/// Like `find_in_chunks` but does NOT compact — bytes are accumulated
/// because they're the payload we'll consume on a successful find. The
/// soft `cap` is a memory safety net: if the needle isn't found before
/// `acc.len()` exceeds `cap + chunk_size`, we error out rather than read
/// the entire file looking for an END that isn't there.
fn extend_until_found<R: Read>(
    reader: &mut R,
    acc: &mut Vec<u8>,
    needle: &[u8],
    cap: usize,
    chunk_size: usize,
) -> Result<Option<usize>, String> {
    if let Some(pos) = find_subsequence(acc, needle) {
        return Ok(Some(pos));
    }
    let overlap = needle.len().saturating_sub(1);
    let mut tmp = vec![0u8; chunk_size];
    loop {
        let n = reader.read(&mut tmp).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Ok(None);
        }
        let search_start = acc.len().saturating_sub(overlap);
        acc.extend_from_slice(&tmp[..n]);
        // Search FIRST so we exit cleanly even if this chunk overshot the
        // cap by less than chunk_size (the search would still find the
        // needle within the budget).
        if let Some(rel) = find_subsequence(&acc[search_start..], needle) {
            return Ok(Some(search_start + rel));
        }
        if acc.len() > cap + chunk_size {
            return Err(format!(
                "UNPIN_META payload exceeded {cap}-byte budget without finding terminator"
            ));
        }
    }
}

fn parse_payload(payload: &[u8]) -> Result<Meta, String> {
    let text = std::str::from_utf8(payload)
        .map_err(|e| format!("UNPIN_META payload is not UTF-8: {e}"))?;
    let mut meta = Meta::default();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("UNPIN_META: malformed line {line:?} (expected KEY=VALUE)"))?;
        // `match` (not `if`) so adding more KEY arms in future schema
        // versions stays a one-line edit. Unknown keys silently ignored
        // for forward-compat — older unpin readers should still install
        // packages built against a future schema.
        #[allow(clippy::single_match)]
        match key.trim() {
            "ALIASES" => {
                // Dedup while preserving first-seen order. Duplicate names
                // would otherwise cause double link creation (second
                // overwrites first, harmless but wasteful) and a noisy
                // `aliases: foo foo bar` in the install summary. A HashSet of
                // borrowed slices does the membership check in O(1); `out`
                // keeps the order and owns only the names we actually keep.
                let mut seen: HashSet<&str> = HashSet::new();
                let mut out: Vec<String> = Vec::new();
                for s in value.split(',') {
                    let s = s.trim();
                    if s.is_empty() || !seen.insert(s) {
                        continue;
                    }
                    out.push(s.to_string());
                }
                meta.aliases = out;
            }
            _ => {}
        }
    }
    Ok(meta)
}

fn find_subsequence(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

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

    /// Test convenience: scan from an in-memory byte slice. Production
    /// `read_meta` opens a file and feeds a BufReader, but the streaming
    /// logic is identical so testing through Cursor exercises the same
    /// code path.
    fn parse_meta_from_bytes(bytes: &[u8]) -> Result<Option<Meta>, String> {
        stream_scan(io::Cursor::new(bytes))
    }

    fn build_marked(payload: &str) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"random binary preamble\x00\x01\x02");
        v.extend_from_slice(MARKER_BEGIN);
        v.push(b'\n');
        v.extend_from_slice(payload.as_bytes());
        v.extend_from_slice(MARKER_END);
        v.push(b'\n');
        v.extend_from_slice(b"random binary postamble\x03\x04");
        v
    }

    #[test]
    fn parse_no_marker_returns_none() {
        let bytes = b"plain binary content with no marker";
        assert!(parse_meta_from_bytes(bytes).unwrap().is_none());
    }

    #[test]
    fn parse_single_marker_extracts_aliases() {
        let bytes = build_marked("ALIASES=xzcat,unxz,lzma\n");
        let meta = parse_meta_from_bytes(&bytes).unwrap().unwrap();
        assert_eq!(meta.aliases, vec!["xzcat", "unxz", "lzma"]);
    }

    #[test]
    fn parse_skips_blank_and_unknown_keys() {
        let bytes = build_marked("\nUNKNOWN=garbage\nALIASES=foo,bar\n");
        let meta = parse_meta_from_bytes(&bytes).unwrap().unwrap();
        assert_eq!(meta.aliases, vec!["foo", "bar"]);
    }

    #[test]
    fn parse_trims_alias_whitespace_and_skips_empty() {
        let bytes = build_marked("ALIASES= foo , , bar ,baz\n");
        let meta = parse_meta_from_bytes(&bytes).unwrap().unwrap();
        assert_eq!(meta.aliases, vec!["foo", "bar", "baz"]);
    }

    #[test]
    fn parse_dedups_alias_names_preserving_order() {
        // Duplicates in the marker (build bug or hand-edited binary) must
        // not produce duplicate links or noisy summary output.
        let bytes = build_marked("ALIASES=foo,bar,foo,baz,bar\n");
        let meta = parse_meta_from_bytes(&bytes).unwrap().unwrap();
        assert_eq!(meta.aliases, vec!["foo", "bar", "baz"]);
    }

    #[test]
    fn parse_multiple_markers_is_fatal() {
        let mut bytes = build_marked("ALIASES=a\n");
        bytes.extend_from_slice(&build_marked("ALIASES=b\n"));
        let err = parse_meta_from_bytes(&bytes).unwrap_err();
        assert!(err.contains("multiple"), "got: {err}");
    }

    #[test]
    fn parse_unterminated_marker_is_fatal() {
        let mut bytes = b"prefix".to_vec();
        bytes.extend_from_slice(MARKER_BEGIN);
        bytes.extend_from_slice(b"\nALIASES=foo\n");
        let err = parse_meta_from_bytes(&bytes).unwrap_err();
        assert!(err.contains("no matching end marker"), "got: {err}");
    }

    #[test]
    fn parse_oversized_payload_is_fatal() {
        let big = "x".repeat(MAX_PAYLOAD_BYTES + 1);
        let bytes = build_marked(&format!("ALIASES={big}\n"));
        let err = parse_meta_from_bytes(&bytes).unwrap_err();
        assert!(
            err.contains("too large") || err.contains("budget"),
            "got: {err}"
        );
    }

    #[test]
    fn parse_malformed_line_is_fatal() {
        let bytes = build_marked("just-a-bare-line\n");
        let err = parse_meta_from_bytes(&bytes).unwrap_err();
        assert!(err.contains("malformed line"), "got: {err}");
    }

    #[test]
    fn streaming_finds_marker_straddling_chunk_boundary() {
        // Force a small chunk so the marker straddles the boundary, then
        // confirm the overlap retention catches it. Without overlap the
        // scan would miss the marker entirely — this test would fail.
        let needle = MARKER_BEGIN;
        // Filler sized so the marker starts inside chunk 1 and finishes in chunk 2.
        let chunk = 64usize;
        let filler_len = chunk - needle.len() / 2;
        let mut bytes = vec![b'.'; filler_len];
        bytes.extend_from_slice(needle);
        bytes.push(b'\n');
        bytes.extend_from_slice(b"ALIASES=foo\n");
        bytes.extend_from_slice(MARKER_END);
        let meta = stream_scan_with_chunk(&bytes, chunk).unwrap().unwrap();
        assert_eq!(meta.aliases, vec!["foo"]);
    }

    #[test]
    fn streaming_handles_marker_at_arbitrary_offset() {
        // Marker at ~1 MB into the file — same code path exercises the
        // compaction loop many times, with bounded peak memory.
        let mut bytes = vec![b'.'; 1_000_000];
        bytes.extend_from_slice(MARKER_BEGIN);
        bytes.extend_from_slice(b"\nALIASES=lz4cat,unlz4\n");
        bytes.extend_from_slice(MARKER_END);
        let meta = parse_meta_from_bytes(&bytes).unwrap().unwrap();
        assert_eq!(meta.aliases, vec!["lz4cat", "unlz4"]);
    }

    /// Variant of `stream_scan` that lets the test pick the chunk size, so
    /// boundary-straddling cases can be reproduced reliably with small input.
    fn stream_scan_with_chunk(bytes: &[u8], chunk_size: usize) -> Result<Option<Meta>, String> {
        let mut acc: Vec<u8> = Vec::new();
        let mut cursor = io::Cursor::new(bytes);
        let begin = match find_in_chunks(&mut cursor, &mut acc, MARKER_BEGIN, chunk_size)? {
            Some(p) => p,
            None => return Ok(None),
        };
        acc.drain(..begin + MARKER_BEGIN.len());
        let end = extend_until_found(
            &mut cursor,
            &mut acc,
            MARKER_END,
            MAX_PAYLOAD_BYTES + MARKER_END.len(),
            chunk_size,
        )?
        .ok_or_else(|| "no end".to_string())?;
        let payload = acc[..end].to_vec();
        parse_payload(&payload).map(Some)
    }

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
