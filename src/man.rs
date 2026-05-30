//! Embedded man pages (`.unpin_man`) — reader + `unpin man` subcommand.
//!
//! Every unpins binary can carry its own man pages baked into a `.unpin_man`
//! container (built by nix-lib `withMan` for catalog packages, and by this
//! crate's `build.rs` for unpin itself). The on-disk format is frozen in
//! `docs/embedded-man.md`: a 0xff-bracketed BEGIN sentinel followed by a
//! length-prefixed, optionally zstd-compressed inner archive (`UPMAN`) of N
//! roff pages plus an index. Because the blob is located by a byte-scan for
//! the sentinel — not by parsing ELF/PE/Mach-O sections — one reader works on
//! every platform, exactly like the `UNPIN_META` alias block in `aliases.rs`.
//!
//! This module implements the **reading** half (container + inner archive +
//! page lookup + `.so` resolution). Terminal **rendering** of the roff is not
//! implemented yet; it will arrive via the pandoc port (Readers::Man +
//! Writers::ANSI). Until then `unpin man` reports the page it found and offers
//! `--raw` to dump the roff source.

use std::fs;
use std::io::{self, Read};
use std::path::Path;

use crate::aliases;

/// Plant unpin's own man container in the binary so the byte-scan below finds
/// it in our own file, the same way it would in any other unpins binary.
/// `#[used]` keeps the bytes through dead-code elimination even though no code
/// references them — `unpin man` reads them back off disk via `current_exe()`.
#[used]
static UNPIN_MAN_BLOB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/unpin_man.blob"));

// Sentinels — exact bytes from docs/embedded-man.md §1.3 (and build.rs).
const MARKER_BEGIN: &[u8] = b"\xff\xffUNPIN_MAN_v1_b2c9d1\xff\xff";
const MARKER_END: &[u8] = b"\xff\xffUNPIN_MAN_ENDb2c9d1\xff\xff";

const SCAN_CHUNK: usize = 64 * 1024;
/// Caps so a corrupt/crafted length field can't drive an unbounded allocation.
/// util-linux (the worst real case, ~149 pages) is tens of KB; these are far
/// above any legitimate blob.
const MAX_PAYLOAD: usize = 16 * 1024 * 1024;
const MAX_INNER: usize = 64 * 1024 * 1024;
/// `.so` redirect chain depth limit (docs/embedded-man.md §3.3).
const MAX_SO_DEPTH: u32 = 4;

fn crc32(data: &[u8]) -> u32 {
    // IEEE poly 0xEDB88320 — matches build.rs / mkman.py / zlib.crc32.
    let mut table = [0u32; 256];
    for (n, slot) in table.iter_mut().enumerate() {
        let mut c = n as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
        }
        *slot = c;
    }
    let mut c = 0xffff_ffffu32;
    for &b in data {
        c = table[((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
    }
    c ^ 0xffff_ffff
}

// ---------------------------------------------------------------- container

#[derive(Debug)]
struct Container {
    comp: u8,
    payload: Vec<u8>,
}

fn read_container(path: &Path) -> Result<Option<Container>, String> {
    let f = fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    read_container_from(io::BufReader::with_capacity(SCAN_CHUNK, f))
}

enum Parsed {
    Container(Container),
    /// This sentinel was a chance hit (or a non-container marker), not a real
    /// container header — keep scanning for the next BEGIN.
    Skip,
}

/// Scan for the first BEGIN sentinel that introduces a parseable container.
///
/// A byte-scan for the sentinel can match bytes that aren't a real container:
/// most importantly, the reader's *own* `MARKER_BEGIN` constant lives in this
/// binary's `.rodata`, so when `unpin man` scans `unpin` itself it meets that
/// constant before the embedded blob. We therefore try each sentinel in turn
/// and skip the ones whose header doesn't commit to a container (version != 1).
///
/// This replaces the "a second BEGIN is fatal" rule that `aliases.rs` uses:
/// that guards a *security* boundary (aliases create PATH links), whereas a man
/// page is informational, and a self-scan legitimately meets multiple
/// sentinels. Once a header commits (`version == 1`), any further defect
/// (absurd length, END mismatch, CRC failure) is a corrupt container and is
/// reported rather than skipped.
fn read_container_from<R: Read>(mut reader: R) -> Result<Option<Container>, String> {
    let mut acc: Vec<u8> = Vec::with_capacity(SCAN_CHUNK + MARKER_BEGIN.len());
    loop {
        let begin = match aliases::find_in_chunks(&mut reader, &mut acc, MARKER_BEGIN, SCAN_CHUNK)? {
            Some(p) => p,
            None => return Ok(None),
        };
        acc.drain(..begin + MARKER_BEGIN.len());
        match parse_at(&mut reader, &mut acc)? {
            Parsed::Container(c) => return Ok(Some(c)),
            Parsed::Skip => continue,
        }
    }
}

/// Read the length-prefixed container at the current position (BEGIN already
/// drained from `acc`). The payload is binary, so we never scan for END — we
/// read exactly `payload_len` bytes and verify END sits at the computed offset
/// as a corruption tripwire (docs/embedded-man.md §1.2). On a `Skip` return,
/// `acc` still holds the post-BEGIN bytes so the caller's next scan continues
/// past this sentinel.
fn parse_at<R: Read>(reader: &mut R, acc: &mut Vec<u8>) -> Result<Parsed, String> {
    // Fixed header: container_version(1) + compression(1) + payload_len(4).
    fill_to(reader, acc, 6)?;
    if acc.len() < 6 {
        return Ok(Parsed::Skip); // sentinel near EOF with no header — chance hit
    }
    if acc[0] != 1 {
        return Ok(Parsed::Skip); // not a v1 container header — keep scanning
    }
    let comp = acc[1];
    let payload_len = u32::from_le_bytes([acc[2], acc[3], acc[4], acc[5]]) as usize;
    if payload_len > MAX_PAYLOAD {
        return Err(format!(
            "unpin_man: payload too large ({payload_len} bytes, max {MAX_PAYLOAD})"
        ));
    }

    // payload + crc32(4) + END sentinel.
    let need = 6 + payload_len + 4 + MARKER_END.len();
    fill_to(reader, acc, need)?;
    if acc.len() < need {
        return Err("unpin_man: truncated container payload".into());
    }
    let payload = acc[6..6 + payload_len].to_vec();
    let crc_at = 6 + payload_len;
    let crc_stored = u32::from_le_bytes([
        acc[crc_at],
        acc[crc_at + 1],
        acc[crc_at + 2],
        acc[crc_at + 3],
    ]);
    let end_at = crc_at + 4;
    if acc[end_at..end_at + MARKER_END.len()] != *MARKER_END {
        return Err("unpin_man: end sentinel mismatch (corrupt container)".into());
    }
    if crc32(&payload) != crc_stored {
        return Err("unpin_man: payload CRC mismatch (corrupt container)".into());
    }
    Ok(Parsed::Container(Container { comp, payload }))
}

/// Read until `acc` holds at least `n` bytes or the reader hits EOF. The
/// caller checks `acc.len()` to distinguish "filled" from "truncated".
fn fill_to<R: Read>(reader: &mut R, acc: &mut Vec<u8>, n: usize) -> Result<(), String> {
    let mut tmp = [0u8; SCAN_CHUNK];
    while acc.len() < n {
        let k = reader.read(&mut tmp).map_err(|e| format!("unpin_man read: {e}"))?;
        if k == 0 {
            break;
        }
        acc.extend_from_slice(&tmp[..k]);
    }
    Ok(())
}

fn decompress(c: &Container) -> Result<Vec<u8>, String> {
    match c.comp {
        0 => Ok(c.payload.clone()),
        1 => {
            let dec = ruzstd::StreamingDecoder::new(io::Cursor::new(&c.payload))
                .map_err(|e| format!("unpin_man: zstd init: {e}"))?;
            let mut out = Vec::new();
            // Bound the decompressed size: read one byte past the cap so an
            // over-large (or zip-bomb) archive trips the check instead of OOM.
            dec.take(MAX_INNER as u64 + 1)
                .read_to_end(&mut out)
                .map_err(|e| format!("unpin_man: zstd decode: {e}"))?;
            if out.len() > MAX_INNER {
                return Err(format!(
                    "unpin_man: decompressed archive too large (max {MAX_INNER})"
                ));
            }
            Ok(out)
        }
        n => Err(format!("unpin_man: unsupported compression {n} — upgrade unpin")),
    }
}

// ------------------------------------------------------------ inner archive

enum Body {
    Roff { off: u32, len: u32 },
    So { tgt_name: String, tgt_section: u8 },
}

struct Entry {
    name: String,
    section: u8,
    lang: String,
    body: Body,
}

struct Archive {
    entries: Vec<Entry>,
    blob: Vec<u8>,
}

/// Little-endian cursor over the index region with bounds-checked reads.
struct Cur<'a> {
    d: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn new(d: &'a [u8]) -> Self {
        Cur { d, p: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.p.checked_add(n).ok_or("unpin_man: index offset overflow")?;
        let s = self
            .d
            .get(self.p..end)
            .ok_or("unpin_man: truncated index record")?;
        self.p = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn lp_str(&mut self) -> Result<String, String> {
        let n = self.u16()? as usize;
        let b = self.take(n)?;
        String::from_utf8(b.to_vec()).map_err(|e| format!("unpin_man: non-UTF8 string: {e}"))
    }
}

fn parse_archive(data: &[u8]) -> Result<Archive, String> {
    if data.len() < 13 || &data[0..5] != b"UPMAN" {
        return Err("unpin_man: bad inner archive magic".into());
    }
    let ver = data[5];
    if ver != 1 {
        return Err(format!(
            "unpin_man: inner archive version {ver} unsupported — upgrade unpin"
        ));
    }
    // data[6] reserved.
    let entry_count = u16::from_le_bytes([data[7], data[8]]) as usize;
    let index_len = u32::from_le_bytes([data[9], data[10], data[11], data[12]]) as usize;
    let index_end = 13usize
        .checked_add(index_len)
        .ok_or("unpin_man: index_len overflow")?;
    let index = data
        .get(13..index_end)
        .ok_or("unpin_man: truncated index region")?;
    let blob = data
        .get(index_end..)
        .ok_or("unpin_man: truncated blob region")?
        .to_vec();

    let mut cur = Cur::new(index);
    let mut entries = Vec::with_capacity(entry_count.min(1024));
    for _ in 0..entry_count {
        let name = cur.lp_str()?;
        let section = cur.u8()?;
        let lang = cur.lp_str()?;
        let kind = cur.u8()?;
        let body = match kind {
            0 => Body::So {
                tgt_name: cur.lp_str()?,
                tgt_section: cur.u8()?,
            },
            1 => Body::Roff {
                off: cur.u32()?,
                len: cur.u32()?,
            },
            // Variable-length records mean we can't skip an unknown kind, so a
            // future kind makes the rest of the index unparseable. Error clearly.
            k => return Err(format!("unpin_man: unknown entry kind {k} — upgrade unpin")),
        };
        entries.push(Entry {
            name,
            section,
            lang,
            body,
        });
    }
    Ok(Archive { entries, blob })
}

impl Archive {
    /// Pick the best entry for `(name, section, lang)`: prefer the requested
    /// language, fall back to `en`; with no section, take the lowest-numbered
    /// one present (docs/embedded-man.md §3.2).
    fn pick(&self, name: &str, section: Option<u8>, lang: &str) -> Option<&Entry> {
        for want_lang in [lang, "en"] {
            let mut best: Option<&Entry> = None;
            for e in &self.entries {
                if e.name == name
                    && e.lang == want_lang
                    && section.is_none_or(|s| e.section == s)
                {
                    best = match best {
                        Some(b) if b.section <= e.section => Some(b),
                        _ => Some(e),
                    };
                }
            }
            if best.is_some() {
                return best;
            }
        }
        None
    }

    /// Resolve `(name, section, lang)` to roff bytes, following `.so` redirects
    /// up to `MAX_SO_DEPTH`. Returns the resolved section alongside the bytes.
    fn roff_for(
        &self,
        name: &str,
        section: Option<u8>,
        lang: &str,
    ) -> Result<(u8, Vec<u8>), String> {
        let mut cur_name = name.to_string();
        let mut cur_section = section;
        for _ in 0..MAX_SO_DEPTH {
            let e = self.pick(&cur_name, cur_section, lang).ok_or_else(|| {
                let sec = cur_section.map_or_else(|| "?".to_string(), |s| s.to_string());
                format!("unpin man: no page for {cur_name}({sec}) — try `unpin man --list`")
            })?;
            match &e.body {
                Body::Roff { off, len } => {
                    let off = *off as usize;
                    let end = off
                        .checked_add(*len as usize)
                        .ok_or("unpin_man: blob offset overflow")?;
                    let bytes = self
                        .blob
                        .get(off..end)
                        .ok_or("unpin_man: blob slice out of range")?;
                    return Ok((e.section, bytes.to_vec()));
                }
                Body::So {
                    tgt_name,
                    tgt_section,
                } => {
                    cur_name = tgt_name.clone();
                    cur_section = Some(*tgt_section);
                }
            }
        }
        Err(format!("unpin man: .so redirect chain too deep for {name}"))
    }
}

// ----------------------------------------------------------------- command

/// `unpin man [PKG] [PAGE]` — read and report a binary's embedded manual.
pub fn run(list: bool, raw: bool, pkg: Option<String>, page: Option<String>) -> Result<(), String> {
    let target = pkg.as_deref().unwrap_or("unpin");
    if target != "unpin" {
        return Err(format!(
            "unpin man: only unpin's own manual is supported for now (got `{target}`); \
             reading other packages' embedded man lands with the renderer"
        ));
    }

    let exe =
        std::env::current_exe().map_err(|e| format!("unpin man: cannot locate own binary: {e}"))?;
    let container = read_container(&exe)?
        .ok_or_else(|| format!("unpin man: no embedded manual found in {}", exe.display()))?;
    let inner = decompress(&container)?;
    let archive = parse_archive(&inner)?;

    if list {
        if archive.entries.is_empty() {
            println!("(no embedded manual pages)");
        }
        for e in &archive.entries {
            let what = match &e.body {
                Body::Roff { len, .. } => format!("roff, {len} bytes"),
                Body::So {
                    tgt_name,
                    tgt_section,
                } => format!("-> {tgt_name}({tgt_section})"),
            };
            println!("{}({}) [{}]  {what}", e.name, e.section, e.lang);
        }
        return Ok(());
    }

    let want = page.as_deref().unwrap_or(target);
    let lang = "en";
    let (section, roff) = archive.roff_for(want, None, lang)?;

    if raw {
        use std::io::Write;
        return std::io::stdout()
            .write_all(&roff)
            .map_err(|e| format!("unpin man: write: {e}"));
    }

    // No renderer yet — confirm the read worked end-to-end and point at the
    // deferred work (the pandoc port).
    println!(
        "Found embedded manual: {want}({section}) [{lang}] — {} bytes of roff source.\n\n\
         Terminal rendering is not implemented yet — it will arrive via the pandoc\n\
         port (Readers::Man + Writers::ANSI). For now:\n  \
         unpin man --raw     dump the raw roff source\n  \
         unpin man --list    list the embedded manual pages",
        roff.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_str(out: &mut Vec<u8>, s: &str) {
        out.extend_from_slice(&(s.len() as u16).to_le_bytes());
        out.extend_from_slice(s.as_bytes());
    }

    /// Build an inner UPMAN archive from (name, section, lang, body) entries.
    /// `body` is `Ok(roff)` for a roff page or `Err((tgt, sec))` for a `.so`.
    fn mk_inner(entries: &[(&str, u8, &str, Result<&[u8], (&str, u8)>)]) -> Vec<u8> {
        let mut blob = Vec::new();
        let mut index = Vec::new();
        for (name, section, lang, body) in entries {
            push_str(&mut index, name);
            index.push(*section);
            push_str(&mut index, lang);
            match body {
                Ok(roff) => {
                    index.push(1u8);
                    let off = blob.len() as u32;
                    index.extend_from_slice(&off.to_le_bytes());
                    index.extend_from_slice(&(roff.len() as u32).to_le_bytes());
                    blob.extend_from_slice(roff);
                }
                Err((tgt, sec)) => {
                    index.push(0u8);
                    push_str(&mut index, tgt);
                    index.push(*sec);
                }
            }
        }
        let mut inner = Vec::new();
        inner.extend_from_slice(b"UPMAN");
        inner.push(1u8);
        inner.push(0u8);
        inner.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        inner.extend_from_slice(&(index.len() as u32).to_le_bytes());
        inner.extend_from_slice(&index);
        inner.extend_from_slice(&blob);
        inner
    }

    fn mk_container(inner: &[u8]) -> Vec<u8> {
        let mut blob = Vec::new();
        blob.extend_from_slice(b"some binary preamble\x00\x01");
        blob.extend_from_slice(MARKER_BEGIN);
        blob.push(1u8); // version
        blob.push(0u8); // compression none
        blob.extend_from_slice(&(inner.len() as u32).to_le_bytes());
        blob.extend_from_slice(inner);
        blob.extend_from_slice(&crc32(inner).to_le_bytes());
        blob.extend_from_slice(MARKER_END);
        blob.extend_from_slice(b"trailing\x02\x03");
        blob
    }

    fn read_inner(bytes: &[u8]) -> Result<Vec<u8>, String> {
        let c = read_container_from(io::Cursor::new(bytes))?.ok_or("no container")?;
        decompress(&c)
    }

    #[test]
    fn roundtrip_roff_lookup() {
        let inner = mk_inner(&[("unpin", 1, "en", Ok(b".TH UNPIN 1\nhello"))]);
        let bytes = mk_container(&inner);
        let arch = parse_archive(&read_inner(&bytes).unwrap()).unwrap();
        let (sec, roff) = arch.roff_for("unpin", None, "en").unwrap();
        assert_eq!(sec, 1);
        assert_eq!(roff, b".TH UNPIN 1\nhello");
    }

    #[test]
    fn no_marker_returns_none() {
        let bytes = b"a plain binary with no man sentinel at all";
        assert!(read_container_from(io::Cursor::new(bytes)).unwrap().is_none());
    }

    #[test]
    fn so_redirect_resolves() {
        let inner = mk_inner(&[
            ("vigr", 8, "en", Err(("vipw", 8))),
            ("vipw", 8, "en", Ok(b"vipw body")),
        ]);
        let arch = parse_archive(&read_inner(&mk_container(&inner)).unwrap()).unwrap();
        let (sec, roff) = arch.roff_for("vigr", None, "en").unwrap();
        assert_eq!(sec, 8);
        assert_eq!(roff, b"vipw body");
    }

    #[test]
    fn lowest_section_preferred() {
        let inner = mk_inner(&[
            ("foo", 8, "en", Ok(b"section 8")),
            ("foo", 1, "en", Ok(b"section 1")),
        ]);
        let arch = parse_archive(&read_inner(&mk_container(&inner)).unwrap()).unwrap();
        let (sec, roff) = arch.roff_for("foo", None, "en").unwrap();
        assert_eq!(sec, 1);
        assert_eq!(roff, b"section 1");
    }

    #[test]
    fn crc_mismatch_is_fatal() {
        let inner = mk_inner(&[("unpin", 1, "en", Ok(b"body"))]);
        let mut bytes = mk_container(&inner);
        // Flip a payload byte (just past BEGIN+header) without touching the CRC.
        let begin = bytes
            .windows(MARKER_BEGIN.len())
            .position(|w| w == MARKER_BEGIN)
            .unwrap();
        bytes[begin + MARKER_BEGIN.len() + 6] ^= 0xff;
        let err = read_container_from(io::Cursor::new(&bytes)).unwrap_err();
        assert!(err.contains("CRC"), "got: {err}");
    }

    #[test]
    fn false_positive_sentinel_is_skipped() {
        // Models the self-scan: a BEGIN sentinel whose following byte is not a
        // v1 header (here 0xff, as the reader's own MARKER_BEGIN constant is
        // followed by in the real binary), then the genuine container. The
        // scan must skip the decoy and find the real blob.
        let inner = mk_inner(&[("unpin", 1, "en", Ok(b"real body"))]);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"preamble");
        bytes.extend_from_slice(MARKER_BEGIN);
        bytes.extend_from_slice(&[0xff, 0xff, 0xff]); // version 0xff -> skip
        bytes.extend_from_slice(&mk_container(&inner));
        let arch = parse_archive(&read_inner(&bytes).unwrap()).unwrap();
        let (_, roff) = arch.roff_for("unpin", None, "en").unwrap();
        assert_eq!(roff, b"real body");
    }

    #[test]
    fn first_valid_container_wins() {
        // Two genuine containers: take the first (no "fatal" rule for man).
        let a = mk_inner(&[("unpin", 1, "en", Ok(b"first"))]);
        let b = mk_inner(&[("unpin", 1, "en", Ok(b"second"))]);
        let mut bytes = mk_container(&a);
        bytes.extend_from_slice(&mk_container(&b));
        let arch = parse_archive(&read_inner(&bytes).unwrap()).unwrap();
        let (_, roff) = arch.roff_for("unpin", None, "en").unwrap();
        assert_eq!(roff, b"first");
    }

    #[test]
    fn so_chain_too_deep_errors() {
        // a -> b -> c -> d -> e, exceeding MAX_SO_DEPTH (4 hops).
        let inner = mk_inner(&[
            ("a", 1, "en", Err(("b", 1))),
            ("b", 1, "en", Err(("c", 1))),
            ("c", 1, "en", Err(("d", 1))),
            ("d", 1, "en", Err(("e", 1))),
            ("e", 1, "en", Ok(b"end")),
        ]);
        let arch = parse_archive(&read_inner(&mk_container(&inner)).unwrap()).unwrap();
        assert!(arch.roff_for("a", None, "en").is_err());
    }
}
