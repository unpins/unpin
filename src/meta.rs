//! Embedded metadata container — reader.
//!
//! Every unpins binary can carry a plain **ZIP** somewhere in its bytes holding
//! entries under a reserved `unpin/` namespace (`unpin/aliases`, `unpin/man/...`,
//! future kinds). This module finds that ZIP and materializes its `unpin/*`
//! entries. The on-disk format is specified in `docs/embedded-metadata.md`.
//!
//! Locating uses the ZIP's own structure — a byte-scan for the End Of Central
//! Directory record (`PK\x05\x06`), validated against the central directory —
//! so one reader works on ELF/PE/Mach-O/cosmo-APE and survives `strip`. There
//! is **no** sentinel or marker: the `unpin/` entry namespace is what identifies
//! data as ours, and a binary's other ZIPs (a cosmo runtime ZIP, a VFS runtime
//! ZIP) simply carry no `unpin/` entries.
//!
//! Security for aliases lives upstream (catalog-owner gate + blocklist in
//! `aliases.rs` / `install/linker.rs`), not here — see the doc §4. The one guard
//! kept: two distinct ZIPs both carrying `unpin/aliases` is a fatal ambiguity.

use std::fs;
use std::io::Read;
use std::path::Path;

/// Plant unpin's own metadata ZIP (its `unpin.1`, built by `build.rs`) in the
/// binary so the byte-scan below finds it in our own file, exactly as it would
/// in any other unpins binary. `#[used]` keeps the bytes through dead-code
/// elimination — `unpin bundle` reads them back off disk via `current_exe()`,
/// which is how the `man` package fetches unpin's own manual (`unpin man unpin`).
#[used]
static UNPIN_META_ZIP: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/unpin_meta.zip"));

/// Don't even try to scan an absurdly large file into memory.
const MAX_FILE: u64 = 512 * 1024 * 1024;
/// Caps so a crafted ZIP can't drive unbounded allocation while reading `unpin/*`.
const MAX_META_ENTRIES: usize = 8192;
const MAX_META_ENTRY: u64 = 16 * 1024 * 1024;
const MAX_META_TOTAL: u64 = 64 * 1024 * 1024;

const EOCD_SIG: [u8; 4] = [0x50, 0x4b, 0x05, 0x06]; // PK\x05\x06
const CDH_SIG: [u8; 4] = [0x50, 0x4b, 0x01, 0x02]; // PK\x01\x02
const LFH_SIG: [u8; 4] = [0x50, 0x4b, 0x03, 0x04]; // PK\x03\x04 (local file header)
const ALIASES_PATH: &str = "unpin/aliases";
/// Reserved STORED entry holding the shared zstd dictionary a large man overlay
/// was packed against (written by `unpin-vfs-pack --dict`). Outside the served
/// `unpin/` namespace (leading dot) so it's never mistaken for a payload entry.
const ZDICT_PATH: &str = ".unpin/zdict";

/// One materialized `unpin/*` entry.
#[derive(Debug)]
pub struct Entry {
    pub path: String,
    pub is_symlink: bool,
    pub data: Vec<u8>,
}

/// The `unpin/*` entries collected from a binary's embedded ZIP(s).
#[derive(Debug)]
pub struct Meta {
    entries: Vec<Entry>,
}

/// Read `path` and collect any embedded `unpin/*` entries.
///
/// `Ok(None)` = no `unpin/*` entries found; `Ok(Some(meta))` = collected;
/// `Err(e)` = a fatal ambiguity (two ZIPs carrying `unpin/aliases`) or a cap
/// breach. A binary with unrelated ZIPs but no `unpin/` entries reads as `None`.
pub fn read(path: &Path) -> Result<Option<Meta>, String> {
    let len = fs::metadata(path)
        .map_err(|e| format!("stat {}: {e}", path.display()))?
        .len();
    if len > MAX_FILE {
        return Err(format!(
            "{}: {len} bytes is too large to scan for embedded metadata (max {MAX_FILE})",
            path.display()
        ));
    }
    let data = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    read_bytes(&data)
}

fn read_bytes(data: &[u8]) -> Result<Option<Meta>, String> {
    let mut entries: Vec<Entry> = Vec::new();
    let mut total: u64 = 0;
    let mut alias_bearing_zips = 0usize;

    for (start, end, eocd) in locate_zips(data) {
        let slice = &data[start..end];
        // Parse the central directory ourselves rather than via the `zip` crate
        // so method 93 (Zstandard) entries decode through the pure-Rust `ruzstd`
        // already used for release assets — the reader stays portable to every
        // cross target (mingw, i686/riscv64-musl) without a C zstd. A slice we
        // can't parse cleanly is skipped: another ZIP may hold our `unpin/*`.
        let Some(cd) = parse_central_dir(slice, eocd - start) else {
            continue;
        };
        // A large man overlay ships a shared zstd dictionary (the reserved STORED
        // `.unpin/zdict` entry) that every method-93 entry was trained against;
        // load it once and reuse the decoder across this overlay. A plain
        // (no-dict) or non-zstd overlay yields `None` and decodes directly.
        let mut dict_dec = overlay_dict(&cd)?;
        let mut has_aliases_here = false;
        for ent in &cd {
            if !ent.name.starts_with("unpin/") || ent.name.ends_with('/') {
                continue;
            }
            let sz = ent.usize as u64;
            if sz > MAX_META_ENTRY {
                return Err(format!(
                    "embedded `{}` is {sz} bytes (max {MAX_META_ENTRY})",
                    ent.name
                ));
            }
            total = total.saturating_add(sz);
            if total > MAX_META_TOTAL {
                return Err(format!("embedded meta exceeds {MAX_META_TOTAL} bytes total"));
            }
            if entries.len() >= MAX_META_ENTRIES {
                return Err(format!("embedded meta exceeds {MAX_META_ENTRIES} entries"));
            }
            let buf = match decompress(ent.method, ent.payload, dict_dec.as_mut()) {
                None => {
                    return Err(format!(
                        "embedded `{}`: unsupported compression method {}",
                        ent.name, ent.method
                    ));
                }
                Some(Err(e)) => return Err(format!("read embedded `{}`: {e}", ent.name)),
                Some(Ok(b)) => b,
            };
            // The declared sizes and CRC are the integrity check the `zip` crate
            // used to give us for free; keep it now that we decode by hand.
            if buf.len() != ent.usize {
                return Err(format!(
                    "embedded `{}`: decoded {} bytes, header declares {}",
                    ent.name,
                    buf.len(),
                    ent.usize
                ));
            }
            if crc32(&buf) != ent.crc {
                return Err(format!("embedded `{}`: CRC mismatch", ent.name));
            }
            if ent.name == ALIASES_PATH {
                has_aliases_here = true;
            }
            entries.push(Entry {
                path: ent.name.clone(),
                is_symlink: ent.is_symlink,
                data: buf,
            });
        }
        if has_aliases_here {
            alias_bearing_zips += 1;
        }
    }

    // The one security guard kept (doc §4): a binary we built carries exactly
    // one `unpin/aliases`. Two distinct ZIPs both carrying it is a tampered or
    // bundled artifact — refuse to guess which alias set to trust.
    if alias_bearing_zips > 1 {
        return Err("multiple embedded ZIPs carry unpin/aliases — refusing to guess".into());
    }

    if entries.is_empty() {
        Ok(None)
    } else {
        Ok(Some(Meta { entries }))
    }
}

/// Scan `data` for every validated ZIP, returning `(zip_start, zip_end, eocd)`
/// byte offsets. Each `[start, end)` is a clean, zero-prefix ZIP slice (doc §2);
/// `eocd` is the absolute offset of its End Of Central Directory record.
fn locate_zips(data: &[u8]) -> Vec<(usize, usize, usize)> {
    let mut out = Vec::new();
    if data.len() < 22 {
        return out;
    }
    let mut i = 0;
    // Last position an EOCD's 22-byte fixed record could start.
    let limit = data.len() - 22;
    while i <= limit {
        if data[i..i + 4] == EOCD_SIG
            && let Some((start, end)) = validate_eocd(data, i)
        {
            out.push((start, end, i));
            i = end; // a validated ZIP can't overlap the next; skip past it
            continue;
        }
        i += 1;
    }
    out
}

/// One entry harvested from a ZIP's central directory, with its raw (still
/// compressed) payload sliced out of the archive.
struct CdEntry<'a> {
    name: String,
    method: u16,
    crc: u32,
    usize: usize,
    payload: &'a [u8],
    is_symlink: bool,
}

/// Walk the central directory of the ZIP `slice` (whose EOCD sits at offset
/// `eocd`), returning every entry. `None` on any structural inconsistency — the
/// caller treats that as "not one of ours" and moves on. Does not decompress.
fn parse_central_dir(slice: &[u8], eocd: usize) -> Option<Vec<CdEntry<'_>>> {
    let hdr = slice.get(eocd..eocd + 22)?;
    let n_entries = u16::from_le_bytes([hdr[10], hdr[11]]) as usize;
    let cd_size = u32::from_le_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]) as usize;
    let cd_offset = u32::from_le_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]) as usize;
    if cd_offset.checked_add(cd_size)? > slice.len() {
        return None;
    }
    let mut p = cd_offset;
    let mut out = Vec::new();
    for _ in 0..n_entries {
        let h = slice.get(p..p + 46)?;
        if h[0..4] != CDH_SIG {
            return None;
        }
        let made_by = u16::from_le_bytes([h[4], h[5]]);
        let method = u16::from_le_bytes([h[10], h[11]]);
        let crc = u32::from_le_bytes([h[16], h[17], h[18], h[19]]);
        let csize = u32::from_le_bytes([h[20], h[21], h[22], h[23]]) as usize;
        let usize_ = u32::from_le_bytes([h[24], h[25], h[26], h[27]]) as usize;
        let nlen = u16::from_le_bytes([h[28], h[29]]) as usize;
        let elen = u16::from_le_bytes([h[30], h[31]]) as usize;
        let clen = u16::from_le_bytes([h[32], h[33]]) as usize;
        let ext_attr = u32::from_le_bytes([h[38], h[39], h[40], h[41]]);
        let loff = u32::from_le_bytes([h[42], h[43], h[44], h[45]]) as usize;
        let name = std::str::from_utf8(slice.get(p + 46..p + 46 + nlen)?)
            .ok()?
            .to_string();
        // Follow the local file header to where this entry's payload begins —
        // the central dir's stored offset is only the LFH, whose name/extra
        // lengths can differ from the central record's.
        let lh = slice.get(loff..loff + 30)?;
        if lh[0..4] != LFH_SIG {
            return None;
        }
        let lh_nlen = u16::from_le_bytes([lh[26], lh[27]]) as usize;
        let lh_elen = u16::from_le_bytes([lh[28], lh[29]]) as usize;
        let data_start = loff.checked_add(30)?.checked_add(lh_nlen)?.checked_add(lh_elen)?;
        let payload = slice.get(data_start..data_start.checked_add(csize)?)?;
        // Unix symlink: external attrs carry the mode only when "made by" Unix.
        let unix_mode = if made_by >> 8 == 3 { ext_attr >> 16 } else { 0 };
        out.push(CdEntry {
            name,
            method,
            crc,
            usize: usize_,
            payload,
            is_symlink: unix_mode & 0o170000 == 0o120000,
        });
        p = p
            .checked_add(46)?
            .checked_add(nlen)?
            .checked_add(elen)?
            .checked_add(clen)?;
    }
    Some(out)
}

/// Decompress one ZIP payload by method: `0` stored, `8` raw deflate (via
/// `flate2`), `93` Zstandard (via the pure-Rust `ruzstd`). `None` = a method we
/// don't implement. When `dict` is `Some`, method-93 frames decode against that
/// shared dictionary (large man overlays); the same decoder is reused across the
/// overlay's entries. The output is bounded at `MAX_META_ENTRY + 1` so a crafted
/// entry can't drive an unbounded allocation; the caller's size/CRC check then
/// rejects anything that didn't decode to exactly its declared length.
fn decompress(
    method: u16,
    payload: &[u8],
    dict: Option<&mut ruzstd::FrameDecoder>,
) -> Option<Result<Vec<u8>, String>> {
    fn capped<R: Read>(r: R) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        r.take(MAX_META_ENTRY + 1)
            .read_to_end(&mut out)
            .map(|_| out)
            .map_err(|e| e.to_string())
    }
    match method {
        0 => Some(Ok(payload.to_vec())),
        8 => Some(capped(flate2::read::DeflateDecoder::new(payload))),
        93 => match dict {
            Some(fd) => match ruzstd::StreamingDecoder::new_with_decoder(payload, fd) {
                Ok(z) => Some(capped(z)),
                Err(e) => Some(Err(e.to_string())),
            },
            None => match ruzstd::StreamingDecoder::new(payload) {
                Ok(z) => Some(capped(z)),
                Err(e) => Some(Err(e.to_string())),
            },
        },
        _ => None,
    }
}

/// Build the shared-dictionary decoder for one overlay, if it needs one: present
/// only when the overlay has zstd `unpin/*` entries AND carries the reserved
/// STORED `.unpin/zdict`. Returns `Ok(None)` for plain/non-zstd overlays. The
/// dict entry is STORED, so its payload is the raw dictionary bytes.
fn overlay_dict(cd: &[CdEntry]) -> Result<Option<ruzstd::FrameDecoder>, String> {
    let needs_dict = cd
        .iter()
        .any(|e| e.method == 93 && e.name.starts_with("unpin/") && !e.name.ends_with('/'));
    if !needs_dict {
        return Ok(None);
    }
    let Some(zd) = cd.iter().find(|e| e.name == ZDICT_PATH && e.method == 0) else {
        return Ok(None); // plain zstd overlay (small man set, no dict)
    };
    let dict = ruzstd::decoding::dictionary::Dictionary::decode_dict(zd.payload)
        .map_err(|e| format!("embedded `{ZDICT_PATH}`: {e}"))?;
    let mut fd = ruzstd::FrameDecoder::new();
    fd.add_dict(dict)
        .map_err(|e| format!("embedded `{ZDICT_PATH}`: {e}"))?;
    Ok(Some(fd))
}

/// CRC-32 (ISO-HDLC, the ZIP variant) — reuses `flate2`'s, already a dependency.
fn crc32(data: &[u8]) -> u32 {
    let mut h = flate2::Crc::new();
    h.update(data);
    h.sum()
}

/// Validate the EOCD at `e` and return the enclosing `(zip_start, zip_end)`.
/// Rejects coincidental `PK\x05\x06` hits (the central directory it claims must
/// actually be there) and ZIP64 (never produced by our writers).
fn validate_eocd(data: &[u8], e: usize) -> Option<(usize, usize)> {
    let hdr = data.get(e..e + 22)?;
    let cd_size = u32::from_le_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]) as usize;
    let cd_offset = u32::from_le_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]) as usize;
    let comment_len = u16::from_le_bytes([hdr[20], hdr[21]]) as usize;
    // ZIP64 sentinel — we never emit it; treat as not-our-ZIP.
    if cd_size == 0xffff_ffff || cd_offset == 0xffff_ffff {
        return None;
    }
    let zip_end = e.checked_add(22)?.checked_add(comment_len)?;
    if zip_end > data.len() {
        return None;
    }
    // The central directory ends right where the EOCD begins.
    let cd_start = e.checked_sub(cd_size)?;
    let zip_start = cd_start.checked_sub(cd_offset)?;
    // It must actually be a central directory, not a stray signature in code.
    if data.get(cd_start..cd_start + 4)? != CDH_SIG {
        return None;
    }
    Some((zip_start, zip_end))
}

impl Meta {
    /// The exact `unpin/<path>` entry, if present.
    pub fn entry(&self, path: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.path == path)
    }

    /// Every entry whose path starts with `prefix` (e.g. `"unpin/man/"`).
    pub fn entries_under<'a>(&'a self, prefix: &'a str) -> impl Iterator<Item = &'a Entry> {
        self.entries
            .iter()
            .filter(move |e| e.path.starts_with(prefix))
    }

    /// Declared alias names from `unpin/aliases`: one per line, blank lines and
    /// `#` comments skipped, deduped preserving first-seen order. Validation
    /// (blocklist, charset, …) is the caller's job via `aliases::validate_alias`.
    pub fn aliases(&self) -> Vec<String> {
        let Some(e) = self.entry(ALIASES_PATH) else {
            return Vec::new();
        };
        let Ok(text) = std::str::from_utf8(&e.data) else {
            return Vec::new();
        };
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for line in text.lines() {
            let n = line.trim();
            if n.is_empty() || n.starts_with('#') {
                continue;
            }
            if seen.insert(n.to_string()) {
                out.push(n.to_string());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// How a test entry is stored.
    enum M {
        Stored,
        Deflate,
        /// Zstandard, ZIP method 93 — what `withMan` now emits for man pages.
        Zstd,
        /// Method 93 with the payload supplied verbatim (a pre-built zstd frame),
        /// for the dictionary fixture whose frame was trained against `.unpin/zdict`.
        ZstdRaw(Vec<u8>),
        /// Stored, but flagged as a unix symlink (external attr S_IFLNK).
        Symlink,
    }

    fn crc32(data: &[u8]) -> u32 {
        let mut h = flate2::Crc::new();
        h.update(data);
        h.sum()
    }

    fn raw_deflate(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// A standard single-frame zstd stream (the C `zstd` crate, dev-only) — the
    /// reader must decode it with the pure-Rust `ruzstd`.
    fn raw_zstd(data: &[u8]) -> Vec<u8> {
        zstd::encode_all(data, 3).unwrap()
    }

    /// Build a standard ZIP from `(name, data, method)` triples.
    fn build_zip(entries: &[(&str, &[u8], M)]) -> Vec<u8> {
        const DOS_DATE: u16 = 0x0021;
        let mut zip = Vec::new();
        // (offset, crc, comp_size, uncomp_size, method, name, external_attr)
        let mut cd_meta: Vec<(u32, u32, u32, u32, u16, &str, u32)> = Vec::new();

        for (name, data, method) in entries {
            let offset = zip.len() as u32;
            let crc = crc32(data);
            let (m, payload): (u16, Vec<u8>) = match method {
                M::Stored | M::Symlink => (0, data.to_vec()),
                M::Deflate => (8, raw_deflate(data)),
                M::Zstd => (93, raw_zstd(data)),
                M::ZstdRaw(frame) => (93, frame.clone()),
            };
            let ext_attr = match method {
                M::Symlink => (0o120777u32) << 16,
                _ => (0o100644u32) << 16,
            };
            let nlen = name.len() as u16;
            let csize = payload.len() as u32;
            let usize_ = data.len() as u32;

            zip.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
            zip.extend_from_slice(&20u16.to_le_bytes());
            zip.extend_from_slice(&0u16.to_le_bytes());
            zip.extend_from_slice(&m.to_le_bytes());
            zip.extend_from_slice(&0u16.to_le_bytes()); // time
            zip.extend_from_slice(&DOS_DATE.to_le_bytes());
            zip.extend_from_slice(&crc.to_le_bytes());
            zip.extend_from_slice(&csize.to_le_bytes());
            zip.extend_from_slice(&usize_.to_le_bytes());
            zip.extend_from_slice(&nlen.to_le_bytes());
            zip.extend_from_slice(&0u16.to_le_bytes());
            zip.extend_from_slice(name.as_bytes());
            zip.extend_from_slice(&payload);

            cd_meta.push((offset, crc, csize, usize_, m, name, ext_attr));
        }

        let cd_offset = zip.len() as u32;
        for (offset, crc, csize, usize_, m, name, ext_attr) in &cd_meta {
            zip.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]);
            zip.extend_from_slice(&0x031eu16.to_le_bytes()); // made by: unix
            zip.extend_from_slice(&20u16.to_le_bytes());
            zip.extend_from_slice(&0u16.to_le_bytes());
            zip.extend_from_slice(&m.to_le_bytes());
            zip.extend_from_slice(&0u16.to_le_bytes());
            zip.extend_from_slice(&DOS_DATE.to_le_bytes());
            zip.extend_from_slice(&crc.to_le_bytes());
            zip.extend_from_slice(&csize.to_le_bytes());
            zip.extend_from_slice(&usize_.to_le_bytes());
            zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
            zip.extend_from_slice(&0u16.to_le_bytes()); // extra
            zip.extend_from_slice(&0u16.to_le_bytes()); // comment
            zip.extend_from_slice(&0u16.to_le_bytes()); // disk
            zip.extend_from_slice(&0u16.to_le_bytes()); // internal
            zip.extend_from_slice(&ext_attr.to_le_bytes());
            zip.extend_from_slice(&offset.to_le_bytes());
            zip.extend_from_slice(name.as_bytes());
        }
        let cd_size = zip.len() as u32 - cd_offset;

        zip.extend_from_slice(&EOCD_SIG);
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&(cd_meta.len() as u16).to_le_bytes());
        zip.extend_from_slice(&(cd_meta.len() as u16).to_le_bytes());
        zip.extend_from_slice(&cd_size.to_le_bytes());
        zip.extend_from_slice(&cd_offset.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip
    }

    /// Embed `zip` mid-binary: junk prefix + zip + junk suffix, mimicking a
    /// real binary where the ZIP isn't at EOF.
    fn embed(zip: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"\x7fELF fake program bytes \x00\x01\x02\x03");
        v.extend_from_slice(zip);
        v.extend_from_slice(b"trailing non-zip bytes \xca\xfe");
        v
    }

    #[test]
    fn reads_aliases_and_man_mid_binary() {
        let zip = build_zip(&[
            ("unpin/aliases", b"xzcat\nunxz\n# note\n\nlzma\n", M::Stored),
            ("unpin/man/xz.1", b".TH XZ 1\nbody", M::Deflate),
        ]);
        let bin = embed(&zip);
        let meta = read_bytes(&bin).unwrap().unwrap();
        assert_eq!(meta.aliases(), vec!["xzcat", "unxz", "lzma"]);
        let man: Vec<_> = meta.entries_under("unpin/man/").collect();
        assert_eq!(man.len(), 1);
        assert_eq!(man[0].path, "unpin/man/xz.1");
        assert_eq!(man[0].data, b".TH XZ 1\nbody");
    }

    #[test]
    fn reads_zstd_man_pages() {
        // What `withMan` now ships: aliases stored, man pages as zstd (method
        // 93). The reader must decode them via ruzstd, with the CRC/size checks
        // passing. Body is repetitive so zstd actually shrinks it.
        let body = b".TH PERL 1\n".repeat(400);
        let zip = build_zip(&[
            ("unpin/aliases", b"perldoc\nperlbug\n", M::Stored),
            ("unpin/man/perl.1", &body, M::Zstd),
            ("unpin/man/perlfunc.1", b".TH PERLFUNC 1\nshort", M::Zstd),
        ]);
        let meta = read_bytes(&embed(&zip)).unwrap().unwrap();
        assert_eq!(meta.aliases(), vec!["perldoc", "perlbug"]);
        let mut man: Vec<_> = meta.entries_under("unpin/man/").collect();
        man.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(man.len(), 2);
        assert_eq!(man[0].path, "unpin/man/perl.1");
        assert_eq!(man[0].data, body);
        assert_eq!(man[1].data, b".TH PERLFUNC 1\nshort");
    }

    #[test]
    fn reads_dict_compressed_man_page() {
        // The large-man-set path: a shared zstd dictionary stored as `.unpin/zdict`
        // and a page compressed against it (fixtures built with the real `zstd`
        // CLI: `--train` then `-D`). The reader must load the dict and decode the
        // method-93 frame through ruzstd — and must NOT surface the dict as an entry.
        let dict: &[u8] = include_bytes!("testdata/man.zdict");
        let plain: &[u8] = include_bytes!("testdata/man_page.1");
        let frame = include_bytes!("testdata/man_page.1.zst").to_vec();
        let zip = build_zip(&[
            (ZDICT_PATH, dict, M::Stored),
            ("unpin/man/tool42.1", plain, M::ZstdRaw(frame)),
        ]);
        let meta = read_bytes(&embed(&zip)).unwrap().unwrap();
        assert!(meta.entry(ZDICT_PATH).is_none(), "dict must not be served");
        let page = meta.entry("unpin/man/tool42.1").expect("man page entry");
        assert_eq!(page.data, plain, "dict-decoded page must match the original");
    }

    #[test]
    fn corrupt_zstd_payload_is_rejected() {
        // A method-93 entry whose CRC won't match its (mangled) bytes must error,
        // not silently yield garbage.
        let mut zip = build_zip(&[("unpin/man/x.1", b"hello world hello world", M::Zstd)]);
        // Corrupt the first byte of the zstd payload (the frame magic) — past the
        // 30-byte local header + the entry name — so the decode itself fails.
        let payload_start = 30 + "unpin/man/x.1".len();
        zip[payload_start] ^= 0xff;
        assert!(read_bytes(&embed(&zip)).is_err());
    }

    #[test]
    fn no_zip_returns_none() {
        let bin = b"a plain binary with no embedded zip at all".to_vec();
        assert!(read_bytes(&bin).unwrap().is_none());
    }

    #[test]
    fn zip_without_meta_entries_returns_none() {
        // A runtime ZIP (cosmo zoneinfo / VFS) carries no unpin/* — contributes
        // nothing, reads as None.
        let zip = build_zip(&[("usr/share/zoneinfo/UTC", b"TZif...", M::Stored)]);
        assert!(read_bytes(&embed(&zip)).unwrap().is_none());
    }

    #[test]
    fn coincidental_eocd_signature_is_rejected() {
        // PK\x05\x06 in junk with no valid central directory behind it must not
        // be mistaken for a ZIP.
        let mut bin = b"prefix".to_vec();
        bin.extend_from_slice(&EOCD_SIG);
        bin.extend_from_slice(&[0u8; 18]); // bogus EOCD fields, cd_size/off = 0
        bin.extend_from_slice(b"suffix");
        assert!(read_bytes(&bin).unwrap().is_none());
    }

    #[test]
    fn symlink_entry_is_flagged() {
        let zip = build_zip(&[("unpin/man/vigr.8", b"vipw.8", M::Symlink)]);
        let meta = read_bytes(&embed(&zip)).unwrap().unwrap();
        let e = meta.entry("unpin/man/vigr.8").unwrap();
        assert!(e.is_symlink);
        assert_eq!(e.data, b"vipw.8");
    }

    #[test]
    fn two_zips_with_aliases_is_fatal() {
        // A bundled/tampered artifact: two distinct ZIPs each declaring aliases.
        let a = build_zip(&[("unpin/aliases", b"foo\n", M::Stored)]);
        let b = build_zip(&[("unpin/aliases", b"bar\n", M::Stored)]);
        let mut bin = embed(&a);
        bin.extend_from_slice(&b);
        let err = read_bytes(&bin).unwrap_err();
        assert!(err.contains("refusing to guess"), "got: {err}");
    }

    #[test]
    fn second_zip_man_only_is_fine() {
        // Two ZIPs but only one has aliases — no ambiguity. Man entries union.
        let runtime = build_zip(&[("runtime/foo", b"x", M::Stored)]);
        let meta_zip = build_zip(&[
            ("unpin/aliases", b"foo\n", M::Stored),
            ("unpin/man/foo.1", b"page", M::Stored),
        ]);
        let mut bin = embed(&runtime);
        bin.extend_from_slice(&meta_zip);
        let meta = read_bytes(&bin).unwrap().unwrap();
        assert_eq!(meta.aliases(), vec!["foo"]);
        assert_eq!(meta.entries_under("unpin/man/").count(), 1);
    }

    #[test]
    fn reads_own_embedded_zip() {
        // The test binary carries the same `#[used]` UNPIN_META_ZIP + build.rs
        // ZIP as the real `unpin` binary, so scanning our own file must find it.
        // Locks down `#[used]` retention AND that the self-scan needs no marker
        // (the EOCD validation rejects the reader's own .rodata constants).
        let exe = std::env::current_exe().expect("current_exe");
        let meta = read(&exe)
            .expect("read own binary")
            .expect("embedded meta ZIP present");
        let page = meta.entry("unpin/man/unpin.1").expect("unpin.1 entry");
        assert!(
            page.data.windows(9).any(|w| w == b".TH UNPIN"),
            "expected unpin man roff source"
        );
    }
}
