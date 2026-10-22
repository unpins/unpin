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

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Seek};
use std::path::Path;

use crate::sqfs;

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
    read_container(open(path)?).map_err(|e| format!("{}: {e}", path.display()))
}

/// Where a binary's `unpin/*` entries live.
enum Container<R> {
    /// A squashfs image behind the footer (Linux); authoritative when present.
    Image(R, sqfs::Footer),
    /// The whole file, to scan for embedded ZIPs.
    Zips(Vec<u8>),
    /// No footer, and too large to scan.
    TooLarge(u64),
}

fn open(path: &Path) -> Result<Container<fs::File>, String> {
    let f = fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let len = f
        .metadata()
        .map_err(|e| format!("stat {}: {e}", path.display()))?
        .len();
    container(f, len).map_err(|e| format!("{}: {e}", path.display()))
}

fn container<R: Read + Seek>(mut r: R, len: u64) -> Result<Container<R>, String> {
    if let Some(ft) = sqfs::footer(&mut r, len)? {
        return Ok(Container::Image(r, ft));
    }
    if len > MAX_FILE {
        return Ok(Container::TooLarge(len));
    }
    let mut data = Vec::new();
    r.rewind()
        .and_then(|_| r.read_to_end(&mut data))
        .map_err(|e| format!("read: {e}"))?;
    Ok(Container::Zips(data))
}

fn read_container<R: Read + Seek>(c: Container<R>) -> Result<Option<Meta>, String> {
    match c {
        Container::Image(r, ft) => read_image(r, &ft),
        Container::Zips(data) => read_zips(&data),
        Container::TooLarge(len) => Err(format!(
            "{len} bytes is too large to scan for embedded metadata (max {MAX_FILE})"
        )),
    }
}

/// Count one `unpin/*` entry of `size` bytes against the per-entry and total caps.
fn charge_entry(total: &mut u64, path: &str, size: u64) -> Result<(), String> {
    if size > MAX_META_ENTRY {
        return Err(format!(
            "embedded `{path}` is {size} bytes (max {MAX_META_ENTRY})"
        ));
    }
    *total = total.saturating_add(size);
    if *total > MAX_META_TOTAL {
        return Err(format!(
            "embedded meta exceeds {MAX_META_TOTAL} bytes total"
        ));
    }
    Ok(())
}

/// Collect the `unpin/*` entries of a footer-located squashfs image (Linux).
/// The footer is authoritative: no ZIP scan follows, and a damaged image is
/// an error rather than "no metadata".
fn read_image<R: Read + Seek>(r: R, ft: &sqfs::Footer) -> Result<Option<Meta>, String> {
    let mut img = sqfs::Image::open(r, ft.offset, ft.size)?;
    let Some(dir) = img.lookup("unpin")? else {
        return Ok(None);
    };
    let mut entries = Vec::new();
    let mut total: u64 = 0;
    for (rel, node) in sqfs::walk(&mut img, &dir, MAX_META_ENTRIES)? {
        let path = format!("unpin/{rel}");
        let (is_symlink, data) = match node {
            sqfs::Node::File(f) => {
                charge_entry(&mut total, &path, f.size)?;
                let data = img
                    .read_file(&f, f.size)
                    .map_err(|e| format!("read embedded `{path}`: {e}"))?;
                (false, data)
            }
            sqfs::Node::Symlink(t) => (true, t),
            _ => continue,
        };
        entries.push(Entry {
            path,
            is_symlink,
            data,
        });
    }
    Ok((!entries.is_empty()).then_some(Meta { entries }))
}

/// [`read`] over an in-memory binary.
#[cfg(test)]
fn read_bytes(data: &[u8]) -> Result<Option<Meta>, String> {
    read_container(container(std::io::Cursor::new(data), data.len() as u64)?)
}

/// The ZIP container (macOS, Windows, and Linux binaries built before the
/// squashfs one): every embedded ZIP in `data` is scanned.
fn read_zips(data: &[u8]) -> Result<Option<Meta>, String> {
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
            charge_entry(&mut total, &ent.name, ent.usize as u64)?;
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
        let data_start = loff
            .checked_add(30)?
            .checked_add(lh_nlen)?
            .checked_add(lh_elen)?;
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
    decompress_capped(method, payload, dict, MAX_META_ENTRY + 1)
}

/// Like [`decompress`] but stops after at most `limit` output bytes. Used to
/// read only the NAME-section prefix of a man page (see [`read_program_docs`])
/// without inflating the whole body. `ruzstd`'s streaming decoder decodes blocks
/// on demand, so a small `limit` touches only the first block(s); dropping the
/// decoder mid-frame is safe because the next `new`/`new_with_decoder` re-`init`s
/// the frame from its header (and the shared dict map survives that reset).
fn decompress_capped(
    method: u16,
    payload: &[u8],
    dict: Option<&mut ruzstd::FrameDecoder>,
    limit: u64,
) -> Option<Result<Vec<u8>, String>> {
    fn capped<R: Read>(r: R, limit: u64) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        r.take(limit)
            .read_to_end(&mut out)
            .map(|_| out)
            .map_err(|e| e.to_string())
    }
    match method {
        0 => Some(capped(payload, limit)),
        8 => Some(capped(flate2::read::DeflateDecoder::new(payload), limit)),
        93 => match dict {
            Some(fd) => match ruzstd::StreamingDecoder::new_with_decoder(payload, fd) {
                Ok(z) => Some(capped(z, limit)),
                Err(e) => Some(Err(e.to_string())),
            },
            None => match ruzstd::StreamingDecoder::new(payload) {
                Ok(z) => Some(capped(z, limit)),
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
        self.entry(ALIASES_PATH)
            .map(|e| alias_names(&e.data))
            .unwrap_or_default()
    }
}

/// Parse the `unpin/aliases` payload: one name per line, blank lines and `#`
/// comments skipped, deduped preserving first-seen order. Shared by
/// [`Meta::aliases`] and [`read_program_docs`].
fn alias_names(data: &[u8]) -> Vec<String> {
    let Ok(text) = std::str::from_utf8(data) else {
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

/// One documented program in a binary's bundle: its command name and, when its
/// man page carries a NAME section, the one-line description harvested from it.
#[derive(Debug, PartialEq, Eq)]
pub struct ProgramDoc {
    pub name: String,
    pub whatis: Option<String>,
}

/// How much of each man page to inflate when harvesting its whatis. The NAME
/// section sits right after the `.TH`/comment preamble, so a small prefix always
/// covers it (even the long DocBook headers) while never touching the — often
/// far larger — body.
const WHATIS_SCAN: u64 = 8 * 1024;

/// Enumerate the programs a binary's embedded bundle documents, each paired with
/// the one-line description from its man page's NAME section (the `whatis`).
///
/// The program set is the union of the declared multicall aliases
/// (`unpin/aliases`) and the stems of the embedded man pages
/// (`unpin/man/<name>.<section>`): a single-command package shows its one tool,
/// a multicall shows every applet. Names are returned sorted.
///
/// Only a bounded prefix of each man page is inflated (see [`WHATIS_SCAN`]) —
/// never the whole body — so this stays cheap even for a multicall with a man
/// page per applet. `Ok(None)` = no bundle (or nothing documentable). It is
/// best-effort by design: a page we can't locate or parse yields `whatis: None`,
/// not an error.
pub fn read_program_docs(path: &Path) -> Result<Option<Vec<ProgramDoc>>, String> {
    Ok(program_docs_in(open(path)?))
}

fn program_docs_in<R: Read + Seek>(c: Container<R>) -> Option<Vec<ProgramDoc>> {
    match c {
        Container::Image(r, ft) => program_docs_from_image(r, &ft),
        Container::Zips(data) => program_docs_from_zips(&data),
        Container::TooLarge(_) => None,
    }
}

/// [`read_program_docs`] over an in-memory binary.
#[cfg(test)]
fn program_docs_from_bytes(data: &[u8]) -> Result<Option<Vec<ProgramDoc>>, String> {
    Ok(program_docs_in(container(
        std::io::Cursor::new(data),
        data.len() as u64,
    )?))
}

fn program_docs_from_zips(data: &[u8]) -> Option<Vec<ProgramDoc>> {
    // Accumulate across every embedded ZIP, not just the first: a binary built
    // before the unified container splits `unpin/aliases` (main embed) from its
    // `unpin/man/*` pages (a separate dict-trained man overlay), so the program
    // names and their descriptions can live in different ZIPs. Each overlay
    // carries its own shared dict, so whatis is resolved inside its own loop.
    let mut whatis: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut aliases: Vec<String> = Vec::new();
    let mut saw_bundle = false;

    for (start, end, eocd) in locate_zips(data) {
        let slice = &data[start..end];
        let Some(cd) = parse_central_dir(slice, eocd - start) else {
            continue;
        };
        // Skip non-bundle ZIPs (cosmo/VFS runtime ZIPs carry no `unpin/*`).
        if !cd
            .iter()
            .any(|e| e.name.starts_with("unpin/") && !e.name.ends_with('/'))
        {
            continue;
        }
        saw_bundle = true;
        let mut dict = overlay_dict(&cd).ok().flatten();

        // Declared multicall aliases (small entry — full-decode is cheap).
        if let Some(e) = cd.iter().find(|e| e.name == ALIASES_PATH)
            && let Some(Ok(b)) = decompress(e.method, e.payload, dict.as_mut())
        {
            aliases.extend(alias_names(&b));
        }

        // Resolve each man page's whatis now, while this overlay's dict is live.
        let man: Vec<(&str, bool, &CdEntry)> = cd
            .iter()
            .filter_map(|e| Some((e.name.strip_prefix("unpin/man/")?, e.is_symlink, e)))
            .collect();
        let files: Vec<(&str, bool)> = man.iter().map(|&(n, l, _)| (n, l)).collect();
        let found = man_whatis(&files, |i, limit| {
            let e = man[i].2;
            decompress_capped(e.method, e.payload, dict.as_mut(), limit)?.ok()
        });
        for (stem, w) in found {
            let slot = whatis.entry(stem).or_insert(None);
            if w.is_some() {
                *slot = w;
            }
        }
    }

    if !saw_bundle {
        return None;
    }
    docs_from(whatis, aliases)
}

/// The squashfs-container counterpart of [`program_docs_from_zips`]: one image,
/// read through its directory tree, so only `unpin/aliases` and the first
/// block of each man page are ever decoded.
fn program_docs_from_image<R: Read + Seek>(r: R, ft: &sqfs::Footer) -> Option<Vec<ProgramDoc>> {
    let mut img = sqfs::Image::open(r, ft.offset, ft.size).ok()?;
    img.lookup("unpin").ok()??;
    let mut aliases = Vec::new();
    if let Ok(Some(sqfs::Node::File(f))) = img.lookup(ALIASES_PATH)
        && f.size <= MAX_META_ENTRY
        && let Ok(b) = img.read_file(&f, f.size)
    {
        aliases = alias_names(&b);
    }
    let mut whatis = BTreeMap::new();
    if let Ok(Some(dir @ sqfs::Node::Dir { .. })) = img.lookup("unpin/man")
        && let Ok(list) = img.read_dir(&dir)
    {
        let nodes: Vec<(String, sqfs::Node)> = list
            .into_iter()
            .filter_map(|(name, iref)| Some((name, img.inode(iref).ok()?)))
            .filter(|(_, n)| matches!(n, sqfs::Node::File(_) | sqfs::Node::Symlink(_)))
            .collect();
        let files: Vec<(&str, bool)> = nodes
            .iter()
            .map(|(n, node)| (n.as_str(), matches!(node, sqfs::Node::Symlink(_))))
            .collect();
        whatis = man_whatis(&files, |i, limit| match &nodes[i].1 {
            sqfs::Node::File(f) => img.read_file(f, limit).ok(),
            sqfs::Node::Symlink(t) => Some(t.clone()),
            _ => unreachable!("filtered to files and symlinks above"),
        });
    }
    docs_from(whatis, aliases)
}

/// The sorted union of the documented stems and the declared aliases, each
/// with its whatis. `None` if there is nothing to list.
fn docs_from(
    whatis: BTreeMap<String, Option<String>>,
    aliases: Vec<String>,
) -> Option<Vec<ProgramDoc>> {
    let mut names: BTreeSet<String> = whatis.keys().cloned().collect();
    names.extend(aliases);
    if names.is_empty() {
        return None;
    }
    Some(
        names
            .into_iter()
            .map(|name| {
                let whatis = whatis.get(&name).cloned().flatten();
                ProgramDoc { name, whatis }
            })
            .collect(),
    )
}

/// The whatis of every program in one man listing. `files[i]` is a page's name
/// under `unpin/man/` and whether it is a symlink; `read(i, limit)` returns the
/// first `limit` bytes of page `i` (a symlink's target path). Pages are indexed
/// by stem, preferring the lowest section so `foo.1` wins over a stray `foo.3`;
/// one `.so`/symlink redirect (e.g. `unxz.1 -> xz.1`) is followed, and only the
/// NAME-section prefix is ever inflated.
fn man_whatis(
    files: &[(&str, bool)],
    mut read: impl FnMut(usize, u64) -> Option<Vec<u8>>,
) -> BTreeMap<String, Option<String>> {
    let mut man: BTreeMap<String, usize> = BTreeMap::new();
    for (i, (file, _)) in files.iter().enumerate() {
        if file.is_empty() || file.ends_with('/') {
            continue;
        }
        let (stem, sec) = split_section(file);
        match man.get(&stem) {
            Some(&j) if sec >= split_section(files[j].0).1 => {}
            _ => {
                man.insert(stem, i);
            }
        }
    }
    let mut whatis_of = |idx: usize| -> Option<String> {
        let target = if files[idx].1 {
            let tgt = String::from_utf8(read(idx, MAX_META_ENTRY + 1)?).ok()?;
            let base = tgt.trim().rsplit(['/', '\\']).next()?;
            let &j = man.get(&split_section(base).0)?;
            if files[j].1 {
                return None; // don't chase multi-hop redirects
            }
            j
        } else {
            idx
        };
        whatis_from_roff(&String::from_utf8_lossy(&read(target, WHATIS_SCAN)?))
    };
    man.iter()
        .map(|(stem, &i)| (stem.clone(), whatis_of(i)))
        .collect()
}

/// Split a man-page filename into `(stem, section)` on the final dot:
/// `pdftotext.1 -> ("pdftotext", "1")`, `mkfs.ext4.8 -> ("mkfs.ext4", "8")`.
fn split_section(file: &str) -> (String, String) {
    match file.rfind('.') {
        Some(i) if i > 0 => (file[..i].to_string(), file[i + 1..].to_string()),
        _ => (file.to_string(), String::new()),
    }
}

/// Pull the one-line description from a man page's NAME section. Handles man(7)
/// (`.SH NAME` / `name[, name…] \- description`) and mdoc(7) (`.Sh NAME` /
/// `.Nd description`). Only the first description line is taken (a continuation
/// like poppler's `(version 3.03)` is dropped, matching `whatis`/`apropos`).
/// `None` if the prefix holds no recognizable NAME description.
fn whatis_from_roff(text: &str) -> Option<String> {
    let mut lines = text.lines();
    loop {
        if is_name_header(lines.next()?.trim()) {
            break;
        }
    }
    for line in lines {
        let t = line.trim();
        if t.is_empty() || t.starts_with(".\\\"") {
            continue; // blank line or roff comment
        }
        if t.starts_with(".SH") || t.starts_with(".Sh") {
            break; // next section — NAME had no usable description
        }
        // mdoc: the description is its own `.Nd` macro.
        if let Some(rest) = t.strip_prefix(".Nd ") {
            return Some(clean_roff(rest));
        }
        // Other mdoc dot-macros in NAME (`.Nm name`) precede `.Nd` — skip them.
        if t.starts_with('.') {
            continue;
        }
        // man(7): `name[, name…] \- description`.
        if let Some(desc) = split_name_dash(t) {
            return Some(clean_roff(desc));
        }
    }
    None
}

/// Is `t` a `NAME`-section header — `.SH NAME`, `.SH "NAME"`, or mdoc `.Sh NAME`?
fn is_name_header(t: &str) -> bool {
    let Some(rest) = t.strip_prefix(".SH").or_else(|| t.strip_prefix(".Sh")) else {
        return false;
    };
    rest.trim()
        .trim_matches('"')
        .trim()
        .eq_ignore_ascii_case("NAME")
}

/// The description after the `name … \- description` separator on a man(7) NAME
/// line. The separator is a dash flanked by whitespace (` \- `, or an en/em dash,
/// or a literal ` - `) — matching that, not a bare `\-`, avoids splitting inside
/// a hyphenated command name written in roff as `curl\-config`.
fn split_name_dash(t: &str) -> Option<&str> {
    for sep in [" \\- ", " \\(en ", " \\(em ", " - "] {
        if let Some(i) = t.find(sep) {
            return Some(t[i + sep.len()..].trim_start());
        }
    }
    None
}

/// Strip the handful of roff escapes that show up in NAME lines (`\-`, font
/// changes `\fX`/`\f(XX`/`\f[..]`, zero-width `\&`) and collapse whitespace. Not
/// a full roff engine — just enough for a readable one-liner.
fn clean_roff(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('f') => match chars.peek() {
                Some('(') => {
                    chars.next();
                    chars.next();
                    chars.next();
                }
                Some('[') => {
                    chars.next();
                    for x in chars.by_ref() {
                        if x == ']' {
                            break;
                        }
                    }
                }
                _ => {
                    chars.next();
                }
            },
            Some('(') => {
                // A two-char glyph name, e.g. `\(aq`/`\(oq`/`\(cq` (quotes) or
                // `\(en`/`\(em` (dashes). Map the common ones to ASCII; drop
                // anything else rather than emit the raw glyph name.
                match (chars.next(), chars.next()) {
                    (Some('a' | 'o' | 'c'), Some('q')) => out.push('\''),
                    (Some('e'), Some('n' | 'm')) => out.push('-'),
                    _ => {}
                }
            }
            Some('-') => out.push('-'),
            Some('&') => {}
            Some(other) => out.push(other),
            None => {}
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
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
        let mut v = PROG.to_vec();
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
        assert_eq!(
            page.data, plain,
            "dict-decoded page must match the original"
        );
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
    fn whatis_parses_man_and_mdoc() {
        // man(7), unquoted header (poppler style); the continuation line after
        // the description must be dropped.
        let man = ".TH X 1\n.SH NAME\npdftotext \\- PDF to text converter\n(version 3.03)\n.SH SYNOPSIS\n";
        assert_eq!(
            whatis_from_roff(man).as_deref(),
            Some("PDF to text converter")
        );
        // DocBook output: quoted header.
        let docbook = ".TH IFNE 1\n.SH \"NAME\"\nifne \\- Run command if stdin is not empty\n.SH \"SYNOPSIS\"\n";
        assert_eq!(
            whatis_from_roff(docbook).as_deref(),
            Some("Run command if stdin is not empty")
        );
        // Several names share one description.
        let multi = ".SH NAME\ngrep, egrep, fgrep \\- print lines matching a pattern\n";
        assert_eq!(
            whatis_from_roff(multi).as_deref(),
            Some("print lines matching a pattern")
        );
        // mdoc(7): the description is its own `.Nd` macro.
        let mdoc = ".Sh NAME\n.Nm tmux\n.Nd terminal multiplexer\n.Sh DESCRIPTION\n";
        assert_eq!(
            whatis_from_roff(mdoc).as_deref(),
            Some("terminal multiplexer")
        );
        // Font escapes are stripped.
        let fonts = ".SH NAME\nfoo \\- a \\fBbold\\fR word\n";
        assert_eq!(whatis_from_roff(fonts).as_deref(), Some("a bold word"));
        // A hyphenated command name (roff `name\-part`) must not be mistaken for
        // the ` \- ` description separator.
        let hyphen = ".SH NAME\ncurl\\-config \\- Get information about libcurl\n";
        assert_eq!(
            whatis_from_roff(hyphen).as_deref(),
            Some("Get information about libcurl")
        );
        // Two-char glyph escapes map to ASCII (apostrophe), not raw `(aq`.
        let glyph = ".SH NAME\nfoo \\- don\\(aqt panic\n";
        assert_eq!(whatis_from_roff(glyph).as_deref(), Some("don't panic"));
        // No NAME section → nothing.
        assert_eq!(whatis_from_roff(".TH X 1\n.SH SYNOPSIS\nfoo\n"), None);
    }

    #[test]
    fn program_docs_lists_and_describes() {
        // A man body larger than the prefix scan proves we never inflate the
        // whole page — the NAME line sits above the filler and still resolves.
        let sponge = format!(
            ".TH SPONGE 1\n.SH NAME\nsponge \\- soak up standard input and write to a file\n.SH DESCRIPTION\n{}",
            "filler line filler line\n".repeat(2000)
        );
        let ifne =
            ".TH IFNE 1\n.SH \"NAME\"\nifne \\- run command if stdin is not empty\n.SH SYNOPSIS\n";
        let zip = build_zip(&[
            ("unpin/aliases", b"sponge\nifne\nlckdo\n", M::Stored),
            ("unpin/man/sponge.1", sponge.as_bytes(), M::Zstd),
            ("unpin/man/ifne.1", ifne.as_bytes(), M::Deflate),
            // `lckdo` ships no man page → listed, but with no description.
        ]);
        let docs = program_docs_from_bytes(&embed(&zip))
            .unwrap()
            .expect("docs");
        assert_eq!(
            docs.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
            vec!["ifne", "lckdo", "sponge"],
        );
        assert_eq!(
            docs[0].whatis.as_deref(),
            Some("run command if stdin is not empty")
        );
        assert_eq!(docs[1].whatis, None);
        assert_eq!(
            docs[2].whatis.as_deref(),
            Some("soak up standard input and write to a file")
        );
    }

    #[test]
    fn program_docs_follow_so_redirect() {
        // `unxz.1` is a `.so` redirect (stored as a unix symlink) to `xz.1`; the
        // alias `unxz` borrows xz's description.
        let xz = ".TH XZ 1\n.SH NAME\nxz \\- Compress or decompress .xz files\n.SH SYNOPSIS\n";
        let zip = build_zip(&[
            ("unpin/aliases", b"unxz\n", M::Stored),
            ("unpin/man/xz.1", xz.as_bytes(), M::Zstd),
            ("unpin/man/unxz.1", b"xz.1\n", M::Symlink),
        ]);
        let docs = program_docs_from_bytes(&embed(&zip))
            .unwrap()
            .expect("docs");
        let unxz = docs.iter().find(|d| d.name == "unxz").expect("unxz listed");
        assert_eq!(
            unxz.whatis.as_deref(),
            Some("Compress or decompress .xz files")
        );
    }

    #[test]
    fn program_docs_none_without_bundle() {
        let zip = build_zip(&[("usr/share/zoneinfo/UTC", b"TZif...", M::Stored)]);
        assert!(program_docs_from_bytes(&embed(&zip)).unwrap().is_none());
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
    fn own_binary_scan_is_clean() {
        // The reader's own .rodata constants (EOCD/CDH signatures) must not be
        // mistaken for an embedded ZIP when unpin scans its own file — the
        // cargo-built test binary carries no metadata overlay (that's appended
        // by the nix build), so the self-scan must come back empty, not error.
        let exe = std::env::current_exe().expect("current_exe");
        assert!(read(&exe).expect("read own binary").is_none());
    }

    use crate::sqfs::build_sqfs;

    /// `prog` + `img` + the 64-byte container footer.
    fn with_footer(prog: &[u8], img: &[u8], version: u32) -> Vec<u8> {
        let mut v = prog.to_vec();
        v.extend_from_slice(img);
        v.extend_from_slice(&(prog.len() as u64).to_le_bytes());
        v.extend_from_slice(&(img.len() as u64).to_le_bytes());
        let mut id = [0u8; 32];
        id[..20].copy_from_slice(&[0xab; 20]);
        v.extend_from_slice(&id);
        v.push(20);
        v.extend_from_slice(&[0, 0, 0]);
        v.extend_from_slice(&version.to_le_bytes());
        v.extend_from_slice(b"UNPINSQF");
        v
    }

    const PROG: &[u8] = b"\x7fELF fake program bytes \x00\x01\x02\x03";

    /// Bytes that compress poorly, so a multi-block file stays multi-block.
    fn noise(n: usize) -> Vec<u8> {
        let mut x: u32 = 0x1234_5678;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect()
    }

    #[test]
    fn sqfs_reads_aliases_man_and_symlinks() {
        let img = build_sqfs(
            &[
                ("unpin/aliases", b"xzcat\nunxz\n# note\n\nlzma\n"),
                ("unpin/man/xz.1", b".TH XZ 1\n.SH NAME\nxz \\- compress\n"),
                ("__unpins_xz__/share/data", &noise(300_000)),
            ],
            &[("unpin/man/unxz.1", "xz.1")],
            131072,
        );
        let meta = read_bytes(&with_footer(PROG, &img, 1)).unwrap().unwrap();
        assert_eq!(meta.aliases(), vec!["xzcat", "unxz", "lzma"]);
        let mut man: Vec<_> = meta
            .entries_under("unpin/man/")
            .map(|e| (e.path.as_str(), e.is_symlink, e.data.clone()))
            .collect();
        man.sort();
        assert_eq!(
            man,
            vec![
                ("unpin/man/unxz.1", true, b"xz.1".to_vec()),
                (
                    "unpin/man/xz.1",
                    false,
                    b".TH XZ 1\n.SH NAME\nxz \\- compress\n".to_vec()
                ),
            ]
        );
        // The runtime tree beside `unpin/` is not metadata.
        assert!(meta.entry("__unpins_xz__/share/data").is_none());
        assert_eq!(meta.entries.len(), 3);
    }

    #[test]
    fn sqfs_reads_multiblock_files_with_fragment_tails() {
        // 2.5 blocks of noise (two full blocks + a fragment tail), a file of
        // exactly one block, and small files packed together in fragments.
        let big = noise(2 * 65536 + 12345);
        let exact = noise(65536);
        let img = build_sqfs(
            &[
                ("unpin/man/big.1", &big),
                ("unpin/man/exact.1", &exact),
                ("unpin/man/a.1", b"aaa"),
                ("unpin/man/b.1", b"bbbb"),
                ("unpin/man/sub/deep.5", b"nested"),
            ],
            &[],
            65536,
        );
        let meta = read_bytes(&with_footer(PROG, &img, 1)).unwrap().unwrap();
        assert_eq!(meta.entry("unpin/man/big.1").unwrap().data, big);
        assert_eq!(meta.entry("unpin/man/exact.1").unwrap().data, exact);
        assert_eq!(meta.entry("unpin/man/a.1").unwrap().data, b"aaa");
        assert_eq!(meta.entry("unpin/man/b.1").unwrap().data, b"bbbb");
        assert_eq!(meta.entry("unpin/man/sub/deep.5").unwrap().data, b"nested");
    }

    #[test]
    fn sqfs_program_docs_follow_symlink_and_list_aliases() {
        let img = build_sqfs(
            &[
                ("unpin/aliases", b"xz\nunxz\nlzcat\n"),
                (
                    "unpin/man/xz.1",
                    b".TH XZ 1\n.SH NAME\nxz, unxz \\- Compress or decompress .xz files\n",
                ),
            ],
            &[("unpin/man/unxz.1", "xz.1")],
            131072,
        );
        let docs = program_docs_from_bytes(&with_footer(PROG, &img, 1))
            .unwrap()
            .unwrap();
        let want = Some("Compress or decompress .xz files".to_string());
        assert_eq!(
            docs,
            vec![
                ProgramDoc {
                    name: "lzcat".into(),
                    whatis: None
                },
                ProgramDoc {
                    name: "unxz".into(),
                    whatis: want.clone()
                },
                ProgramDoc {
                    name: "xz".into(),
                    whatis: want
                },
            ]
        );
    }

    #[test]
    fn sqfs_through_a_file_reads_only_what_it_needs() {
        let img = build_sqfs(
            &[
                ("unpin/aliases", b"foo\n"),
                (
                    "unpin/man/foo.1",
                    b".TH FOO 1\n.SH NAME\nfoo \\- does foo\n",
                ),
            ],
            &[],
            131072,
        );
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("foo");
        fs::write(&p, with_footer(PROG, &img, 1)).unwrap();
        assert_eq!(read(&p).unwrap().unwrap().aliases(), vec!["foo"]);
        let docs = read_program_docs(&p).unwrap().unwrap();
        assert_eq!(docs[0].whatis.as_deref(), Some("does foo"));
    }

    #[test]
    fn sqfs_without_unpin_dir_is_none() {
        let img = build_sqfs(&[("__unpins_x__/f", b"x")], &[], 131072);
        let bin = with_footer(PROG, &img, 1);
        assert!(read_bytes(&bin).unwrap().is_none());
        assert!(program_docs_from_bytes(&bin).unwrap().is_none());
    }

    #[test]
    fn sqfs_footer_is_authoritative_over_embedded_zips() {
        // A stray ZIP with `unpin/aliases` inside the program bytes is not read
        // once a footer says where the container is.
        let zip = build_zip(&[("unpin/aliases", b"evil\n", M::Stored)]);
        let img = build_sqfs(&[("unpin/aliases", b"good\n")], &[], 131072);
        let meta = read_bytes(&with_footer(&embed(&zip), &img, 1))
            .unwrap()
            .unwrap();
        assert_eq!(meta.aliases(), vec!["good"]);
    }

    #[test]
    fn sqfs_bad_footer_is_an_error_not_absence() {
        let img = build_sqfs(&[("unpin/aliases", b"a\n")], &[], 131072);
        let err = read_bytes(&with_footer(PROG, &img, 2)).unwrap_err();
        assert!(err.contains("version 2"), "got: {err}");
        // Bytes appended after the footer move it off EOF: no magic, no container.
        let mut tail = with_footer(PROG, &img, 1);
        tail.push(0);
        assert!(read_bytes(&tail).unwrap().is_none());
        // An offset that doesn't put the image right before the footer.
        let mut off = with_footer(PROG, &img, 1);
        let at = off.len() - 64;
        off[at] ^= 1;
        assert!(read_bytes(&off).unwrap_err().contains("does not end"));
    }

    #[test]
    fn sqfs_corruption_never_panics() {
        // Flip every byte of a small image in turn: each read must come back
        // Ok or Err, never panic or hang.
        let img = build_sqfs(
            &[
                ("unpin/aliases", b"a\nb\n"),
                ("unpin/man/a.1", b".TH A 1\n.SH NAME\na \\- x\n"),
            ],
            &[("unpin/man/b.1", "a.1")],
            4096,
        );
        let base = with_footer(PROG, &img, 1);
        for i in PROG.len()..PROG.len() + img.len() {
            let mut bin = base.clone();
            bin[i] ^= 0xff;
            let _ = read_bytes(&bin);
            let _ = program_docs_from_bytes(&bin);
        }
    }
}
