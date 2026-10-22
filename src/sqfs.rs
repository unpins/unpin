//! Linux metadata container — a squashfs v4 (zstd) image appended to the
//! binary, located by a fixed 64-byte footer at EOF:
//!
//! ```text
//! [program][squashfs image][footer]
//! footer (little-endian):  0 u64 image offset   8 u64 image size
//!                         16 [u8; 32] build-id  48 u8 build-id length
//!                         49 [u8; 3] zero      52 u32 version (1)
//!                         56 b"UNPINSQF"
//! ```
//!
//! The image ends where the footer begins. Only what `unpin` needs is read —
//! the superblock, the directory/inode metadata on the path to `unpin/`, and
//! the data blocks of the files under it — never the runtime tree beside it, so
//! a 70 MB image costs a few metadata blocks, not a whole-file read.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};

const FOOTER_LEN: u64 = 64;
const FOOTER_MAGIC: &[u8; 8] = b"UNPINSQF";
const FOOTER_VERSION: u32 = 1;

const SQFS_MAGIC: u32 = 0x7371_7368; // "hsqs"
const SUPER_LEN: usize = 96;
const COMP_ZSTD: u16 = 6;
const META_MAX: usize = 8192;
const NO_FRAGMENT: u32 = 0xffff_ffff;
/// Directory entries per header and nesting are bounded by squashfs itself
/// (256) and by our layout; these caps only stop a crafted image from looping.
const MAX_DIR_ENTRIES: usize = 65536;
const MAX_DEPTH: usize = 32;
/// Every block an [`Image`] decodes — metadata, fragments, data, sparse —
/// counts against this, so a few KB of zstd can't expand into gigabytes.
const MAX_DECODED: u64 = 256 << 20;

/// The parsed footer. The build-id is validated but not kept: it is for the
/// runtime layer in libc, not for `unpin`.
#[derive(Debug, PartialEq, Eq)]
pub struct Footer {
    pub offset: u64,
    pub size: u64,
}

/// Read the footer at the end of a `len`-byte file. `Ok(None)` = no footer
/// magic (not this format); `Err` = the magic is there but the footer is not
/// one we can trust — a damaged container must fail loudly, not read as absent.
pub fn footer<R: Read + Seek>(r: &mut R, len: u64) -> Result<Option<Footer>, String> {
    if len < FOOTER_LEN {
        return Ok(None);
    }
    let mut b = [0u8; FOOTER_LEN as usize];
    r.seek(SeekFrom::Start(len - FOOTER_LEN))
        .and_then(|_| r.read_exact(&mut b))
        .map_err(|e| format!("read footer: {e}"))?;
    if &b[56..64] != FOOTER_MAGIC {
        return Ok(None);
    }
    let version = u32_at(&b, 52);
    if version != FOOTER_VERSION {
        return Err(format!(
            "container footer version {version} (this unpin reads {FOOTER_VERSION})"
        ));
    }
    let id_len = b[48] as usize;
    if id_len > 32 || b[49..52] != [0, 0, 0] {
        return Err("container footer: malformed".into());
    }
    let offset = u64_at(&b, 0);
    let size = u64_at(&b, 8);
    if offset.checked_add(size) != Some(len - FOOTER_LEN) {
        return Err("container footer: image does not end at the footer".into());
    }
    Ok(Some(Footer { offset, size }))
}

/// A node reached through a directory listing.
#[derive(Debug, Clone)]
pub enum Node {
    Dir { block: u32, offset: u16, size: u32 },
    File(FileNode),
    Symlink(Vec<u8>),
    Other,
}

#[derive(Debug, Clone)]
pub struct FileNode {
    pub size: u64,
    blocks_start: u64,
    fragment: u32,
    frag_offset: u32,
    /// Where the block-size list starts in the inode table; read lazily so a
    /// crafted `size` can't drive an allocation before the caller's cap check.
    list: (u64, usize),
}

pub struct Image<R> {
    r: R,
    base: u64,
    bytes_used: u64,
    block_size: u32,
    frag_count: u32,
    root: u64,
    inode_table: u64,
    dir_table: u64,
    frag_table: u64,
    /// Decoded metadata blocks by image offset → (data, offset of the next block).
    meta: HashMap<u64, (Vec<u8>, u64)>,
    frags: HashMap<u32, Vec<u8>>,
    /// Bytes left to decode, from [`MAX_DECODED`].
    budget: u64,
}

impl<R: Read + Seek> Image<R> {
    /// Open the image occupying `size` bytes at `base` in `r`.
    pub fn open(mut r: R, base: u64, size: u64) -> Result<Self, String> {
        let mut sb = [0u8; SUPER_LEN];
        if size < SUPER_LEN as u64 {
            return Err("squashfs: image smaller than its superblock".into());
        }
        r.seek(SeekFrom::Start(base))
            .and_then(|_| r.read_exact(&mut sb))
            .map_err(|e| format!("squashfs: read superblock: {e}"))?;
        if u32_at(&sb, 0) != SQFS_MAGIC {
            return Err("squashfs: bad magic".into());
        }
        let (major, minor) = (u16_at(&sb, 28), u16_at(&sb, 30));
        if (major, minor) != (4, 0) {
            return Err(format!("squashfs: version {major}.{minor} (need 4.0)"));
        }
        let comp = u16_at(&sb, 20);
        if comp != COMP_ZSTD {
            return Err(format!("squashfs: compressor {comp} (need zstd)"));
        }
        let block_size = u32_at(&sb, 12);
        let block_log = u16_at(&sb, 22);
        if !(12..=20).contains(&block_log) || block_size != 1 << block_log {
            return Err(format!("squashfs: bad block size {block_size}"));
        }
        let bytes_used = u64_at(&sb, 40);
        if bytes_used > size {
            return Err("squashfs: image truncated".into());
        }
        let img = Image {
            r,
            base,
            bytes_used,
            block_size,
            frag_count: u32_at(&sb, 16),
            root: u64_at(&sb, 32),
            inode_table: u64_at(&sb, 64),
            dir_table: u64_at(&sb, 72),
            frag_table: u64_at(&sb, 80),
            meta: HashMap::new(),
            frags: HashMap::new(),
            budget: MAX_DECODED,
        };
        if img.inode_table >= bytes_used || img.dir_table >= bytes_used {
            return Err("squashfs: table offsets out of range".into());
        }
        Ok(img)
    }

    /// The root directory.
    fn root(&mut self) -> Result<Node, String> {
        self.inode(self.root)
    }

    /// Resolve `path` (components separated by `/`, no leading slash) from the
    /// root. `Ok(None)` = some component is missing.
    pub fn lookup(&mut self, path: &str) -> Result<Option<Node>, String> {
        let mut node = self.root()?;
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            let Some((_, child)) = self.read_dir(&node)?.into_iter().find(|(n, _)| n == comp)
            else {
                return Ok(None);
            };
            node = self.inode(child)?;
        }
        Ok(Some(node))
    }

    /// List a directory: `(name, inode ref)` pairs in on-disk (sorted) order.
    pub fn read_dir(&mut self, dir: &Node) -> Result<Vec<(String, u64)>, String> {
        let &Node::Dir {
            block,
            offset,
            size,
        } = dir
        else {
            return Err("squashfs: not a directory".into());
        };
        // The stored size counts 3 bytes for the implicit `.`/`..`.
        let mut left = (size as usize).saturating_sub(3);
        let mut cur = (self.dir_table + block as u64, offset as usize);
        let mut out = Vec::new();
        while left > 0 {
            let h = self.read_meta(&mut cur, 12)?;
            let count = u32_at(&h, 0) as usize + 1;
            let start = u32_at(&h, 4) as u64;
            left = left.checked_sub(12).ok_or("squashfs: directory overrun")?;
            if count > 256 || out.len() + count > MAX_DIR_ENTRIES {
                return Err("squashfs: oversized directory".into());
            }
            for _ in 0..count {
                let e = self.read_meta(&mut cur, 8)?;
                let nlen = u16_at(&e, 6) as usize + 1;
                let name = self.read_meta(&mut cur, nlen)?;
                left = left
                    .checked_sub(8 + nlen)
                    .ok_or("squashfs: directory overrun")?;
                let name = String::from_utf8(name).map_err(|_| "squashfs: non-UTF-8 name")?;
                if name == "." || name == ".." || name.contains('/') {
                    return Err(format!("squashfs: invalid entry name {name:?}"));
                }
                out.push((name, (start << 16) | u16_at(&e, 0) as u64));
            }
        }
        Ok(out)
    }

    /// Decode the inode at `iref` (`block << 16 | offset`, relative to the inode table).
    pub fn inode(&mut self, iref: u64) -> Result<Node, String> {
        let mut cur = (self.inode_table + (iref >> 16), (iref & 0xffff) as usize);
        let h = self.read_meta(&mut cur, 16)?;
        Ok(match u16_at(&h, 0) {
            1 => {
                let d = self.read_meta(&mut cur, 16)?;
                Node::Dir {
                    block: u32_at(&d, 0),
                    size: u16_at(&d, 8) as u32,
                    offset: u16_at(&d, 10),
                }
            }
            8 => {
                let d = self.read_meta(&mut cur, 24)?;
                Node::Dir {
                    size: u32_at(&d, 4),
                    block: u32_at(&d, 8),
                    offset: u16_at(&d, 18),
                }
            }
            2 => {
                let d = self.read_meta(&mut cur, 16)?;
                Node::File(FileNode {
                    blocks_start: u32_at(&d, 0) as u64,
                    size: u32_at(&d, 12) as u64,
                    fragment: u32_at(&d, 4),
                    frag_offset: u32_at(&d, 8),
                    list: cur,
                })
            }
            9 => {
                let d = self.read_meta(&mut cur, 40)?;
                Node::File(FileNode {
                    blocks_start: u64_at(&d, 0),
                    size: u64_at(&d, 8),
                    fragment: u32_at(&d, 28),
                    frag_offset: u32_at(&d, 32),
                    list: cur,
                })
            }
            3 | 10 => {
                let d = self.read_meta(&mut cur, 8)?;
                let n = u32_at(&d, 4) as usize;
                if n > 4096 {
                    return Err("squashfs: symlink target too long".into());
                }
                Node::Symlink(self.read_meta(&mut cur, n)?)
            }
            _ => Node::Other,
        })
    }

    /// Read at most `limit` bytes from the start of `f`. Reading the whole file
    /// (`limit >= f.size`) also checks it decoded to exactly its declared size.
    pub fn read_file(&mut self, f: &FileNode, limit: u64) -> Result<Vec<u8>, String> {
        let bs = self.block_size as u64;
        let has_frag = f.fragment != NO_FRAGMENT;
        let full = if has_frag {
            f.size / bs
        } else {
            f.size.div_ceil(bs)
        };
        let want = limit.min(f.size);
        let mut out = Vec::new();
        let mut cur = f.list;
        let mut pos = f.blocks_start;
        for i in 0..full {
            if out.len() as u64 >= want {
                break;
            }
            let w = u32_at(&self.read_meta(&mut cur, 4)?, 0);
            let expect = bs.min(f.size - i * bs) as usize;
            let len = (w & 0x00ff_ffff) as u64;
            if len == 0 {
                self.charge(expect)?;
                out.resize(out.len() + expect, 0); // sparse block
            } else {
                let raw = self.read_raw(pos, len)?;
                let block = self.decode(raw, w & 0x0100_0000 == 0, expect)?;
                if block.len() != expect {
                    return Err("squashfs: short data block".into());
                }
                out.extend_from_slice(&block);
            }
            pos += len;
        }
        if has_frag && (out.len() as u64) < want {
            let tail = (f.size - full * bs) as usize;
            let s = f.frag_offset as usize;
            let block = self.fragment(f.fragment)?;
            let piece = block
                .get(s..s.checked_add(tail).ok_or("squashfs: bad fragment")?)
                .ok_or("squashfs: fragment out of range")?;
            out.extend_from_slice(piece);
        }
        if limit >= f.size && out.len() as u64 != f.size {
            return Err("squashfs: file size mismatch".into());
        }
        out.truncate(want as usize);
        Ok(out)
    }

    /// Fragment block `idx`, decoded once and cached.
    fn fragment(&mut self, idx: u32) -> Result<&[u8], String> {
        if !self.frags.contains_key(&idx) {
            if idx >= self.frag_count {
                return Err("squashfs: fragment index out of range".into());
            }
            // An array of u64 pointers to metadata blocks of 512 16-byte entries.
            let ptr = u64_at(
                &self.read_raw(self.frag_table + 8 * (idx as u64 / 512), 8)?,
                0,
            );
            let mut cur = (ptr, (idx as usize % 512) * 16);
            let e = self.read_meta(&mut cur, 16)?;
            let (start, w) = (u64_at(&e, 0), u32_at(&e, 8));
            let raw = self.read_raw(start, (w & 0x00ff_ffff) as u64)?;
            let block = self.decode(raw, w & 0x0100_0000 == 0, self.block_size as usize)?;
            self.frags.insert(idx, block);
        }
        Ok(&self.frags[&idx])
    }

    /// A block from its raw bytes, decompressed if `compressed`, charged
    /// against [`MAX_DECODED`].
    fn decode(&mut self, raw: Vec<u8>, compressed: bool, cap: usize) -> Result<Vec<u8>, String> {
        let block = if compressed { unzstd(&raw, cap)? } else { raw };
        self.charge(block.len())?;
        Ok(block)
    }

    fn charge(&mut self, n: usize) -> Result<(), String> {
        self.budget = self
            .budget
            .checked_sub(n as u64)
            .ok_or("squashfs: decodes past its size cap")?;
        Ok(())
    }

    /// `n` bytes of the metadata stream at `cur` (block offset, offset inside
    /// the decoded block), crossing block boundaries; advances `cur`.
    fn read_meta(&mut self, cur: &mut (u64, usize), n: usize) -> Result<Vec<u8>, String> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            let (data, next) = self.meta_block(cur.0)?;
            if cur.1 >= data.len() {
                if cur.1 > data.len() {
                    return Err("squashfs: metadata offset out of range".into());
                }
                *cur = (next, 0);
                continue;
            }
            let take = (n - out.len()).min(data.len() - cur.1);
            out.extend_from_slice(&data[cur.1..cur.1 + take]);
            cur.1 += take;
        }
        Ok(out)
    }

    fn meta_block(&mut self, at: u64) -> Result<(&[u8], u64), String> {
        if !self.meta.contains_key(&at) {
            let h = u16_at(&self.read_raw(at, 2)?, 0);
            let len = (h & 0x7fff) as u64;
            if len == 0 || len as usize > META_MAX {
                return Err("squashfs: bad metadata block".into());
            }
            let raw = self.read_raw(at + 2, len)?;
            let data = self.decode(raw, h & 0x8000 == 0, META_MAX)?;
            if data.is_empty() {
                return Err("squashfs: empty metadata block".into());
            }
            self.meta.insert(at, (data, at + 2 + len));
        }
        let (d, next) = &self.meta[&at];
        Ok((d, *next))
    }

    /// `len` raw bytes at image offset `at`, bounded by the image.
    fn read_raw(&mut self, at: u64, len: u64) -> Result<Vec<u8>, String> {
        if at.checked_add(len).is_none_or(|end| end > self.bytes_used) {
            return Err("squashfs: read past the end of the image".into());
        }
        let mut buf = vec![0u8; len as usize];
        self.r
            .seek(SeekFrom::Start(self.base + at))
            .and_then(|_| self.r.read_exact(&mut buf))
            .map_err(|e| format!("squashfs: read: {e}"))?;
        Ok(buf)
    }
}

/// Decode one zstd frame (a squashfs block), refusing output beyond `cap`.
fn unzstd(src: &[u8], cap: usize) -> Result<Vec<u8>, String> {
    let z = ruzstd::StreamingDecoder::new(src).map_err(|e| format!("squashfs: zstd: {e}"))?;
    let mut out = Vec::new();
    z.take(cap as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| format!("squashfs: zstd: {e}"))?;
    if out.len() > cap {
        return Err("squashfs: block decodes past its size".into());
    }
    Ok(out)
}

/// Every node under `dir`, depth-first, as `(path relative to dir, node)`.
/// Directories themselves are not listed, but count against `max_entries`.
/// A directory listed twice (a loop, or two names for one listing) is refused:
/// a tree we build never has one, and following it would be exponential.
pub fn walk<R: Read + Seek>(
    img: &mut Image<R>,
    dir: &Node,
    max_entries: usize,
) -> Result<Vec<(String, Node)>, String> {
    struct Walk {
        seen: HashSet<(u32, u16)>,
        count: usize,
        max: usize,
        out: Vec<(String, Node)>,
    }
    fn go<R: Read + Seek>(
        img: &mut Image<R>,
        w: &mut Walk,
        dir: &Node,
        prefix: &str,
        depth: usize,
    ) -> Result<(), String> {
        if depth > MAX_DEPTH {
            return Err("squashfs: directory nesting too deep".into());
        }
        if let &Node::Dir { block, offset, .. } = dir
            && !w.seen.insert((block, offset))
        {
            return Err("squashfs: directory listed twice".into());
        }
        for (name, iref) in img.read_dir(dir)? {
            w.count += 1;
            if w.count > w.max {
                return Err(format!("squashfs: more than {} entries", w.max));
            }
            let path = format!("{prefix}{name}");
            match img.inode(iref)? {
                d @ Node::Dir { .. } => go(img, w, &d, &format!("{path}/"), depth + 1)?,
                n => w.out.push((path, n)),
            }
        }
        Ok(())
    }
    let mut w = Walk {
        seen: HashSet::new(),
        count: 0,
        max: max_entries,
        out: Vec::new(),
    };
    go(img, &mut w, dir, "", 0)?;
    Ok(w.out)
}

fn u16_at(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}

fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
}

/// A squashfs v4 (zstd) image of `files` and `links` (`(path, target)`),
/// written by `backhand` — an implementation independent of this reader.
#[cfg(test)]
pub(crate) fn build_sqfs(
    files: &[(&str, &[u8])],
    links: &[(&str, &str)],
    block_size: u32,
) -> Vec<u8> {
    use backhand::compression::Compressor;
    use backhand::{FilesystemCompressor, FilesystemWriter, NodeHeader};
    let h = NodeHeader::new(0o644, 0, 0, 1);
    let mut fs = FilesystemWriter::default();
    fs.set_compressor(FilesystemCompressor::new(Compressor::Zstd, None).unwrap());
    fs.set_block_size(block_size);
    fs.set_no_padding();
    for (path, data) in files {
        if let Some((dir, _)) = path.rsplit_once('/') {
            fs.push_dir_all(dir, NodeHeader::new(0o755, 0, 0, 1))
                .unwrap();
        }
        fs.push_file(std::io::Cursor::new(data.to_vec()), path, h)
            .unwrap();
    }
    for (path, target) in links {
        fs.push_symlink(*target, path, h).unwrap();
    }
    let mut out = std::io::Cursor::new(Vec::new());
    fs.write(&mut out).unwrap();
    out.into_inner()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A hand-built image whose `unpin/` lists `a` and `b`, both pointing back
    /// at `unpin/` itself — a shape no writer emits, so it is laid out by hand
    /// with uncompressed metadata blocks.
    fn looping_image() -> Vec<u8> {
        fn dir_inode(listing_off: u16, size: u16) -> Vec<u8> {
            let mut v = vec![0u8; 16];
            v[0] = 1; // basic directory
            v.extend_from_slice(&0u32.to_le_bytes()); // listing block
            v.extend_from_slice(&2u32.to_le_bytes()); // nlink
            v.extend_from_slice(&size.to_le_bytes());
            v.extend_from_slice(&listing_off.to_le_bytes());
            v.extend_from_slice(&0u32.to_le_bytes()); // parent
            v
        }
        fn listing(entries: &[(&str, u16)]) -> Vec<u8> {
            let mut v = Vec::new();
            v.extend_from_slice(&(entries.len() as u32 - 1).to_le_bytes());
            v.extend_from_slice(&0u32.to_le_bytes()); // inode block
            v.extend_from_slice(&0u32.to_le_bytes());
            for (name, ioff) in entries {
                v.extend_from_slice(&ioff.to_le_bytes());
                v.extend_from_slice(&0u16.to_le_bytes());
                v.extend_from_slice(&1u16.to_le_bytes());
                v.extend_from_slice(&(name.len() as u16 - 1).to_le_bytes());
                v.extend_from_slice(name.as_bytes());
            }
            v
        }
        let root_list = listing(&[("unpin", 32)]);
        let loop_list = listing(&[("a", 32), ("b", 32)]);
        let mut inodes = dir_inode(0, root_list.len() as u16 + 3);
        inodes.extend(dir_inode(
            root_list.len() as u16,
            loop_list.len() as u16 + 3,
        ));
        let dirs = [root_list, loop_list].concat();
        let meta = |b: &[u8]| [&(0x8000 | b.len() as u16).to_le_bytes()[..], b].concat();
        let (inodes, dirs) = (meta(&inodes), meta(&dirs));
        let inode_table = SUPER_LEN as u64;
        let dir_table = inode_table + inodes.len() as u64;
        let used = dir_table + dirs.len() as u64;
        let mut sb = vec![0u8; SUPER_LEN];
        sb[0..4].copy_from_slice(&SQFS_MAGIC.to_le_bytes());
        sb[12..16].copy_from_slice(&4096u32.to_le_bytes());
        sb[20..22].copy_from_slice(&COMP_ZSTD.to_le_bytes());
        sb[22..24].copy_from_slice(&12u16.to_le_bytes());
        sb[28..30].copy_from_slice(&4u16.to_le_bytes());
        sb[40..48].copy_from_slice(&used.to_le_bytes());
        sb[64..72].copy_from_slice(&inode_table.to_le_bytes());
        sb[72..80].copy_from_slice(&dir_table.to_le_bytes());
        sb[80..88].copy_from_slice(&used.to_le_bytes());
        [sb, inodes, dirs].concat()
    }

    #[test]
    fn walk_refuses_a_directory_loop() {
        let img = looping_image();
        let mut img = Image::open(Cursor::new(&img), 0, img.len() as u64).unwrap();
        let dir = img.lookup("unpin").unwrap().unwrap();
        // Both children resolve to `unpin/` again; without the guard only the
        // entry cap would stop it, after re-listing the loop thousands of times.
        assert!(matches!(
            img.lookup("unpin/a/b/a").unwrap(),
            Some(Node::Dir { .. })
        ));
        let err = walk(&mut img, &dir, 8192).unwrap_err();
        assert!(err.contains("listed twice"), "got: {err}");
    }

    #[test]
    fn decoding_is_capped_and_fragments_are_charged_once() {
        // 40 small files share one fragment block: every read after the first
        // comes from the cache and must not be charged again.
        let small: Vec<(String, Vec<u8>)> = (0..40)
            .map(|i| (format!("f{i:02}"), vec![b'x'; 1000]))
            .collect();
        let mut files: Vec<(&str, &[u8])> = small
            .iter()
            .map(|(n, d)| (n.as_str(), d.as_slice()))
            .collect();
        let zeros = vec![0u8; 1 << 20];
        files.push(("big", &zeros));
        let raw = build_sqfs(&files, &[], 1 << 17);
        let mut img = Image::open(Cursor::new(&raw), 0, raw.len() as u64).unwrap();
        img.budget = 128 << 10;
        let root = img.root().unwrap();
        let mut list = img.read_dir(&root).unwrap();
        list.sort_by_key(|(n, _)| n == "big"); // the cap trips last
        for (name, iref) in list {
            let Node::File(f) = img.inode(iref).unwrap() else {
                panic!("{name}: not a file")
            };
            let r = img.read_file(&f, f.size);
            if name == "big" {
                // 1 MiB of zeros costs next to nothing on disk, and is still refused.
                let err = r.map(|v| v.len()).unwrap_err();
                assert!(err.contains("decodes past"), "got: {err}");
            } else {
                assert_eq!(r.unwrap(), vec![b'x'; 1000], "{name}");
            }
        }
    }
}
