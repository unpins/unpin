//! Embed unpin's own man page into the binary as a `.unpin_man` container.
//!
//! Catalog packages get their man pages embedded by the nix-lib `withMan`
//! pipeline (`mkman.py` + `llvm-objcopy`), but unpin's man is self-authored
//! (`unpin.1`), so we build the same on-disk container here and let
//! `include_bytes!` plant it in the binary. The byte-scanning reader in
//! `src/man.rs` then finds it the same way it finds any other binary's blob.
//!
//! Format mirrors `nix-lib/mkman.py` (docs/embedded-man.md §1-2). We emit the
//! uncompressed variant (`compression = 0`): unpin's single page is tiny, and
//! skipping zstd keeps the build dependency-free (the reader still handles the
//! zstd variant for catalog binaries).

use std::env;
use std::fs;
use std::path::Path;

// Sentinels — exact bytes from docs/embedded-man.md §1.3, matched by src/man.rs.
const BEGIN: &[u8] = b"\xff\xffUNPIN_MAN_v1_b2c9d1\xff\xff";
const END: &[u8] = b"\xff\xffUNPIN_MAN_ENDb2c9d1\xff\xff";

fn crc32(data: &[u8]) -> u32 {
    // IEEE poly 0xEDB88320, matching mkman.py / zlib.crc32.
    let mut table = [0u32; 256];
    let mut n = 0;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[n] = c;
        n += 1;
    }
    let mut c = 0xffff_ffffu32;
    for &b in data {
        c = table[((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
    }
    c ^ 0xffff_ffff
}

/// Length-prefixed UTF-8 string: u16 LE length + bytes.
fn push_str(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    out.extend_from_slice(&(b.len() as u16).to_le_bytes());
    out.extend_from_slice(b);
}

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").unwrap();
    let man_path = Path::new(&manifest).join("unpin.1");
    println!("cargo:rerun-if-changed=unpin.1");
    println!("cargo:rerun-if-changed=build.rs");

    let roff = fs::read(&man_path).expect("read unpin.1");

    // --- Inner archive (UPMAN), one roff entry: name=unpin section=1 lang=en ---
    let mut index = Vec::new();
    push_str(&mut index, "unpin"); // name
    index.push(1u8); // section
    push_str(&mut index, "en"); // lang
    index.push(1u8); // kind = 1 (roff)
    index.extend_from_slice(&0u32.to_le_bytes()); // blob_off
    index.extend_from_slice(&(roff.len() as u32).to_le_bytes()); // blob_len

    let mut inner = Vec::new();
    inner.extend_from_slice(b"UPMAN"); // magic (5)
    inner.push(1u8); // archive version
    inner.push(0u8); // reserved
    inner.extend_from_slice(&1u16.to_le_bytes()); // entry_count
    inner.extend_from_slice(&(index.len() as u32).to_le_bytes()); // index_len
    inner.extend_from_slice(&index);
    inner.extend_from_slice(&roff); // blob region

    // --- Outer container ---
    let crc = crc32(&inner);
    let mut blob = Vec::new();
    blob.extend_from_slice(BEGIN);
    blob.push(1u8); // container_version
    blob.push(0u8); // compression = 0 (none)
    blob.extend_from_slice(&(inner.len() as u32).to_le_bytes()); // payload_len
    blob.extend_from_slice(&inner); // payload
    blob.extend_from_slice(&crc.to_le_bytes()); // payload_crc32
    blob.extend_from_slice(END);

    let out_dir = env::var("OUT_DIR").unwrap();
    fs::write(Path::new(&out_dir).join("unpin_man.blob"), &blob).expect("write unpin_man.blob");
}
