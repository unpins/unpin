//! Embed unpin's own man page into the binary as a `unpin/man/unpin.1` entry of
//! an embedded ZIP (the unified embedded-metadata container).
//!
//! Catalog packages get their `unpin/*` entries embedded by the nix-lib
//! `withMeta` pipeline (`zipfile` + objcopy), but unpin's man is self-authored
//! (`unpin.1`), so we build the same kind of ZIP here and let `include_bytes!`
//! plant it. The byte-scanning reader in `src/meta.rs` then finds it the same
//! way it finds any other binary's ZIP (docs/embedded-metadata.md §2).
//!
//! We emit a single **stored** (uncompressed) entry: unpin's one page is tiny
//! and storing it keeps the build dependency-free (no Python, no zip crate at
//! build time). The reader still handles `deflate` entries from catalog
//! binaries.

use std::env;
use std::fs;
use std::path::Path;

fn crc32(data: &[u8]) -> u32 {
    // IEEE poly 0xEDB88320, matching zlib.crc32 / the zip per-entry CRC.
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

const NAME: &str = "unpin/man/unpin.1";

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").unwrap();
    let man_path = Path::new(&manifest).join("unpin.1");
    println!("cargo:rerun-if-changed=unpin.1");
    println!("cargo:rerun-if-changed=build.rs");

    let roff = fs::read(&man_path).expect("read unpin.1");
    let crc = crc32(&roff);
    let name = NAME.as_bytes();
    let nlen = name.len() as u16;
    let dlen = roff.len() as u32;

    // DOS date 1980-01-01, time 0 — fixed for reproducibility.
    const DOS_DATE: u16 = 0x0021;
    const DOS_TIME: u16 = 0x0000;

    let mut zip = Vec::new();

    // --- Local file header (offset 0) ---
    zip.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]); // PK\x03\x04
    zip.extend_from_slice(&20u16.to_le_bytes()); // version needed
    zip.extend_from_slice(&0u16.to_le_bytes()); // flags
    zip.extend_from_slice(&0u16.to_le_bytes()); // method 0 = stored
    zip.extend_from_slice(&DOS_TIME.to_le_bytes());
    zip.extend_from_slice(&DOS_DATE.to_le_bytes());
    zip.extend_from_slice(&crc.to_le_bytes());
    zip.extend_from_slice(&dlen.to_le_bytes()); // compressed size
    zip.extend_from_slice(&dlen.to_le_bytes()); // uncompressed size
    zip.extend_from_slice(&nlen.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes()); // extra len
    zip.extend_from_slice(name);
    zip.extend_from_slice(&roff); // stored data

    let cd_offset = zip.len() as u32;

    // --- Central directory header ---
    zip.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]); // PK\x01\x02
    // version made by: high byte 3 = unix (so unix_mode is honored), low = 30.
    zip.extend_from_slice(&0x031eu16.to_le_bytes());
    zip.extend_from_slice(&20u16.to_le_bytes()); // version needed
    zip.extend_from_slice(&0u16.to_le_bytes()); // flags
    zip.extend_from_slice(&0u16.to_le_bytes()); // method 0 = stored
    zip.extend_from_slice(&DOS_TIME.to_le_bytes());
    zip.extend_from_slice(&DOS_DATE.to_le_bytes());
    zip.extend_from_slice(&crc.to_le_bytes());
    zip.extend_from_slice(&dlen.to_le_bytes()); // compressed size
    zip.extend_from_slice(&dlen.to_le_bytes()); // uncompressed size
    zip.extend_from_slice(&nlen.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes()); // extra len
    zip.extend_from_slice(&0u16.to_le_bytes()); // comment len
    zip.extend_from_slice(&0u16.to_le_bytes()); // disk number start
    zip.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
    // external attrs: regular file, mode 0644 in the high 16 bits.
    zip.extend_from_slice(&((0o100644u32) << 16).to_le_bytes());
    zip.extend_from_slice(&0u32.to_le_bytes()); // local header offset
    zip.extend_from_slice(name);

    let cd_size = zip.len() as u32 - cd_offset;

    // --- End of central directory ---
    zip.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]); // PK\x05\x06
    zip.extend_from_slice(&0u16.to_le_bytes()); // this disk
    zip.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
    zip.extend_from_slice(&1u16.to_le_bytes()); // entries this disk
    zip.extend_from_slice(&1u16.to_le_bytes()); // total entries
    zip.extend_from_slice(&cd_size.to_le_bytes());
    zip.extend_from_slice(&cd_offset.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes()); // comment len (no marker)

    let out_dir = env::var("OUT_DIR").unwrap();
    fs::write(Path::new(&out_dir).join("unpin_meta.zip"), &zip).expect("write unpin_meta.zip");
}
