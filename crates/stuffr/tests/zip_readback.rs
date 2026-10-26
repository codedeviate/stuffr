//! The fuzz target's zip read-back (`fuzz/fuzz_targets/zip_readback.rs`,
//! included here by path) held to what it claims: stored and deflated
//! entries are read by the walk AND by the `zip` crate, an archive the crate
//! cannot be asked about says why, and damage is refused.

#[path = "../../../fuzz/fuzz_targets/zip_readback.rs"]
mod zip_readback;

use zip_readback::verify_zip;

fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
    }
    !c
}

/// An entry: name, plain bytes, and its method (0 stored, 8 deflated with
/// zip's own encoder at level 9, the one `zip -9` uses).
fn archive(entries: &[(&str, &[u8], u16)], comment: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, plain, method) in entries {
        let data = if *method == 8 {
            let mut d = stuffr::infozip::ZipDeflater::new(9);
            d.set_store_fallback(false);
            let mut v = Vec::new();
            d.compress(&mut &plain[..], &mut v).unwrap();
            v
        } else {
            plain.to_vec()
        };
        let at = out.len() as u32;
        let crc = crc32(plain);
        let sizes = |v: &mut Vec<u8>| {
            v.extend_from_slice(&method.to_le_bytes());
            v.extend_from_slice(&[0, 0, 0x21, 0x50]); // time, date
            v.extend_from_slice(&crc.to_le_bytes());
            v.extend_from_slice(&(data.len() as u32).to_le_bytes());
            v.extend_from_slice(&(plain.len() as u32).to_le_bytes());
            v.extend_from_slice(&(name.len() as u16).to_le_bytes());
        };
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&[20, 0, 0, 0]); // version, flags
        sizes(&mut out);
        out.extend_from_slice(&[0, 0]); // extra length
        out.extend_from_slice(name.as_bytes());
        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&[20, 3, 20, 0, 0, 0]); // made by, needed, flags
        sizes(&mut central);
        central.extend_from_slice(&[0; 2 + 2 + 2 + 2 + 4]); // extra, comment, disk, internal, external
        central.extend_from_slice(&at.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&data);
    }
    let (cd_at, cd_len, n) = (out.len() as u32, central.len() as u32, entries.len() as u16);
    out.extend(central);
    out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&cd_len.to_le_bytes());
    out.extend_from_slice(&cd_at.to_le_bytes());
    out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    out.extend_from_slice(comment);
    out
}

fn text(n: usize) -> Vec<u8> {
    (0..n).map(|i| b"seed line of text\n"[i % 18]).collect()
}

#[test]
fn the_zip_crate_reads_stored_and_deflated_entries_too() {
    let (a, b, c) = (text(3000), text(500), text(40));
    let z = archive(&[("a.txt", &a, 8), ("b.txt", &b, 8), ("c.txt", &c, 0)], b"");
    let v = verify_zip(&z).unwrap();
    assert_eq!((v.entries, v.unchecked), (3, 0));
    // the crate decoded both deflated entries, byte for byte, and the stored
    assert_eq!((v.crate_read, v.crate_deflated), (3, 2), "{v:?}");
    assert_eq!(v.crate_skipped, None);
}

#[test]
fn a_repeated_name_is_whole_but_not_put_to_the_zip_crate() {
    let a = text(900);
    let z = archive(&[("a.txt", &a, 8), ("a.txt", &a, 8)], b"");
    let v = verify_zip(&z).unwrap();
    assert_eq!(v.entries, 2);
    assert_eq!(v.crate_read, 0);
    assert_eq!(v.crate_skipped, Some("two central records share a name"));
}

#[test]
fn a_comment_holding_an_end_record_is_found_by_its_length() {
    let a = text(900);
    let mut comment = b"PK\x05\x06".to_vec();
    comment.extend_from_slice(&[0xff; 18]);
    let z = archive(&[("a.txt", &a, 8)], &comment);
    let v = verify_zip(&z).unwrap();
    assert_eq!(v.entries, 1);
    assert!(v.crate_skipped.is_some(), "{v:?}");
}

#[test]
fn damage_is_refused() {
    let a = text(3000);
    let z = archive(&[("a.txt", &a, 8)], b"");
    let mut bad = z.clone();
    bad[40] ^= 0x55; // inside the deflated data
    assert!(verify_zip(&bad).is_err());
    let mut crc = z.clone();
    crc[14] ^= 1; // the local CRC is not what is checked; the central one is
    let at = crc.windows(4).rposition(|w| w == b"PK\x01\x02").unwrap();
    crc[at + 16] ^= 1;
    assert!(verify_zip(&crc).unwrap_err().contains("CRC"));
}
