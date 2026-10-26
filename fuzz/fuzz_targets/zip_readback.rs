//! The zip family's read-back, shared by the `compat` fuzz target and the
//! test that pins it (`crates/stuffr/tests/zip_readback.rs` includes this
//! file by path): an independent walk of an archive's records, held to the
//! `zip` crate as a second reader.

#![allow(dead_code)]

/// The most any entry of an archive checked here may inflate to.
const OUTPUT_CAP: u64 = 8 * 1024 * 1024;

/// What [`verify_zip`] found in an archive that read back.
#[derive(Debug)]
pub struct Verified {
    /// Entries the end record counts.
    pub entries: usize,
    /// Entries whose data the walk could not check (encrypted, or a method
    /// it does not decode): structure only.
    pub unchecked: usize,
    /// Entries the `zip` crate read, byte for byte as the walk did.
    pub crate_read: usize,
    /// Of those, the deflated ones.
    pub crate_deflated: usize,
    /// Why the `zip` crate was not asked, when it was not.
    pub crate_skipped: Option<&'static str>,
}

/// An archive's own view of itself, read independently of stuffr's reader:
/// the end record (and a Zip64 one behind it), every central record, its
/// local header (the names must agree), and the data of every stored or
/// deflated entry that is not encrypted: stored as it is, deflated through
/// `infozip::inflate`, either way to the central record's size and CRC-32.
/// The `zip` crate counts the entries a second time. `Err` says what failed.
pub fn verify_zip(bytes: &[u8]) -> Result<Verified, String> {
    use std::io::Cursor;
    let le16 = |at: usize| -> Option<u64> {
        bytes
            .get(at..at + 2)
            .map(|b| u64::from(u16::from_le_bytes([b[0], b[1]])))
    };
    let le32 = |at: usize| -> Option<u64> {
        bytes
            .get(at..at + 4)
            .map(|b| u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
    };
    let le64 = |at: usize| -> Option<u64> {
        bytes
            .get(at..at + 8)
            .map(|b| u64::from_le_bytes(b.try_into().expect("eight bytes")))
    };
    // The end record is the last `PK\5\6` whose comment length reaches
    // exactly the end of the file, as a reader looks for it: a comment may
    // hold those four bytes itself.
    let eocd = (0..bytes.len().saturating_sub(21))
        .rev()
        .find(|&p| {
            bytes[p..].starts_with(b"PK\x05\x06")
                && le16(p + 20).is_some_and(|c| p as u64 + 22 + c == bytes.len() as u64)
        })
        .ok_or("no end record that ends the file")?;
    let (mut entries, mut cd_size, mut cd_off) = (
        le16(eocd + 10).ok_or("cut")?,
        le32(eocd + 12).ok_or("cut")?,
        le32(eocd + 16).ok_or("cut")?,
    );
    if entries == 0xffff || cd_size == 0xffff_ffff || cd_off == 0xffff_ffff {
        let loc = eocd.checked_sub(20).ok_or("no Zip64 locator")?;
        if le32(loc) != Some(0x0706_4b50) {
            return Err("Zip64 values without a locator".into());
        }
        let z64 = le64(loc + 8).ok_or("cut")? as usize;
        if le32(z64) != Some(0x0606_4b50) {
            return Err(format!("no Zip64 end record at {z64}"));
        }
        entries = le64(z64 + 32).ok_or("cut")?;
        cd_size = le64(z64 + 40).ok_or("cut")?;
        cd_off = le64(z64 + 48).ok_or("cut")?;
    }
    let mut at = usize::try_from(cd_off).map_err(|_| "offset")?;
    let cd_end = at.checked_add(usize::try_from(cd_size).map_err(|_| "size")?);
    if cd_end.is_none_or(|e| e > eocd) {
        return Err(format!(
            "central directory {cd_off}+{cd_size} runs past the end record"
        ));
    }
    let mut seen = 0u64;
    let mut unchecked = 0usize;
    // Each entry's bytes as the walk read them (stored entries only), for
    // the `zip` crate to be held to.
    let mut stored_plain: Vec<Option<Vec<u8>>> = Vec::new();
    let mut names = std::collections::HashSet::new();
    let mut repeated_name = false;
    let mut methods: Vec<u64> = Vec::new();
    while seen < entries {
        if le32(at) != Some(0x0201_4b50) {
            return Err(format!("entry {seen}: no central record at {at}"));
        }
        let flags = le16(at + 8).ok_or("cut")?;
        let method = le16(at + 10).ok_or("cut")?;
        let (crc, mut csize, mut usize_) = (
            le32(at + 16).ok_or("cut")?,
            le32(at + 20).ok_or("cut")?,
            le32(at + 24).ok_or("cut")?,
        );
        let (n, e, c) = (
            le16(at + 28).ok_or("cut")? as usize,
            le16(at + 30).ok_or("cut")? as usize,
            le16(at + 32).ok_or("cut")? as usize,
        );
        let mut lho = le32(at + 42).ok_or("cut")?;
        let name = bytes.get(at + 46..at + 46 + n).ok_or("name cut")?;
        let extra = bytes.get(at + 46 + n..at + 46 + n + e).ok_or("extra cut")?;
        // The Zip64 block gives, in order, the sizes and offset that are
        // all ones in the record.
        let mut x = 0;
        while x + 4 <= extra.len() {
            let id = u16::from_le_bytes([extra[x], extra[x + 1]]);
            let len = usize::from(u16::from_le_bytes([extra[x + 2], extra[x + 3]]));
            let body = extra.get(x + 4..x + 4 + len).ok_or("extra field cut")?;
            if id == 1 {
                let mut p = 0;
                for v in [&mut usize_, &mut csize, &mut lho] {
                    if *v == 0xffff_ffff {
                        let w = body.get(p..p + 8).ok_or("Zip64 extra short")?;
                        *v = u64::from_le_bytes(w.try_into().expect("eight bytes"));
                        p += 8;
                    }
                }
            }
            x += 4 + len;
        }
        repeated_name |= !names.insert(name.to_vec());
        methods.push(method);
        let lh = usize::try_from(lho).map_err(|_| "local offset")?;
        if le32(lh) != Some(0x0403_4b50) {
            return Err(format!("entry {seen} {name:?}: no local header at {lh}"));
        }
        let (ln, le) = (
            le16(lh + 26).ok_or("cut")? as usize,
            le16(lh + 28).ok_or("cut")? as usize,
        );
        if bytes.get(lh + 30..lh + 30 + ln) != Some(name) {
            return Err(format!("entry {seen} {name:?}: the local name differs"));
        }
        let data_at = lh + 30 + ln + le;
        let data = bytes
            .get(data_at..data_at.saturating_add(usize::try_from(csize).map_err(|_| "csize")?))
            .ok_or_else(|| format!("entry {seen} {name:?}: data runs past the file"))?;
        if flags & 1 != 0 || !matches!(method, 0 | 8) {
            // Encrypted, or a method the walk does not decode: structure only.
            unchecked += 1;
            stored_plain.push(None);
        } else {
            let plain: Vec<u8> = if method == 0 {
                data.to_vec()
            } else {
                let mut window = vec![0u8; stuffr::infozip::WSIZE];
                let mut out = Vec::new();
                let r = stuffr::infozip::inflate(
                    &mut data.iter(),
                    false,
                    &mut window,
                    &mut |c| {
                        out.extend_from_slice(c);
                        if out.len() as u64 > OUTPUT_CAP {
                            Err(())
                        } else {
                            Ok(())
                        }
                    },
                    &mut |_| {},
                );
                r.map_err(|e| format!("entry {seen} {name:?}: inflate failed: {e:?}"))?;
                out
            };
            if plain.len() as u64 != usize_ {
                return Err(format!(
                    "entry {seen} {name:?}: {} bytes where the record says {usize_}",
                    plain.len()
                ));
            }
            let mut crc_now = !0u32;
            for &b in &plain {
                crc_now ^= u32::from(b);
                for _ in 0..8 {
                    crc_now = if crc_now & 1 != 0 {
                        0xedb8_8320 ^ (crc_now >> 1)
                    } else {
                        crc_now >> 1
                    };
                }
            }
            if u64::from(!crc_now) != crc {
                return Err(format!(
                    "entry {seen} {name:?}: CRC {:08x}, the record says {crc:08x}",
                    !crc_now
                ));
            }
            stored_plain.push(Some(plain));
        }
        at += 46 + n + e + c;
        seen += 1;
    }
    if at as u64 != cd_off + cd_size {
        return Err(format!(
            "central records end at {at}, the end record says {}",
            cd_off + cd_size
        ));
    }
    let mut v = Verified {
        entries: entries as usize,
        unchecked,
        crate_read: 0,
        crate_deflated: 0,
        crate_skipped: None,
    };
    // The `zip` crate takes the last `PK\5\6` it finds, so an archive whose
    // comment holds that signature is whole to the walk above (and to a
    // reader that checks the comment length) and unreadable to the crate; and
    // it collapses central records that share a name (its index is keyed by
    // name), so a repeated name makes its count and its `by_index` misalign.
    // Neither is held to the crate's count or bytes.
    if bytes[eocd + 22..].windows(4).any(|w| w == b"PK\x05\x06") {
        v.crate_skipped = Some("the comment holds an end-record signature");
        return Ok(v);
    }
    if repeated_name {
        v.crate_skipped = Some("two central records share a name");
        return Ok(v);
    }
    let mut archive = ::zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| format!("the zip crate refuses it: {e}"))?;
    let counted = archive.len();
    if counted as u64 != entries {
        return Err(format!(
            "the zip crate counts {counted} entries, the end record {entries}"
        ));
    }
    // The `zip` crate reads every entry the walk checked (stored and
    // deflated: the workspace's `zip` has `deflate-flate2`, and cargo unifies
    // the fuzz crate's `default-features = false` with it, so the decoder is
    // there; an entry it cannot open is a failure, not a skip) and must give
    // the same bytes.
    for (i, (plain, method)) in stored_plain.iter().zip(&methods).enumerate() {
        let Some(plain) = plain else { continue };
        let mut got = Vec::new();
        let mut f = archive
            .by_index(i)
            .map_err(|e| format!("the zip crate cannot open entry {i} (method {method}): {e}"))?;
        std::io::Read::read_to_end(&mut f, &mut got)
            .map_err(|e| format!("the zip crate cannot read entry {i}: {e}"))?;
        if got != *plain {
            return Err(format!(
                "the zip crate reads {} bytes of entry {i}, the walk {}",
                got.len(),
                plain.len()
            ));
        }
        v.crate_read += 1;
        v.crate_deflated += usize::from(*method == 8);
    }
    Ok(v)
}
