use super::*;

/// A sink in memory that can be rewound.
struct Mem(Vec<u8>);

impl Write for Mem {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ZWrite for Mem {
    fn seekable(&self) -> bool {
        true
    }
    fn offset(&self) -> u64 {
        self.0.len() as u64
    }
    fn seek_to(&mut self, _at: u64) -> io::Result<()> {
        Ok(())
    }
    fn write_here(&mut self, _bytes: &[u8]) -> io::Result<()> {
        Ok(())
    }
    fn seek_end(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn seek_here(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn ferror(&self) -> Option<io::Error> {
        None
    }
}

fn entry() -> ZEntry {
    ZEntry {
        name: b"a.txt".to_vec(),
        iname: b"a.txt".to_vec(),
        oname: b"a.txt".to_vec(),
        vem: 0x31e,
        ver: 10,
        tim: 0x2b29_0dd4,
        crc: 0x363a_3020,
        siz: 6,
        len: 6,
        extra: b"UT\x05\x00\x03\x00\xca\x9a\x3b".to_vec(),
        cextra: b"UT\x05\x00\x03\x00\xca\x9a\x3b".to_vec(),
        att: 1,
        atx: 0x81a4_0000,
        ..ZEntry::default()
    }
}

#[test]
fn get_extra_field_walks_the_blocks() {
    let x = b"UT\x01\x00\x03\x01\x00\x02\x00ab";
    assert_eq!(get_extra_field(0x5455, x), Some(0));
    assert_eq!(get_extra_field(0x0001, x), Some(5));
    assert_eq!(get_extra_field(0x7875, x), None);
    assert_eq!(get_extra_field(0x0001, b""), None);
}

/// `-fz`: the local header's sizes are all ones and a 16-byte Zip64 block
/// follows the others; the central one has the uncompressed size only;
/// the end records are Zip64's, the end record's offset all ones.
#[test]
fn forced_zip64_records() {
    let mut out = ZOut::new(Box::new(Mem(Vec::new())), 1, None);
    let mut e = entry();
    putlocal(&mut e, &mut out).unwrap();
    assert!(out.zip64_entry);
    assert_eq!(e.ver, 45);
    assert_eq!(e.extra.len(), 9 + 20);
    putlocal_rewrite(&mut e, &mut out).unwrap();
    assert!(out.zip64_archive);
    putcentral(&mut e, &mut out).unwrap();
    assert_eq!(
        &e.cextra[9..],
        b"\x01\x00\x08\x00\x06\x00\x00\x00\x00\x00\x00\x00"
    );
    let c = out.w.offset();
    putend(&mut out, 1, 10, c, b"").unwrap();
    // Zip64 end record (56) + locator (20) + end record (22)
    assert_eq!(out.w.offset(), c + 56 + 20 + 22);
}

/// A plain entry: the local header carries the sizes, the end record no
/// Zip64 records.
#[test]
fn plain_records() {
    let mut out = ZOut::new(Box::new(Mem(Vec::new())), -1, None);
    let mut e = entry();
    putlocal(&mut e, &mut out).unwrap();
    assert!(!out.zip64_entry);
    e.off = out.current_local_offset;
    putcentral(&mut e, &mut out).unwrap();
    let off = out.w.offset();
    putend(&mut out, 1, off - 44, 44, b"hi").unwrap();
    assert_eq!(out.w.offset(), 44 + 46 + 5 + 9 + 22 + 2);
}

/// `-dg`'s dots: a space at the first write, then one dot each time the
/// count of large writes reaches the dot size.
#[test]
fn global_dots_follow_bfwrite() {
    let g = GlobalDots {
        dot_size: 32 * 1024,
        dot_count: -1,
    };
    let mut out = ZOut::new(Box::new(Mem(Vec::new())), -1, Some(g));
    out.bfwrite(b"header", Bf::LocalHeader).unwrap();
    assert_eq!(out.dots, b" ");
    for _ in 0..40 {
        out.bfwrite(&[0u8; 1024], Bf::Data).unwrap();
    }
    assert_eq!(out.dots, b" .");
}
