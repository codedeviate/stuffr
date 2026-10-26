use super::*;

/// Deviation 13: a block that runs past the old extra field ends the copy
/// (the C copies past it); blocks whose tag the new field has are dropped.
#[test]
fn copy_nondup_extra_fields_stays_inside_the_old_field() {
    let new = [0x55, 0x54, 1, 0, 3];
    let old = [
        0x55, 0x54, 1, 0, 9, 0x01, 0x02, 2, 0, 7, 7, 0x09, 0x09, 0xff, 0,
    ];
    assert_eq!(
        copy_nondup_extra_fields(&old, &new),
        [0x01, 0x02, 2, 0, 7, 7, 0x55, 0x54, 1, 0, 3]
    );
    assert_eq!(copy_nondup_extra_fields(&[], &new), new);
    assert_eq!(copy_nondup_extra_fields(&[1, 2, 3], &[]), Vec::<u8>::new());
}

/// Deviation 13: a Zip64 field shorter than the sizes it should hold is
/// read as zeros past its end.
#[test]
fn a_short_zip64_field_reads_zeros() {
    let mut e = ZEntry {
        len: 0xffff_ffff,
        siz: 0xffff_ffff,
        cextra: vec![1, 0, 8, 0, 5, 0, 0, 0, 0, 0, 0, 0],
        ..ZEntry::default()
    };
    adjust_zip_central_entry(&mut e);
    assert_eq!((e.len, e.siz), (5, 0));
}

/// The `UT` and `UX` times as `ef_scan_ut_time` reads them: the last `UT`
/// block counts, an old `UX` one only without a `UT` or `Ux` before it.
#[test]
fn ut_and_ux_times() {
    let ut = |t: u32| {
        let mut b = vec![0x55, 0x54, 5, 0, 1];
        b.extend_from_slice(&t.to_le_bytes());
        b
    };
    let ux = |t: u32| {
        let mut b = vec![0x55, 0x58, 8, 0, 0, 0, 0, 0];
        b.extend_from_slice(&t.to_le_bytes());
        b
    };
    let e = |cextra: Vec<u8>| ZEntry {
        cextra,
        ..ZEntry::default()
    };
    assert_eq!(ut_mtime(&e(ut(7))), Some(7));
    assert_eq!(ut_mtime(&e([ut(7), ut(9)].concat())), Some(9));
    assert_eq!(ut_mtime(&e(ux(3))), Some(3));
    assert_eq!(ut_mtime(&e([ut(7), ux(3)].concat())), Some(7));
    assert_eq!(ut_mtime(&e(vec![0x55, 0x54, 1, 0, 0])), None);
    assert_eq!(ut_mtime(&e(vec![0x55, 0x54, 9, 0])), None);
    assert_eq!(ut_mtime(&ZEntry::default()), None);
}

/// util.c:search over `zsort`: a name found by binary search, cut at NUL.
#[test]
fn zsearch_finds_by_external_name() {
    let mk = |n: &[u8]| ZFile {
        zname: n.to_vec(),
        ..ZFile::default()
    };
    let ar = Archive {
        zfiles: vec![mk(b"b"), mk(b"a"), mk(b"c")],
        zsort: vec![1, 0, 2],
        ..Archive::default()
    };
    assert_eq!(zsearch(&ar, b"a"), Some(1));
    assert_eq!(zsearch(&ar, b"c\0x"), Some(2));
    assert_eq!(zsearch(&ar, b"d"), None);
    assert_eq!(zsearch(&Archive::default(), b"a"), None);
}
