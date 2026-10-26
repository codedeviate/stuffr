//! The conversions against glibc 2.39 `en_US.UTF-8` and the C locale
//! (probe 2026-10-26, `mbstowcs`/`wctomb` in the reference image) and
//! against zip's own UTF-8 coder.

use super::*;

#[test]
fn mbstowcs_is_glibcs_utf8() {
    let ok = |s: &[u8]| local_to_wide(true, s).map(|w| w.len());
    assert_eq!(ok(b"caf\xc3\xa9"), Some(4));
    assert_eq!(ok(b"\xc1\xbf"), None); // overlong
    assert_eq!(ok(b"\xe0\x80\x80"), None);
    assert_eq!(ok(b"\xf0\x80\x80\x80"), None);
    assert_eq!(ok(b"\xfc\x80\x80\x80\x80\x80"), None);
    assert_eq!(ok(b"\xed\xa0\x80"), None); // surrogate
    assert_eq!(
        local_to_wide(true, b"\xf4\x90\x80\x80"),
        Some(vec![0x11_0000])
    );
    assert_eq!(
        local_to_wide(true, b"\xfc\x84\x80\x80\x80\x80"),
        Some(vec![0x400_0000])
    );
    assert_eq!(
        local_to_wide(true, b"\xfd\xbf\xbf\xbf\xbf\xbf"),
        Some(vec![0x7fff_ffff])
    );
    assert_eq!(ok(b"\x7f"), Some(1));
    assert_eq!(ok(b"h\xe9"), None);
    assert_eq!(ok(b"\xc3"), None);
    assert_eq!(ok(b"\xe2\x82"), None);
    assert_eq!(ok(b"\xc3\xa9\x80"), None);
    assert_eq!(ok(b"\xfe"), None);
}

#[test]
fn the_c_locale_converts_ascii_only() {
    assert_eq!(local_to_wide(false, b"\x7f"), Some(vec![0x7f]));
    assert_eq!(local_to_wide(false, b"caf\xc3\xa9"), None);
    assert_eq!(wide_to_local(false, false, &[0x61, 0xe9]), b"a#U00e9");
}

#[test]
fn zips_coder_writes_del_as_two_bytes() {
    assert_eq!(local_to_utf8(true, b"d\x7fl").unwrap(), b"d\xc1\xbfl");
    assert_eq!(local_to_utf8(true, b"caf\xc3\xa9").unwrap(), b"caf\xc3\xa9");
    assert_eq!(local_to_utf8(true, b"h\xe9"), None);
    // zip's decoder takes overlong forms and surrogates
    assert_eq!(utf8_to_wide(b"\xc1\xbf"), Some(vec![0x7f]));
    assert_eq!(utf8_to_wide(b"\xed\xa0\x80"), Some(vec![0xd800]));
    assert_eq!(utf8_to_wide(b"h\xe9.txt"), None);
    assert_eq!(utf8_to_wide(b"\xc3"), None);
}

#[test]
fn escapes_are_zips() {
    assert_eq!(wide_char_to_escape(0xe9), b"#U00e9");
    assert_eq!(wide_char_to_escape(0x0a), b"#U000a");
    assert_eq!(wide_char_to_escape(0x11_0000), b"#L110000");
    assert_eq!(wide_char_to_escape(0x400_0000), b"#L000000");
    assert_eq!(local_to_escape(true, b"n\nl").unwrap(), b"n#U000al");
    assert_eq!(local_to_escape(true, b"d\x7fl").unwrap(), b"d#U007fl");
    assert_eq!(local_to_escape(true, b"s\xed\xa0\x80"), None);
    // wctomb refuses a surrogate: escaped even without -UN escape
    assert_eq!(
        utf8_to_local(true, false, b"\xed\xa0\x80").unwrap(),
        b"#Ud800"
    );
    assert_eq!(
        utf8_to_local(true, true, b"caf\xc3\xa9").unwrap(),
        b"caf#U00e9"
    );
    assert_eq!(utf8_to_local(true, false, b"h\xe9"), None);
}

#[test]
fn the_unicode_path_field_is_written_in_place_or_appended() {
    let mut e = Vec::new();
    add_unicode_path_field(&mut e, b"caf\xe9.txt", "café.txt".as_bytes());
    assert_eq!(
        e,
        [
            &[0x75, 0x70, 14, 0, 1][..],
            &0x4e75_28d3u32.to_le_bytes(),
            "café.txt".as_bytes()
        ]
        .concat()
    );
    let first = e.clone();
    add_unicode_path_field(&mut e, b"caf\xe9.txt", "café.txt".as_bytes());
    assert_eq!(e, first);
    let mut e = b"UT\x01\x00\x03".to_vec();
    add_unicode_path_field(&mut e, b"a", b"b");
    assert_eq!(&e[..5], b"UT\x01\x00\x03");
    assert_eq!(&e[5..7], &[0x75, 0x70]);
}

#[test]
fn ascii_is_cut_at_a_nul() {
    assert!(is_ascii(Some(b"abc\0\xe9")));
    assert!(!is_ascii(Some(b"ab\xe9")));
    assert!(!is_ascii(None));
}
