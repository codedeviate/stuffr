//! macOS's quarantine attribute (`com.apple.quarantine`), carried from an
//! input onto what is made from it — the thing Gatekeeper checks before
//! running a downloaded program. An extractor that drops it hands a
//! downloaded archive's contents a Gatekeeper bypass (the CVE-2022-22616 /
//! CVE-2022-42821 class; security audit EXTRACT-3).
//!
//! The value written is the one libquarantine writes for an archive
//! (`qtn_file_init_with_fd()` then `qtn_file_apply_to_fd()`), as Apple's
//! unzip and bsdtar do: see [`qtn_value`]. Everything goes by descriptor.
//! Off macOS there is no attribute: [`read`] answers `None` and [`apply`]
//! does nothing.
//!
//! Shared by `unpack`, `salvage` and the single-stream verbs and by the
//! `stuffr` binary's unzip compatibility family. Not part of the stable API.

use std::io;

/// The quarantine attribute's name.
#[cfg(target_os = "macos")]
const QUARANTINE: &std::ffi::CStr = c"com.apple.quarantine";

/// The longest quarantine value read (its fields are a flags word, a time,
/// an agent name and a UUID: far below this).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const QUARANTINE_MAX: usize = 1024;

/// What libquarantine writes for an archive whose quarantine value is
/// `raw` (`qtn_file_init_with_fd()` then `qtn_file_apply_to_fd()`), `None`
/// when it writes nothing. This is the **fallback** for a system without
/// libquarantine; on macOS the library itself is asked ([`read`], [`apply`]).
///
/// probe: macOS 27.2 (2026-11-07). Flags (1-4 hex digits): 0 becomes `0081`;
/// g = flags & 0xfde7, nothing when 0, else g when it has 0x40, g | 0x80
/// when it has 0x01 or 0x02, else g; no 0x4000 cut-off. The time is 1-8 hex
/// digits (a non-empty field), written as eight lowercase digits. Everything
/// after the third `;` is the agent and the UUID (and anything further): read
/// with `\xHH` decoded (any other `\` is `?`) and written with the bytes <=
/// 0x20, `"` `$` `,` `/` `:` `;` `[` `]` `{` `}` and >= 0x7f as lowercase
/// `\xHH` (a decoded `\` is `\x5c`), so a `;` in a fifth field is `\x3b`. Three
/// fields, flags not hex or longer than four digits, an empty time: nothing.
/// Odder times (signs, `0x`, spaces, trailing text, over eight digits) are
/// parsed by libquarantine in ways not reproduced: refused here.
/// ruling: T10-6.
pub fn qtn_value(raw: &[u8]) -> Option<Vec<u8>> {
    let mut fields = raw.splitn(4, |&b| b == b';');
    let flags = fields.next()?;
    let time = fields.next()?;
    let agent = fields.next()?;
    let rest = fields.next()?;
    let hex = |f: &[u8], max: usize| {
        if f.is_empty() || f.len() > max || !f.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        u32::from_str_radix(std::str::from_utf8(f).ok()?, 16).ok()
    };
    let flags = hex(flags, 4)?;
    let time = hex(time, 8)?;
    let out = if flags == 0 {
        0x0081
    } else {
        let g = flags & 0xfde7;
        if g == 0 {
            return None;
        } else if g & 0x40 != 0 {
            g
        } else if g & 0x03 != 0 {
            g | 0x80
        } else {
            g
        }
    };
    let mut v = format!("{out:04x};{time:08x};").into_bytes();
    // The agent and everything after it: each decoded and re-encoded.
    reencode(agent, &mut v);
    v.push(b';');
    reencode(rest, &mut v);
    Some(v)
}

/// libquarantine's decode-then-encode of free text (see [`qtn_value`]).
fn reencode(text: &[u8], out: &mut Vec<u8>) {
    let mut i = 0;
    while i < text.len() {
        let mut b = text[i];
        i += 1;
        let mut decoded = false;
        if b == b'\\' {
            let hexv = text
                .get(i..i + 3)
                .filter(|w| w[0] == b'x' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit())
                .and_then(|w| u8::from_str_radix(std::str::from_utf8(&w[1..]).ok()?, 16).ok());
            if let Some(d) = hexv {
                b = d;
                i += 3;
                decoded = true;
            }
        }
        if b == b'\\' && !decoded {
            out.push(b'?');
        } else if b <= 0x20
            || b >= 0x7f
            || b == b'\\'
            || matches!(
                b,
                b'"' | b'$' | b',' | b'/' | b':' | b';' | b'[' | b']' | b'{' | b'}'
            )
        {
            out.extend_from_slice(format!("\\x{b:02x}").as_bytes());
        } else {
            out.push(b);
        }
    }
}

/// The raw quarantine value of the open file `f`, `None` when it has none
/// (or off macOS).
pub fn read_raw(f: &std::fs::File) -> Option<Vec<u8>> {
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        let mut buf = vec![0u8; QUARANTINE_MAX];
        // SAFETY: the name is NUL-terminated; `buf` is valid for its
        // length; the descriptor is open.
        let n = unsafe {
            libc::fgetxattr(
                f.as_raw_fd(),
                QUARANTINE.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                0,
            )
        };
        if n < 0 {
            return None;
        }
        buf.truncate(n as usize);
        Some(buf)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = f;
        None
    }
}

/// The quarantine of an input, in the form [`apply`] needs: libquarantine's
/// own serialisation (`qtn_file_to_data()`) when the library is available,
/// else the raw attribute value for the fallback rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Quarantine(Repr);

#[derive(Clone, Debug, PartialEq, Eq)]
enum Repr {
    /// `qtn_file_to_data()` bytes.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    Data(Vec<u8>),
    /// The raw attribute value; [`qtn_value`] decides what is written.
    Raw(Vec<u8>),
}

#[cfg(target_os = "macos")]
mod lib {
    use std::ffi::{c_char, c_int, c_void};
    use std::sync::OnceLock;

    type Handle = *mut c_void;

    /// The libquarantine entry points this crate uses.
    pub(super) struct Qtn {
        pub alloc: unsafe extern "C" fn() -> Handle,
        pub init_with_fd: unsafe extern "C" fn(Handle, c_int) -> c_int,
        pub to_data: unsafe extern "C" fn(Handle, *mut c_char, *mut usize) -> c_int,
        pub init_with_data: unsafe extern "C" fn(Handle, *const c_void, usize) -> c_int,
        pub apply_to_fd: unsafe extern "C" fn(Handle, c_int) -> c_int,
        pub free: unsafe extern "C" fn(Handle),
    }

    pub(super) type H = Handle;

    /// Looks up `name` in `h`, `None` when absent.
    ///
    /// # Safety
    /// `h` is a live `dlopen` handle and `T` is the symbol's true type.
    unsafe fn sym<T: Copy>(h: *mut c_void, name: &std::ffi::CStr) -> Option<T> {
        // SAFETY: per the caller; `name` is NUL-terminated.
        let p = unsafe { libc::dlsym(h, name.as_ptr()) };
        if p.is_null() {
            return None;
        }
        // SAFETY: a function pointer is pointer-sized; `T` is one by contract.
        Some(unsafe { std::mem::transmute_copy::<*mut c_void, T>(&p) })
    }

    /// The library, opened once; `None` when it or a symbol is missing.
    pub(super) fn get() -> Option<&'static Qtn> {
        static LIB: OnceLock<Option<Qtn>> = OnceLock::new();
        LIB.get_or_init(|| {
            // SAFETY: a NUL-terminated path; the handle is never closed.
            let h = unsafe {
                libc::dlopen(
                    c"/usr/lib/system/libquarantine.dylib".as_ptr(),
                    libc::RTLD_NOW,
                )
            };
            if h.is_null() {
                return None;
            }
            // SAFETY: each type is the C signature of its symbol (qtn_file_*
            // as probed on macOS 27.2).
            unsafe {
                Some(Qtn {
                    alloc: sym(h, c"_qtn_file_alloc")?,
                    init_with_fd: sym(h, c"_qtn_file_init_with_fd")?,
                    to_data: sym(h, c"_qtn_file_to_data")?,
                    init_with_data: sym(h, c"_qtn_file_init_with_data")?,
                    apply_to_fd: sym(h, c"_qtn_file_apply_to_fd")?,
                    free: sym(h, c"_qtn_file_free")?,
                })
            }
        })
        .as_ref()
    }
}

/// The value to give what is made from the open input `f`. `None` when it
/// has no quarantine, libquarantine refuses its value, or off macOS.
pub fn read(f: &std::fs::File) -> Option<Quarantine> {
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        let raw = read_raw(f)?;
        let Some(q) = lib::get() else {
            return Some(Quarantine(Repr::Raw(raw)));
        };
        // SAFETY: `alloc` returns a handle (or null, checked); every later
        // call gets that live handle, `buf`/`len` describe a valid buffer,
        // and the handle is freed on every path.
        unsafe {
            let h = (q.alloc)();
            if h.is_null() {
                return None;
            }
            let mut data = None;
            if (q.init_with_fd)(h, f.as_raw_fd()) == 0 {
                let mut buf = vec![0u8; 4096];
                let mut len = buf.len();
                if (q.to_data)(h, buf.as_mut_ptr().cast(), &mut len) == 0 && len <= buf.len() {
                    buf.truncate(len);
                    data = Some(buf);
                }
            }
            (q.free)(h);
            data.map(|d| Quarantine(Repr::Data(d)))
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = f;
        None
    }
}

/// Sets the quarantine `q` on the open file or directory `f` as
/// libquarantine would (`qtn_file_apply_to_fd()`): possibly nothing, for a
/// value it does not write. Nothing off macOS.
pub fn apply(f: &std::fs::File, q: &Quarantine) -> io::Result<()> {
    match &q.0 {
        Repr::Raw(raw) => match qtn_value(raw) {
            Some(v) => apply_raw(f, &v),
            None => Ok(()),
        },
        #[cfg(target_os = "macos")]
        Repr::Data(d) => {
            use std::os::fd::AsRawFd;
            let Some(l) = lib::get() else {
                return Err(io::Error::other("libquarantine is unavailable"));
            };
            // SAFETY: the handle comes from `alloc`, is used only while
            // live and is freed on every path; `d` is valid for its length.
            unsafe {
                let h: lib::H = (l.alloc)();
                if h.is_null() {
                    return Err(io::Error::other("qtn_file_alloc failed"));
                }
                let rc = if (l.init_with_data)(h, d.as_ptr().cast(), d.len()) == 0 {
                    (l.apply_to_fd)(h, f.as_raw_fd())
                } else {
                    -1
                };
                let err = io::Error::last_os_error();
                (l.free)(h);
                if rc == 0 { Ok(()) } else { Err(err) }
            }
        }
        #[cfg(not(target_os = "macos"))]
        Repr::Data(_) => Ok(()),
    }
}

/// Sets the raw quarantine attribute value `v` on `f`, unrewritten. Nothing
/// off macOS.
pub fn apply_raw(f: &std::fs::File, v: &[u8]) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: the name is NUL-terminated; `v` is valid for its length;
        // the descriptor is open.
        let rc = unsafe {
            libc::fsetxattr(
                f.as_raw_fd(),
                QUARANTINE.as_ptr(),
                v.as_ptr().cast(),
                v.len(),
                0,
                0,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (f, v);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fallback rule, value by value (probed on macOS 27.2).
    #[test]
    fn quarantine_values_are_rewritten_as_libquarantine_does() {
        let q = |s: &str| qtn_value(s.as_bytes()).map(|v| String::from_utf8(v).unwrap());
        assert_eq!(
            q("0001;5f000000;Safari;UUID").as_deref(),
            Some("0081;5f000000;Safari;UUID")
        );
        assert_eq!(
            q("0082;688909f7;Test;").as_deref(),
            Some("0082;688909f7;Test;")
        );
        assert_eq!(q("0000;00000000;;").as_deref(), Some("0081;00000000;;"));
        assert_eq!(q("ffff;5f000000;;").as_deref(), Some("fde7;5f000000;;"));
        assert_eq!(q("4000;5f000000;;").as_deref(), Some("4000;5f000000;;"));
        assert_eq!(q("14000;5f000000;;"), None);
        assert_eq!(q("4000;;;"), None);
        assert_eq!(q("41;5f000000;;").as_deref(), Some("0041;5f000000;;"));
        assert_eq!(q("0018;5f000000;;"), None);
        assert_eq!(q("0002;5f000000;;").as_deref(), Some("0082;5f000000;;"));
        assert_eq!(q("0181;5f000000;Safari"), None);
        assert_eq!(q("zz;5f000000;;"), None);
        assert_eq!(
            q("4000;5f000000;Safari;UUID;extra").as_deref(),
            Some("4000;5f000000;Safari;UUID\\x3bextra")
        );
    }

    /// On macOS, libquarantine and the fallback rule write the same thing.
    #[cfg(target_os = "macos")]
    #[test]
    fn libquarantine_and_the_fallback_agree() {
        if lib::get().is_none() {
            return;
        }
        let dir =
            std::env::temp_dir().join(format!("stuffr-quarantine-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let mut values: Vec<String> = Vec::new();
        for f in [0u32, 1, 2, 4, 0x18, 0x40, 0x81, 0x3de7, 0xfde7, 0xffff] {
            values.push(format!("{f:04x}"));
        }
        for n in 0..16u32 {
            values.push(format!("{:04x}", n << 12));
        }
        for f in (0..=0xffffu32).step_by(97) {
            values.push(format!("{f:04x}"));
        }
        let mut cases: Vec<String> = values
            .iter()
            .map(|f| format!("{f};5f000000;Safari;UUID"))
            .collect();
        for extra in [
            "zz;5f000000;Safari;UUID",
            "10000;5f000000;Safari;UUID",
            "4000;;;",
            "4000;5f000000;Safari",
            "4000;5f000000;Safari;UUID;extra",
            "4000;5f000000;Safari;UUID;a;b",
            "4000;5f000000;Safari;",
            "4000;5f000000;;",
            "4000;5f000000;;UUID;",
            "41;5f000000;Safari;UUID",
            ";5f000000;Safari;UUID",
            "0001;5f;Sa fari;UUID",
            "0001;5f;Safari;UUID\\x3b",
            "00FF;5F;Safari;UUID",
            "0001;5f;Sa fari;UU\"ID",
            "0001;5f;Sa/ri:x;U[1]{2},$3",
            "0001;5f;Sa\\x41ri;U\\x5cU",
            "0001;5f;Sa\\fri;U\\xzzU",
            "0001;5f;S\u{e9};U\u{e9}\n",
            "0001;ffffffff;Safari;UUID",
            "0001;0;Safari;UUID",
            "0001;5f;S;U;\\x3b",
        ] {
            cases.push(extra.to_string());
        }
        let src = dir.join("src");
        let a = dir.join("a");
        let b = dir.join("b");
        for case in &cases {
            for p in [&src, &a, &b] {
                let _ = std::fs::remove_file(p);
                std::fs::write(p, b"x").unwrap();
            }
            let sf = std::fs::File::open(&src).unwrap();
            apply_raw(&sf, case.as_bytes()).unwrap();
            let af = std::fs::File::open(&a).unwrap();
            let bf = std::fs::File::open(&b).unwrap();
            if let Some(q) = read(&sf) {
                assert!(matches!(q.0, Repr::Data(_)));
                let _ = apply(&af, &q);
            }
            if let Some(v) = qtn_value(case.as_bytes()) {
                apply_raw(&bf, &v).unwrap();
            }
            assert_eq!(
                read_raw(&af),
                read_raw(&bf),
                "libquarantine and the fallback disagree on {case:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
