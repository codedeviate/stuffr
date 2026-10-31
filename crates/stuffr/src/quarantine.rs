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
/// when it writes nothing. The flags (the first field, hex) are rewritten,
/// the time, agent and UUID copied; a value without its fourth field is
/// dropped.
/// probe: the unzip family's Task 1 sweep of flags 0000..ffff
/// (`<flags>;00000000;;`) on macOS (P7): flags >= 0x4000 nothing; 0 becomes
/// `0081`; g = flags & 0x3de7, nothing when 0, else g when it has 0x40,
/// g | 0x80 when it has 0x01 or 0x02, else g. `0181;5f000000;Safari` (three
/// fields) is dropped.
/// ruling: T10-6. Flags that are not hex (never seen, not swept) are
/// treated as a value libquarantine cannot parse: nothing is written.
pub fn qtn_value(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.iter().filter(|&&b| b == b';').count() < 3 {
        return None;
    }
    let semi = raw.iter().position(|&b| b == b';')?;
    let flags = std::str::from_utf8(&raw[..semi]).ok()?;
    if flags.is_empty() || !flags.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let flags = u32::from_str_radix(flags, 16).ok()?;
    let out = if flags >= 0x4000 {
        return None;
    } else if flags == 0 {
        0x0081
    } else {
        let g = flags & 0x3de7;
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
    let mut v = format!("{out:04x}").into_bytes();
    v.extend_from_slice(&raw[semi..]);
    Some(v)
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

/// The value to give what is made from the open input `f`: its quarantine
/// passed through [`qtn_value`]. `None` when it has none, or off macOS.
pub fn read(f: &std::fs::File) -> Option<Vec<u8>> {
    qtn_value(&read_raw(f)?)
}

/// Sets the quarantine value `v` on the open file or directory `f`
/// (`qtn_file_apply_to_fd()`). Nothing off macOS.
pub fn apply(f: &std::fs::File, v: &[u8]) -> io::Result<()> {
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

    /// P7's rule, value by value (the unzip family's Task 1 probe cases).
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
        assert_eq!(
            q("0181;5f000000;Safari;ABCDEF01-0000").as_deref(),
            Some("0181;5f000000;Safari;ABCDEF01-0000")
        );
        assert_eq!(q("0000;00000000;;").as_deref(), Some("0081;00000000;;"));
        assert_eq!(q("4000;00000000;;"), None);
        assert_eq!(q("ffff;00000000;;"), None);
        assert_eq!(q("0018;00000000;;"), None); // g = 0x0000
        assert_eq!(q("0040;00000000;;").as_deref(), Some("0040;00000000;;"));
        assert_eq!(q("0002;00000000;;").as_deref(), Some("0082;00000000;;"));
        assert_eq!(q("0004;00000000;;").as_deref(), Some("0004;00000000;;"));
        assert_eq!(q("0181;5f000000;Safari"), None); // three fields
        assert_eq!(q("zz;00000000;;"), None); // T10-6
    }
}
