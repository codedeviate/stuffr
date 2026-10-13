//! fileio_common.h's display layer: `DISPLAYLEVEL` and `EXM_THROW`'s
//! format. The progress line (`DISPLAYUPDATE`, `REFRESH_RATE`) arrives in
//! Task 9.

use std::io::Write;

use super::messages::{self as m, printf};

/// `g_display_prefs`: the notification level (0: nothing, 1: errors, 2:
/// results, interaction and warnings, 3: progress, 4: information).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Display {
    /// `displayLevel`.
    pub level: i32,
}

impl Display {
    /// `DISPLAYLEVEL(l, fmt, args)`: `fmt` (a messages.rs format) on
    /// standard error when the level is at least `l`.
    pub(crate) fn at(&self, l: i32, err: &mut dyn Write, fmt: &str, args: &[&[u8]]) {
        if self.level >= l {
            printf(err, fmt, args);
        }
    }
}

/// fileio_common.h: `EXM_THROW(code, msg)`: `zstd: error <code> : <msg> \n`
/// at display level 1, returning `code` for the caller to exit with. `msg`
/// is the formatted message. The level-5 "Error defined at <file>, line
/// <n>" line names zstd's own source position, which a port has no
/// equivalent of; it is not printed.
pub(crate) fn exm_throw(d: &Display, err: &mut dyn Write, code: i32, msg: &[u8]) -> i32 {
    d.at(1, err, m::EXM_PREFIX, &[]);
    d.at(1, err, m::EXM_ERROR, &[code.to_string().as_bytes()]);
    if d.level >= 1 {
        let _ = err.write_all(msg);
    }
    d.at(1, err, m::EXM_END, &[]);
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exm_throw_prints_at_level_1_and_returns_its_code() {
        let mut err = Vec::new();
        let code = exm_throw(
            &Display { level: 1 },
            &mut err,
            11,
            b"Parameter is out of bound",
        );
        assert_eq!(code, 11);
        assert_eq!(err, b"zstd: error 11 : Parameter is out of bound \n");
        let mut err = Vec::new();
        assert_eq!(exm_throw(&Display { level: 0 }, &mut err, 1, b"x"), 1);
        assert!(err.is_empty());
    }
}
