//! Every message bzip2recover prints, copied verbatim from bzip2 1.0.8's
//! `bzip2recover.c` (see `LICENSE-bzip2`), including its typos: a write
//! error says "reading". Each keeps the C `fprintf` layout: `%s`, `%d` and
//! `%Lu` take an argument in order (numbers are formatted by the caller).
//! The comment on each names the function in `bzip2recover.c` it comes from.

use std::io::Write;

/// `main`: printed first, on every run.
pub(super) const BANNER: &str = "bzip2recover 1.0.8: extracts blocks from damaged .bz2 files.\n";

/// `main`, when `argc != 2`: the program name twice.
pub(super) const USAGE: &str = "%s: usage is `%s damaged_file_name'.\n";

/// `main`, after `USAGE`, for an 8-byte `MaybeUInt64` (every 64-bit build).
pub(super) const USAGE_SIZE: &str = "\trestrictions on size of recovered file: None\n";

/// `main`: the operand is `BZ_MAX_FILENAME - 20` bytes or longer.
pub(super) const NAME_TOO_LONG: &str =
    "%s: supplied filename is suspiciously (>= %d chars) long.  Bye!\n";

/// `main`: the first `fopen` of the input failed.
pub(super) const CANT_READ: &str = "%s: can't read `%s'\n";

/// `main`: before the first pass.
pub(super) const SEARCHING: &str = "%s: searching for block boundaries ...\n";

/// `main`, first pass: a block ended by a magic.
pub(super) const BLOCK: &str = "   block %d runs from %Lu to %Lu\n";

/// `main`, first pass: the input ended inside a block.
pub(super) const BLOCK_INCOMPLETE: &str = "   block %d runs from %Lu to %Lu (incomplete)\n";

/// `main`: the first pass recorded no block.
pub(super) const NO_BLOCKS: &str = "%s: sorry, I couldn't find any block boundaries.\n";

/// `main`: between the passes.
pub(super) const SPLITTING: &str = "%s: splitting into blocks\n";

/// `main`: the second `fopen` of the input failed.
pub(super) const CANT_OPEN: &str = "%s: can't open `%s'\n";

/// `main`, second pass: before each output is opened.
pub(super) const WRITING: &str = "   writing block %d to `%s' ...\n";

/// `main`, second pass: an output could not be opened.
pub(super) const CANT_WRITE: &str = "%s: can't write `%s'\n";

/// `main`: the end of a successful run.
pub(super) const FINISHED: &str = "%s: finished\n";

/// `readError` and `writeError` (identical in 1.0.8, "reading" in both).
pub(super) const IO_ERROR: &str = "%s: I/O error reading `%s', possible reason follows.\n";

/// What C's `perror(s)` prints.
pub(super) const PERROR: &str = "%s: %s\n";

/// `readError`, `writeError`, `mallocFail`: the closing warning.
pub(super) const MAY_BE_INCOMPLETE: &str = "%s: warning: output file(s) may be incomplete.\n";

/// `tooManyBlocks`.
pub(super) const TOO_MANY_BLOCKS: &str = concat!(
    "%s: `%s' appears to contain more than %d blocks\n",
    "%s: and cannot be handled.  To fix, increase\n",
    "%s: BZ_MAX_HANDLED_BLOCKS in bzip2recover.c, and recompile.\n",
);

/// Write `fmt` with each `%s`, `%d` and `%Lu` replaced by `args` in order,
/// as C's `fprintf` does for these formats. Write errors are ignored, as
/// bzip2recover ignores `fprintf`'s result.
pub(super) fn printf(w: &mut dyn Write, fmt: &str, args: &[&[u8]]) {
    let mut out = Vec::with_capacity(fmt.len() + 64);
    let mut args = args.iter();
    let mut bytes = fmt.as_bytes().iter().copied().peekable();
    while let Some(b) = bytes.next() {
        if b != b'%' {
            out.push(b);
            continue;
        }
        match bytes.next() {
            Some(b's' | b'd') => out.extend_from_slice(args.next().copied().unwrap_or_default()),
            Some(b'L') if bytes.peek() == Some(&b'u') => {
                bytes.next();
                out.extend_from_slice(args.next().copied().unwrap_or_default());
            }
            Some(other) => out.extend_from_slice(&[b'%', other]),
            None => out.push(b'%'),
        }
    }
    let _ = w.write_all(&out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printf_fills_s_d_and_lu_in_order() {
        let mut v = Vec::new();
        printf(&mut v, BLOCK, &[b"3", b"80", b"269145"]);
        assert_eq!(v, b"   block 3 runs from 80 to 269145\n");
        let mut v = Vec::new();
        printf(&mut v, USAGE, &[b"p", b"p"]);
        assert_eq!(v, b"p: usage is `p damaged_file_name'.\n");
    }

    #[test]
    fn too_many_blocks_is_three_lines_each_with_the_program_name() {
        let mut v = Vec::new();
        printf(&mut v, TOO_MANY_BLOCKS, &[b"p", b"f", b"50000", b"p", b"p"]);
        assert_eq!(
            String::from_utf8(v).unwrap(),
            "p: `f' appears to contain more than 50000 blocks\n\
             p: and cannot be handled.  To fix, increase\n\
             p: BZ_MAX_HANDLED_BLOCKS in bzip2recover.c, and recompile.\n"
        );
    }
}
