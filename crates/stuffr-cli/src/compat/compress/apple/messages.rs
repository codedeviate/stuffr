//! Every message the Apple personality prints, copied from Apple's
//! `compress.c` (file_cmds-479 `compress/`, BSD-3-Clause, see
//! `LICENSE-compress-bsd`) and Apple libc's `getopt`, `err(3)` and
//! `strerror`, and checked against `/usr/bin/compress` 487.0.1. Formats
//! keep C's `fprintf` layout (`%s` takes an argument in order, `%%` is a
//! literal percent sign) and print through [`printf`]. The comment on each
//! names the function it comes from.
//!
//! `warn`/`warnx`/`errx` (err(3)) put `getprogname()`, the invoked name,
//! and `: ` in front ([`PREFIX`]); `warn` adds `: ` and `strerror(errno)`
//! ([`ERRNO_SUFFIX`]), `warnx` and `errx` only the newline ([`NEWLINE`]).
//! getopt's own two messages name the full `argv[0]` instead.
//!
//! No deliberate changes: Apple's compress has no version or licence text.

pub(super) use crate::compat::host::printf;

// ---- err(3) ----

/// `warn`/`warnx`/`errx`: `getprogname()` and a colon.
pub(super) const PREFIX: &str = "%s: ";

/// `warn`: after the message, the error text.
pub(super) const ERRNO_SUFFIX: &str = ": %s\n";

/// `warnx`/`errx`: the message ends the line.
pub(super) const NEWLINE: &str = "\n";

/// `strerror(EFTYPE)` on macOS (errno 79), what `zread`'s refusal of a
/// header prints; the text is Apple's on every platform.
pub(super) const EFTYPE_TEXT: &str = "Inappropriate file type or format";

// ---- getopt(3), Apple libc ----

/// An option not in `b:cdfv`: `argv[0]`, then the option byte.
pub(super) const ILLEGAL_OPTION: &str = "%s: illegal option -- %s\n";

/// `-b` with nothing after it: `argv[0]`.
pub(super) const OPTION_NEEDS_ARGUMENT: &str = "%s: option requires an argument -- %s\n";

// ---- main ----

/// `main`, `-b` with trailing junk (`errx(1, ...)`, after [`PREFIX`]).
pub(super) const ILLEGAL_BIT_COUNT: &str = "illegal bit count -- %s";

/// `main`, `-c` and more than one operand when compressing (`errx(1)`).
pub(super) const C_ONE_FILE: &str = "the -c option permits only a single file argument";

/// `main`, a compress operand whose last `.` starts `.Z` (`cwarnx`).
pub(super) const TRAILING_Z: &str = "%s: name already has trailing .Z";

/// `main`, a name with no room for `.Z` in `MAXPATHLEN` (`cwarnx`).
pub(super) const NAME_TOO_LONG: &str = "%s: name too long";

// ---- compress, decompress ----

/// `compress`/`decompress`, an existing output not to be replaced
/// (`cwarnx`).
pub(super) const ALREADY_EXISTS: &str = "%s already exists";

/// `compress`, `-v` and an output not smaller than its input (a plain
/// `fprintf` to standard error, no program name).
pub(super) const WOULD_GROW: &str = "%s: file would grow; left unmodified\n";

/// `compress`/`decompress` under `-v`: the output's name (`fprintf`).
pub(super) const STATS_NAME: &str = "%s: ";

/// `compress`/`decompress` under `-v`, the output smaller than the input:
/// `%.0f` of output / input × 100 (formatted by the caller).
pub(super) const STATS_COMPRESSION: &str = "%s%% compression\n";

/// The same, otherwise: `%.0f` of input / output × 100.
pub(super) const STATS_EXPANSION: &str = "%s%% expansion\n";

// ---- setfile ----

/// `setfile`, `utimensat` failed (`cwarn`).
pub(super) const UTIMENSAT: &str = "utimensat: %s";

/// `setfile`, `chown` failed other than with `EPERM` (`cwarn`).
pub(super) const CHOWN: &str = "chown: %s";

/// `setfile`, `chmod` failed other than with `EOPNOTSUPP` (`cwarn`).
pub(super) const CHMOD: &str = "chmod: %s";

/// `setfile`, `chflags` failed other than with `EOPNOTSUPP` (`cwarn`).
pub(super) const CHFLAGS: &str = "chflags: %s";

// ---- permission ----

/// `permission`, standard error a terminal (`fprintf`).
pub(super) const OVERWRITE: &str = "overwrite %s? ";

// ---- usage ----

/// `usage(1)`.
pub(super) const USAGE_COMPRESS: &str = "usage: compress [-cfv] [-b bits] [file ...]\n";

/// `usage(0)`.
pub(super) const USAGE_UNCOMPRESS: &str = "usage: uncompress [-cfv] [-b bits] [file ...]\n";
