//! Every string the brotli command line prints, as `c/tools/brotli.c` of
//! brotli 1.2.1 (MIT) words it: parsing, help and version, then the file
//! handling and compression (`%s`/`%d` formats for `host::printf`, named
//! after the function that prints them). Task 5 adds decompression's.

use stuffr::brotli_opts::{LARGE_MAX_WINDOW_BITS, MAX_WINDOW_BITS, MIN_WINDOW_BITS};

/// `MAX_COMMENT_LEN`.
pub(super) const MAX_COMMENT_LEN: usize = 80;
/// `BROTLI_MIN_QUALITY` and `BROTLI_MAX_QUALITY`.
pub(super) const MIN_QUALITY: u32 = 0;
pub(super) const MAX_QUALITY: u32 = 11;

pub(super) const TOO_MANY_OPTIONS: &str = "too many options passed\n";
pub(super) const QUALITY_SET: &str = "quality already set\n";
pub(super) const STDOUT_SET: &str = "write to standard output already set\n";
pub(super) const STDOUT_SET_O: &str = "write to standard output already set (-o)\n";
pub(super) const STDOUT_SET_OUTPUT: &str = "write to standard output already set (--output)\n";
pub(super) const FORCE_SET: &str = "force output overwrite already set\n";
pub(super) const KEEP_SET: &str = "argument --rm / -j or --keep / -k already set\n";
pub(super) const NO_COPY_STAT_SET: &str = "argument --no-copy-stat / -n already set\n";
pub(super) const SQUASH_SET: &str = "argument --squash / -s already set\n";
pub(super) const VERBOSE_SET: &str = "argument --verbose / -v already set\n";
pub(super) const CONCATENATED_SET: &str = "argument -K / --concatenated already set\n";
pub(super) const LGWIN_SET: &str = "lgwin parameter already set\n";
pub(super) const COMMENT_SET: &str = "comment already set\n";
pub(super) const BAD_COMMENT: &str = "invalid base64-encoded comment\n";
pub(super) const DICTIONARY_SET: &str = "dictionary path already set\n";
pub(super) const SUFFIX_SET: &str = "suffix already set\n";

// ---- OpenInputFile, OpenOutputFile, CloseFiles, CopyStat ----

pub(super) const OPEN_INPUT_FAILED: &str = "failed to open input file [%s]: %s\n";
pub(super) const OPEN_OUTPUT_FAILED: &str = "failed to open output file [%s]: %s\n";
pub(super) const FCLOSE_FAILED: &str = "fclose failed [%s]: %s\n";
pub(super) const ACCESS_BITS_FAILED: &str = "setting access bits failed for [%s]: %s\n";
pub(super) const GROUP_FAILED: &str = "setting group failed for [%s]: %s\n";
pub(super) const USER_FAILED: &str = "setting user failed for [%s]: %s\n";
/// stuffr's own (ruling T1-f, deviation 4): the output named is the input
/// itself (same device and inode), which the reference truncates.
pub(super) const SAME_FILE: &str = "input file [%s] is the same as the output file\n";

// ---- ReadDictionary ----

pub(super) const OPEN_DICTIONARY_FAILED: &str = "failed to open dictionary file [%s]: %s\n";
/// No newline: the reference's own.
pub(super) const DICTIONARY_SIZE_UNKNOWN: &str = "could not get size of dictionary file [%s]";
pub(super) const DICTIONARY_TOO_LARGE: &str =
    "dictionary [%s] is larger than maximum allowed: %d\n";
pub(super) const READ_DICTIONARY_FAILED: &str = "failed to read dictionary [%s]: %s\n";
pub(super) const PREPARE_DICTIONARY_FAILED: &str = "failed to prepare dictionary [%s]\n";
/// stuffr's own (ruling T1-b): the pure tier has no raw dictionaries.
pub(super) const DICTIONARY_PURE_TIER: &str =
    "-D is not supported by this build (pure tier); build with --features brotli-c\n";

// ---- NextFile ----

pub(super) const EMPTY_OUTPUT_NAME: &str = "empty output file name for [%s] input file\n";
pub(super) const SUFFIX_MISMATCH: &str = "input file [%s] suffix mismatch\n";

// ---- ProvideInput, WriteOutput ----

pub(super) const READ_INPUT_FAILED: &str = "failed to read input [%s]: %s\n";
pub(super) const WRITE_OUTPUT_FAILED: &str = "failed to write output [%s]: %s\n";

// ---- PrintFileProcessingProgress, PrintBytes ----

pub(super) const PROGRESS_NAME: &str = "[%s]: ";
pub(super) const PROGRESS_ARROW: &str = " -> ";
/// ` in %1.2f sec`, the figure already formatted.
pub(super) const PROGRESS_TIME: &str = " in %s sec";

// ---- CompressFiles, CompressFile, DecompressFiles, InitDecoder ----

pub(super) const OUT_OF_MEMORY: &str = "out of memory\n";
pub(super) const FORCE_OUTPUT_TTY: &str = "Use -h help. Use -f to force output to a terminal.\n";
pub(super) const FORCE_INPUT_TTY: &str = "Use -h help. Use -f to force input from a terminal.\n";
pub(super) const EMIT_METADATA_FAILED: &str = "failed to emit metadata [%s]\n";
pub(super) const COMPRESS_FAILED: &str = "failed to compress data [%s]\n";
pub(super) const COMPRESSED: &str = "Compressed ";
pub(super) const OUTPUT_LARGER: &str = "Output is larger than input\n";

/// `command already set when parsing <what>`.
pub(super) fn command_set(what: &str) -> String {
    format!("command already set when parsing {what}\n")
}

/// `invalid argument -c` (the byte as it came).
pub(super) fn invalid_argument(c: u8) -> Vec<u8> {
    let mut v = b"invalid argument -".to_vec();
    v.push(c);
    v.push(b'\n');
    v
}

pub(super) fn expected_parameter(c: u8) -> Vec<u8> {
    let mut v = b"expected parameter for argument -".to_vec();
    v.push(c);
    v.push(b'\n');
    v
}

/// `<prefix>[<arg>]<suffix>` with the argument's bytes verbatim.
fn bracketed(prefix: &str, arg: &[u8], suffix: &str) -> Vec<u8> {
    let mut v = prefix.as_bytes().to_vec();
    v.extend_from_slice(arg);
    v.extend_from_slice(suffix.as_bytes());
    v
}

pub(super) fn bad_quality(value: &[u8]) -> Vec<u8> {
    bracketed("error parsing quality value [", value, "]\n")
}

pub(super) fn bad_lgwin(value: &[u8]) -> Vec<u8> {
    bracketed("error parsing lgwin value [", value, "]\n")
}

pub(super) fn lgwin_too_small(lgwin: i32) -> String {
    format!("lgwin parameter ({lgwin}) smaller than the minimum ({MIN_WINDOW_BITS})\n")
}

/// `must pass the parameter as --<arg>=value`.
pub(super) fn must_pass_value(arg: &[u8]) -> Vec<u8> {
    bracketed("must pass the parameter as --", arg, "=value\n")
}

/// `invalid parameter: [<arg>]`.
pub(super) fn invalid_parameter(arg: &[u8]) -> Vec<u8> {
    bracketed("invalid parameter: [", arg, "]\n")
}

/// `-V`: `brotli 1.2.1\n`.
pub(super) fn version_line() -> String {
    let (major, minor, patch) = stuffr::brotli_opts::version();
    format!("brotli {major}.{minor}.{patch}\n")
}

/// `PrintHelp`: the usage text for the program called `name`.
pub(super) fn help_text(name: &[u8]) -> Vec<u8> {
    let mut v = b"Usage: ".to_vec();
    v.extend_from_slice(name);
    v.extend_from_slice(b" [OPTION]... [FILE]...\n");
    let rest = format!(
        "Options:
  -#                          compression level (0-9)
  -c, --stdout                write on standard output
  -d, --decompress            decompress
  -f, --force                 force output file overwrite
  -h, --help                  display this help and exit
  -j, --rm                    remove source file(s)
  -s, --squash                remove destination file if larger than source
  -k, --keep                  keep source file(s) (default)
  -n, --no-copy-stat          do not copy source file(s) attributes
  -o FILE, --output=FILE      output file (only if 1 input file)
  -q NUM, --quality=NUM       compression level ({MIN_QUALITY}-{MAX_QUALITY})
  -t, --test                  test compressed file integrity
  -v, --verbose               verbose mode
  -w NUM, --lgwin=NUM         set LZ77 window size (0, {MIN_WINDOW_BITS}-{MAX_WINDOW_BITS})
                              window size = 2**NUM - 16
                              0 lets compressor choose the optimal value
  --large_window=NUM          use incompatible large-window brotli
                              bitstream with window size (0, {MIN_WINDOW_BITS}-{LARGE_MAX_WINDOW_BITS})
                              WARNING: this format is not compatible
                              with brotli RFC 7932 and may not be
                              decodable with regular brotli decoders
  -C B64, --comment=B64       set comment; argument is base64-decoded first;
                              (maximal decoded length: {MAX_COMMENT_LEN})
                              when decoding: check stream comment;
                              when encoding: embed comment (fingerprint)
  -D FILE, --dictionary=FILE  use FILE as raw (LZ77) dictionary
  -K, --concatenated          allows concatenated brotli streams as input
  -S SUF, --suffix=SUF        output file suffix (default:'.br')
  -V, --version               display version and exit
  -Z, --best                  use best compression level (11) (default)
Simple options could be coalesced, i.e. '-9kf' is equivalent to '-9 -k -f'.
With no FILE, or when FILE is -, read standard input.
All arguments after '--' are treated as files.
"
    );
    v.extend_from_slice(rest.as_bytes());
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The recorded help text of the reference, for the name `brotli`.
    #[test]
    fn the_help_text_is_the_references() {
        let want = include_str!("../../../tests/data/brotli/help.txt");
        assert_eq!(String::from_utf8(help_text(b"brotli")).unwrap(), want);
        assert!(help_text(b"unbrotli").starts_with(b"Usage: unbrotli [OPTION]"));
    }

    #[test]
    fn the_version_line_is_the_references() {
        assert_eq!(version_line(), "brotli 1.2.1\n");
    }
}
