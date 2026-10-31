//! The zip family (`zip`, `zipcloak`, `zipnote`, `zipsplit`): stuffr
//! behaving as the platform's Info-ZIP Zip 3.0.
//!
//! **A port** of Info-ZIP Zip 3.0 (July 5th 2008; the Info-ZIP licence,
//! `LICENSE-infozip`: this is an altered version, marked as such by every
//! banner) in two builds, Apple's (`zip-33`, `zip30/`, default on macOS and
//! the BSDs) and Ubuntu's (`3.0-13ubuntu0.2`, default elsewhere), chosen by
//! [`default_flavour`] or `STUFFR_ZIP_FLAVOR=apple|ubuntu` ([`run`] reads
//! it once; anything else in it is refused, exit 1, in stuffr's own
//! words). Each ported function carries `// port: <file>.c:<function>`;
//! Ubuntu's differences are checks in `flavour.rs`, one function per
//! behaviour. Every string is in `messages.rs`.
//!
//! **What is here (Task 4 of 0.19.0):** the names, the flavour, the
//! command lines of all four programs (`cli.rs`: `zip.c`'s option table and
//! `main()`'s loop and checks, `fileio.c`'s `get_option()`, `util.c`'s
//! `envargs()` for `ZIPOPT` and `ZIP`, and the three helpers' own
//! parsing), and every help, licence, version and option-listing screen.
//!
//! **Task 5 (`scan.rs`, `unix.rs`):** which names `zip` operates on: the
//! operands and `-R`, `-i`/`-x`/`-R` patterns, `-r`, `-j`, `-k`, `-D`, `-y`,
//! `-t`/`-tt`, `-@`, duplicates and the archive itself, and `-sf`'s listing
//! (`fileio.c`, `util.c`'s matcher, `unix/unix.c`); also the unix extra
//! fields (`unix::extra_fields`).
//!
//! **Task 6 (`zipup.rs`, `zipfile.rs`, `write.rs`, `sink.rs`):** writing a
//! new archive, byte for byte as the references write it: `zipup.c` (the
//! method, stored or deflated through `stuffr::infozip::ZipDeflater`,
//! `-l`/`-ll`, the
//! descriptor or the rewritten local header), `zipfile.c`'s writing half
//! (local and central headers, Zip64 fields and end records, the end
//! record) and `zip.c:main` from the temporary archive to `finish()`
//! (progress counters and dots, unreadable inputs, `-c`, `-z`, `-m`,
//! `-o`).
//!
//! **Task 7 (`readzip.rs`, `update.rs`):** an archive already at the path:
//! `zipfile.c`'s reading half (`readzipfile`, `scanzipf_regnew`,
//! `readlocal`, `zipcopy`, `bfcopy`), names matched against its entries
//! (`zsearch`, patterns for names not on disk), `-u`, `-f`, `-d`, `-FS`,
//! `-g`, `-U`, `--out`, `-A`, `-J`, `-c`/`-z` over old entries, `-T`/`-TT`
//! (`check_zipfile`), and zip's interrupt handler (INT, TERM, ABRT, BUS,
//! ILL, SEGV: the temporary removed, `Interrupted (aborting)`, exit 9;
//! `host::install_zip_abort`; since ruling T7a of the 2026-10-31 security
//! audit, a signal stuffr sent itself, such as its own `abort()`, and on
//! Linux a real memory fault, removes the temporary and is re-raised, so
//! stuffr's own crash is not reported as an interrupt: deviation 34).
//!
//! **Task 8 (`split.rs`, `fix.rs`, `readzip.rs`):** split archives read
//! (every part through `Host::track`, zip's questions when a part cannot be
//! opened) and written (`-s`, `-sp`, `-sb`, `-sv`: `bfwrite`'s other half,
//! the local header's split kept open for its rewrite, a split archive
//! read and copied split as its first part is); `-F` (`scanzipf_regnew`'s
//! fix mode: the offset of bytes before the archive, damaged central
//! records skipped, a bad entry written over) and `-FF` (`scanzipf_fixnew`:
//! the archive read from its first byte, every local header copied as it
//! is met, a central header found later filling in what only it has).
//!
//! **Task 9 (`ttyio.rs`, `zipcloak.rs`, `zipup.rs`):** encryption (`-P`,
//! `-e`): `crypthead`'s header after each local header (its check the
//! time's, the entry always with a data descriptor), the data encrypted as
//! `zfwrite` encrypts it; the password prompts on the controlling terminal
//! (`getp`, unzip's port, the terminal put back by the interrupt handler
//! too); and `zipcloak` (encrypt, `-d`, `-O`, `-b`), whose messages,
//! warnings and errors are the helpers' (`zipcloak warning:`, `zipcloak
//! error:`, `perror("zipcloak error")`).
//!
//! **Task 10 (`zipnote.rs`, `zipsplit.rs`):** `zipnote` (the comments listed,
//! `-w` rewriting the archive with new comments and names) and `zipsplit`
//! (`-n`, `-r`, `-t`, `-i`, `-p`, `-s`, `-b`: the sequential and the greedy
//! split, the parts and the index written directly under their names), over
//! the shared reader and writer.
//!
//! **Task 11 (`unicode.rs`, `zipup.rs`, `flavour.rs`):** Ubuntu's deltas:
//! `UNICODE_SUPPORT` (bit 11 and the Unicode Path field written and read,
//! `-UN`, `-su`/`-sU`, matching by the Unicode name, the helpers and `-FF`
//! over such entries), `BZIP2_SUPPORT` (`-Z bzip2` through stuffr's bzip2
//! encoder at zip's block size), and the thirteen-patch series (listed in
//! `flavour.rs` with each hook or why it has none).
//!
//! **Zr is `G`:** zip's globals are one value per run (`Zr`, with its
//! options `o`), so a sandboxed run ([`run_in_counted`]) touches nothing of
//! the process.
//!
//! Known deviations (the source of truth; the README and the spec mirror
//! this list):
//!
//! 1. SIGPIPE: [`run`] restores SIGPIPE's default action, as the other
//!    families do; under a parent that ignores SIGPIPE, zip sees `EPIPE`
//!    and stuffr still dies of the signal (the Rust runtime ignores it
//!    before `main`).
//! 2. The banner line of `-v` and the header line of each program's help
//!    name stuffr and say it is altered (Info-ZIP licence clause 3):
//!    `This is Zip 3.0 (July 5th 2008), by stuffr X.Y.Z (altered; original
//!    by Info-ZIP, with modifications by Apple Inc.).` (Ubuntu: `(altered;
//!    Debian's build, original by Info-ZIP)`), likewise `Zip 3.0 (July 5th
//!    2008), by stuffr ... Usage:` and the helpers' `ZipCloak 3.0 (July
//!    5th 2008), by stuffr ...`. `-v`'s `Compiled with` line is the
//!    recorded reference build's (Apple: macOS 27's), so another macOS
//!    build prints a different one.
//! 3. Undefined behaviour and endless loops are not reproduced (the
//!    record's rulings, in the code's `// ruling:` comments); 5 and 6 are
//!    the ones the command line meets.
//! 4. Encryption is compatible, not identical: the ten random bytes of each
//!    12-byte encryption header come from the system's generator
//!    (`getentropy`, `getrandom` or `/dev/urandom`; a system that gives
//!    none ends the run, `Internal logic error`, exit 5), where zip's come
//!    from `rand()` seeded with the time,
//!    so an encrypted entry's header and data differ from the reference's
//!    run to run (every other byte of the archive is the same, and it
//!    decrypts the same).
//! 5. `get_option`'s error text is built in a 50-byte buffer
//!    (`optionerr`'s `char optname[50]`, `sprintf`). An error about an
//!    option whose `'name' (description)` needs 50 bytes or more (`-lf`,
//!    `--output-file`, `--junk-paths=x`, `--recurse-patterns-`: 59 forms in
//!    all, listed by `cli/tests.rs`) aborts both references (Apple: SIGTRAP
//!    from `__sprintf_chk`, Ubuntu: glibc's "buffer overflow detected" and
//!    zip's SIGABRT handler, exit 9). stuffr prints the whole message,
//!    exit 16, as the C would with room.
//! 6. `-O` (`--output-file`) with no archive name at all: the C compares a
//!    NULL `in_path` (`namecmp(in_path, out_path)`) and dies of SIGSEGV,
//!    which zip's handler answers in both builds with a blank line and
//!    `zip error: Interrupted (aborting)`, exit 9. stuffr gives that answer
//!    without the dereference.
//! 7. The "Scanning files" progress message `newname` prints when a scan
//!    of 100 or more names takes over five seconds, with a dot every two
//!    seconds after, is not made (it depends on the clock, not on the
//!    names).
//! 8. A name that is `//host` or `//host/share` and nothing more makes
//!    `ex2in` dereference NULL in both references: SIGSEGV, which zip's
//!    handler answers with a blank line and `Interrupted (aborting)`, exit
//!    9. stuffr gives that answer without the dereference (as for 6), also
//!    for an `-i`/`-x`/`-R` pattern of that shape. The order of two equal
//!    names in the found list follows each libc's `qsort` (Ubuntu's stable
//!    merge sort; Apple's, on macOS, the platform's own `qsort_r`, and off
//!    macOS a BSD quicksort ported in `scan.rs`). Off macOS the port orders
//!    6 of 4000 random arrays with many equal keys differently from macOS
//!    (a known gap: which of two equal names is dropped, when the same
//!    operand is given twice among many).
//! 9. `-c` or `-z` after `-@` (or with zip as a filter) read standard error
//!    (`fdopen(fileno(stderr), "r")`). When it is not open for reading (a
//!    pipe, a file opened to write) `fdopen` fails and the C's `fgets(NULL)`
//!    dies of SIGSEGV in both references, which zip's handler answers with
//!    a blank line and `Interrupted (aborting)`, exit 9, the temporary
//!    removed. stuffr gives that answer without the dereference (as 6 and
//!    8), at the first question, and a sandbox's standard error is never
//!    readable.
//! 10. A `-c` or `-z` line is cut at its first NUL, as the C's `strlen` and
//!     `strcpy` cut it; a line that BEGINS with a NUL makes the C read the
//!     byte before its buffer (`p[k-1]`, `e[r-1]` with a length of 0).
//!     stuffr takes it for an empty line.
//! 11. A symbolic link stored under `-y` that is removed between zip's
//!     `stat` and its `readlink` makes the C pass `readlink`'s -1 on as a
//!     length to `crc32` and `zfwrite`. stuffr stores the link with no
//!     text (0 bytes, CRC 0), exit 0.
//! 12. A write to the archive that fails is answered where and as zip's
//!     stdio stream answers it (`zipup.rs`, `sink.rs`; measured under
//!     `ulimit -f` on both references). Two Ubuntu answers are not
//!     reproduced: when only `fclose` meets the failure, Ubuntu's `ziperr`
//!     closes the stream a second time and glibc aborts on the double free
//!     (exit 5, the temporary left; undefined behaviour, as ruling Z3's);
//!     stuffr answers as Apple does ("Temporary file failure", exit 10, the
//!     temporary removed). And the `zip I/O error:` line of "unexpected
//!     error on zip file" shows whatever `errno` glibc's later calls left
//!     (`No such file or directory` from the time zone lookup in a
//!     container without tzdata); stuffr shows the write's own error, as
//!     Apple does.
//! 13. Reading an archive, undefined behaviour of the C is not reproduced:
//!     an end record or Zip64 record cut short is read as zeros (the C reads
//!     its uninitialised stack buffer: Apple, for an archive that is only
//!     `PK\5\6`, answers "cannot update a split archive"; stuffr sees an
//!     empty archive); a Zip64 extra field shorter than the sizes it should
//!     hold is read as zeros past its end; `-X-` stops copying old extra
//!     blocks at one that runs past its field. And `-g` (grow) writes a copy
//!     of the archive up to its central directory, appends, adds whatever
//!     the old file had past the new end (zip writes in place and never
//!     truncates, so a shorter `-z` comment leaves the old tail), and
//!     renames the copy into place: the bytes of a successful run are
//!     zip's. Except under `--out` (ruling Z33): zip opens the `--out` file
//!     with `FOPW` (truncating it to nothing), grows the input archive in
//!     place and skips `replace`, so `zip -g in.zip --out out.zip f` leaves
//!     `out.zip` empty and `in.zip` grown; stuffr leaves `in.zip` untouched
//!     and publishes the grown copy as `out.zip` (pinned by
//!     `update::tests::growing_with_out_publishes_the_copy`). A failure
//!     leaves the archive as it was: zip prints
//!     `attempting to restore <zip> to its previous state` (so does
//!     stuffr, on every failure and interrupt under `-g`) and rewrites the
//!     old central directory in place, leaving what it appended after it
//!     (a write failure there can even leave no readable archive). A
//!     failed `-T -g` is undefined behaviour in the C (`fseeko` on the
//!     closed stream: Apple exits 5 after a blank line); stuffr answers
//!     with the restore line, exit 8. `-T -g` tests the copy, so a `-TT`
//!     command is given the temporary's name, not the archive's.
//! 14. zip opens the output to check that it can write it with `fopen
//!     "wb"` (truncating it) when it is `--out`'s or the archive has no
//!     entries, and then removes an archive without entries; stuffr opens
//!     it without truncating and removes nothing it did not create. So a
//!     run that fails or is interrupted leaves an `--out` target or an
//!     entry-less archive as it was (zip leaves the first empty and the
//!     second gone). And on success, an entry-less archive that is a
//!     symbolic or hard link: zip, having removed the link, renames a new
//!     file into its place (the link's target left empty); stuffr writes
//!     through the link, as `replace` does for any linked archive. Pinned by
//!     `update::tests::a_failed_run_leaves_the_output_as_it_was`.
//! 15. Ruling Z3: a failing `-T` in Ubuntu's build closes the temporary's
//!     stream twice (`ziperr` after `fclose(y)`) and glibc aborts on the
//!     double free (exit 5, a blank line, glibc's message); stuffr answers
//!     as Apple's build does in both flavours: `test of t.zip FAILED`, `zip
//!     error: Zip file invalid, could not spawn unzip, or wrong unzip
//!     (original files unmodified)`, exit 8, the temporary removed.
//! 16. A sandboxed run ([`run_in`]) spawns no `unzip` and no `-TT`
//!     command: `-T` fails there as without an `unzip` on `PATH`. The
//!     interrupt handler writes `Interrupted (aborting)` to `mesg` only; a
//!     `-lf` log does not get it.
//! 17. Ruling Z16: `-sf -m` (`--show-files` with move) lists and ends
//!     without writing an archive, and zip's `finish()` then deletes the
//!     files of the entries the names marked, though nothing holds them.
//!     stuffr deletes nothing after `-sf`.
//! 18. Ruling Z5: zip reads the answers to its questions about split parts
//!     with `fgets` and never looks at what it returns. At the end of
//!     standard input its buffer keeps what it held (uninitialised at the
//!     first question), and `-FF` (both builds; also `-F` and a copy of a
//!     split archive whose part is missing) asks again for ever, gigabytes
//!     of prompts; so does Ubuntu's `-sp`. stuffr never loops: the end of
//!     standard input at a question about a part to READ answers `q`
//!     (abort: as an explicit `q`, measured on both references: `-FF` goes
//!     on and writes what it has, `could not find split` and exit 0 when
//!     the part was the one to scan, `Interrupted (Could not find split)`,
//!     exit 9, when an entry was being copied), and at `-sp`'s question
//!     about where to WRITE the next split it answers ENTER (that question
//!     has no way out but an interrupt; ENTER is what Apple's build does).
//! 19. `-FF`, undefined behaviour of the C, not reproduced: the central
//!     extra field of an entry `-FF` found by its local header is the local
//!     one copied with `strcpy`, which stops at the first NUL (almost always
//!     the second byte of the first block's size) and leaves the rest of
//!     the `malloc`ed field as it was: zeros on Apple, heap garbage that
//!     changes from run to run on Ubuntu. stuffr copies up to and with the
//!     first NUL and writes zeros after it (Apple's bytes). The entry's
//!     `lflg`, never set, is read as 0 (it only sizes `tempzn`); a data
//!     descriptor signature split across two 16 KiB reads (the C then
//!     writes `kk - 3`, wrapped, bytes) is not taken for one; a Zip64 extra
//!     field shorter than its sizes is read as zeros past its end.
//! 20. Ruling Z21: `-F`/`-FF` whose `--out` is the damaged archive under
//!     another name (`./a.zip`, a hard or symbolic link to it) is refused
//!     as the same name is (`--out path must be different than in path`,
//!     exit 16), before anything is written: zip compares the names only
//!     and renames its lossy salvage over the archive it salvaged from.
//! 21. Ruling Z23: when what did not fit in a split cannot be written to
//!     the next one ("Not enough room on disk"), `-sp` (`split_method` 2)
//!     lets the user choose another disk and opens another split, for ever
//!     on a full disk; stuffr warns as `-sp` does and ends with `-s`'s
//!     answer, `zip error: Output file write failure (Not enough room on
//!     disk)`, exit 14.
//! 22. Ruling Z24: `-sp` with an archive name that has no directory: zip
//!     takes the name part as empty, so an answer (a directory, a bare
//!     name) makes the next split's name from a name shorter than `zip`
//!     and indexes before its buffer. stuffr takes such a name as one in
//!     the current directory: `zip -s 64k -sp t.zip big` answered `o/`
//!     writes `t.z01` here, then `o/t.z02`, ..., `o/t.zip`.
//! 23. Ruling Z25: `-z` whose first comment line is empty copies `\r\n`
//!     into a one-byte block (`strcpy(p, "\r\n")`): Ubuntu's build dies in
//!     glibc's buffer-overflow check (exit 9 through zip's SIGABRT
//!     handler); Apple's writes the comment. stuffr writes it in both
//!     flavours, as Apple's build does.
//! 24. `zipcloak` (crypt.c's `zipcloak()` and `zipbare()`) ignores
//!     `readlocal()`'s failure (a local header that cannot be found or
//!     read) and goes on with an uninitialised local header; stuffr ends the
//!     run there with that failure's code (`zipcloak error: ... (was
//!     encrypting an entry)` or `(was decrypting an entry)`), the temporary
//!     removed and the archive untouched. A split archive under `-O` meets
//!     it at its first entry: zipcloak's `readlocal()` (the UTIL build's)
//!     looks for every entry in the last part only, warns `Did not find
//!     entry for <name>`, and Ubuntu's build then dies of SIGSEGV
//!     (`Interrupted (aborting)`, exit 9, or killed by the signal from its
//!     handler; measured with a terminal in Docker); stuffr warns the same
//!     and ends with `Zip file structure invalid`, exit 3. (Without `-O` both
//!     refuse a split archive: `cannot update a split archive`, exit 16.)
//!     A central name longer than the local one makes `readlocal()` write
//!     past the local name's buffer;
//!     stuffr keeps the local name as it is (a shorter central name cuts it
//!     with a NUL, as the C does).
//! 25. `zipnote` and `zipsplit` never set `out_path`, so `readzipfile()`'s
//!     `strcmp(in_path, out_path)` over a NULL ends in SIGSEGV for an
//!     archive that does not exist (or is named ``) and for a split archive
//!     (a `.zip` that says it is one of several): both references' handler
//!     prints `Interrupted (aborting)` and exits 9. stuffr answers the same
//!     (`readzip::null_out_crash`); the signal is not raised.
//! 26. Ruling Z4: Apple's `zipnote -w` closes the input stream twice (the
//!     second `fclose` closes the temporary's) and always fails, exit 10,
//!     `Bad file descriptor` then `Temporary file failure`, with the
//!     archive untouched. That is undefined behaviour; stuffr takes Ubuntu's
//!     patched answer (patch 07) in both flavours: `-w` works. Pinned by
//!     `compat_zip_helpers::zipnote_w_is_the_same_in_both_flavours`
//!     (stuffr's two flavours agree and exit 0) and, on Ubuntu, against the
//!     reference. A comment's length wraps at 65536 as the C's `ush` does.
//! 27. `zipsplit`: a `%` in the archive's name is a conversion in the C's
//!     name template (`sprintf(name, template, n)`, undefined behaviour);
//!     stuffr takes it as a character. After an error writing the index
//!     under `-p` and a yes to "redo entire disk?", the C goes back to the
//!     wrong disk (its
//!     loop variable holds the failure flag); stuffr redoes disk 1. An
//!     interrupt removes the parts only when `-b`'s directory is shorter
//!     than half of `PATH_MAX` (the handler's static holds that much;
//!     longer arms nothing and the parts stay).
//! 28. Ubuntu's `UNICODE_SUPPORT` (`unicode.rs`), undefined behaviour of the
//!     C not reproduced. Where a conversion fails and the C reads through
//!     the NULL it got (a bit-11 name zip's UTF-8 decoder refuses; a
//!     Unicode Path field whose UTF-8 name it refuses; `-UN escape` over a
//!     found name the locale cannot convert) or copies the entry's
//!     not-yet-set name (a Unicode Path field with no name, read from the
//!     central directory or by `readlocal`), the reference dies of SIGSEGV
//!     and its handler answers `Interrupted (aborting)`, exit 9; stuffr
//!     gives that answer without the crash (`unicode::segv`), as rulings
//!     Z10/Z13 do. A Unicode Path field shorter than its header says is
//!     read as zeros past its end (the C reads past it); an old field of
//!     another length than the new one is taken out and the new one
//!     appended (the C's copy of what follows it runs four bytes long).
//!     Patch 12 (`mbstowcs` told the buffer holds `strlen + 1` wide
//!     characters, which glibc's fortify takes for an overflow and aborts
//!     on, for every name that is not ASCII) and patch 13 (`-TT`'s command
//!     buffer one byte short) are Ubuntu's own fixes: both flavours take the
//!     patched, defined behaviour (Apple has neither code path). Pinned,
//!     stuffr-only, by `compat_zip_common::ub_rulings`; the crash answers
//!     are also compared with the reference (`compat_zip_ubuntu`).
//! 29. `-Z bzip2` (Ubuntu): zipup.c tests whether an entry is text over the
//!     whole 16 KiB input buffer, past the bytes read, and the buffer is
//!     allocated once per run and never cleared, so the test sees what an
//!     earlier entry left there (reproduced: a short text file after a
//!     longer text file is text). The block's first contents are
//!     uninitialised in the C; stuffr takes them as zeros (a short first
//!     text file is binary, `iattr` 0, as measured). Pinned by
//!     `compat_zip_common::ub_rulings`.
//! 30. Ruling Z32: an interrupt (SIGINT, SIGTERM) while the new archive
//!     replaces the old one (`fileio.c:replace`: the archive unlinked, then
//!     the temporary renamed; or, for a linked archive or a temporary on
//!     another device such as `-b`'s, the archive truncated and the
//!     temporary copied into it) makes zip's handler remove the temporary,
//!     which leaves the archive gone or cut short and no whole copy
//!     anywhere. stuffr holds both signals back for the length of the
//!     replace (`zip`, its split parts and `-F`/`-FF`, `zipcloak`, `zipnote
//!     -w`; `-g`'s restore state is cleared in the same window) and answers
//!     them as zip does once the archive is whole: `Interrupted
//!     (aborting)`, exit 9, the new archive in place. A long cross-device
//!     copy answers Ctrl-C when it ends. When the replace fails after the
//!     archive was unlinked or cut (ruling Z34), the temporary is the only
//!     whole copy: it is kept under its own name, where zip's handler would
//!     remove it. Pinned by
//!     `tests::an_interrupt_during_replace_leaves_a_whole_archive` and
//!     `tests::an_interrupt_after_a_failed_replace_keeps_the_temporary`.
//! 31. Hardening (ruling T5 of the 2026-10-31 security audit): a symbolic
//!     link at the archive's name that leads to no regular file (dangling,
//!     or naming a directory or a device) is refused before any work: `zip
//!     I/O error: Too many levels of symbolic links`, `zip error: Could not
//!     create output file (NAME)`, exit 15, the link kept, no temporary
//!     left. Info-ZIP follows it (`fopen`, then `fileio.c:replace`'s copy
//!     for a symlinked archive), creating the file a dangling link names.
//!     A link to an existing regular file is still updated through it, as
//!     Info-ZIP updates it (`replace`'s copy), and `replace` itself refuses
//!     a link that has gone dangling by then. `zipcloak`, `zipnote -w` and
//!     `-F`/`-FF` share `replace`'s check. Why: a planted link must not
//!     redirect where the archive is written.
//! 32. Hardening (ruling T5): `zipsplit` opens its index and each part
//!     `O_NOFOLLOW`. zipsplit truncates whatever is at the name
//!     (`fopen(.., "w")`), writing through a symlink there, live or
//!     dangling; stuffr fails the open (`zipsplit error: Too many levels of
//!     symbolic links`, `Could not create output file (NAME)`, exit 15) and
//!     its cleanup leaves the link, which it did not make. A regular file
//!     at a part's name is still truncated, as zipsplit truncates it.
//! 33. Hardening (ruling T6 of the 2026-10-31 security audit): the `-lf`
//!     log's command line shows `-P`'s password as `********` (eight
//!     asterisks, whatever its length), in every form zip accepts (`-P pw`,
//!     `-Ppw`, `-P=pw`, `-qPpw`, `--password pw`, `--password=pw` and its
//!     abbreviations, from `ZIPOPT`/`ZIP` too); zip writes it as given. A
//!     new log is created 0600 (zip: `0666 & ~umask`), an existing one
//!     keeps its mode, and the log, `-la`'s included, is opened
//!     `O_NOFOLLOW`: a symlink at its name, live or dangling, is `could not
//!     open logfile`, exit 16, where zip writes through it. `-sc`'s listing
//!     still shows the password, as zip's does (it goes to the terminal,
//!     not to a file). zip and zipcloak keep the password, given or typed,
//!     only in a holder that zeroes it when dropped (ruling T6b); the
//!     process's own arguments, and the parser's copies of them (which
//!     `-sc` and `-R`'s hint print), are not zeroed.
//! 34. Hardening (ruling T7a of the 2026-10-31 security audit): zip's
//!     handler answers every INT, TERM, ABRT, BUS, ILL and SEGV with
//!     `Interrupted (aborting)`, exit 9. stuffr's answers a signal it sent
//!     itself (its own `abort()`: a double panic, an allocation failure, a
//!     corrupted heap) and, on Linux, a SEGV, BUS or ILL the kernel raised
//!     for a real fault by removing the temporary (and zipsplit's parts)
//!     and dying of the signal at its default action, without the line: a
//!     crash in stuffr stays a crash. A signal another process sends
//!     (`kill -SEGV` too) keeps zip's answer. On macOS, which reports a
//!     `kill -SEGV`/`-BUS`/`-ILL` exactly as a fault, a real fault still
//!     answers as zip does. A stack overflow dies of the signal with no
//!     message (the handler has no stack to run on).

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use super::CountedRun;
use super::host::{self, Host, SANDBOX_OUTPUT_CAP, Sandbox};

pub(crate) mod cli;
pub(crate) mod fix;
pub(crate) mod flavour;
mod messages;
pub(crate) mod readzip;
pub(crate) mod scan;
pub(crate) mod sink;
pub(crate) mod split;
pub(crate) mod ttyio;
pub(crate) mod unicode;
pub(crate) mod unix;
pub(crate) mod update;
pub(crate) mod write;
pub(crate) mod zipcloak;
pub(crate) mod zipfile;
pub(crate) mod zipnote;
pub(crate) mod zipsplit;
pub(crate) mod zipup;

pub use flavour::Flavour;
use messages::{self as m, printf};

/// The environment variable that overrides [`default_flavour`].
const FLAVOR_VAR: &str = "STUFFR_ZIP_FLAVOR";

/// The exit codes the family can return (`ziperr.h`, the plan's Global
/// Constraints), for the `compat` fuzz target.
#[doc(hidden)]
pub const EXIT_CODES: &[i32] = &[
    0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 19,
];

/// How a run ends: the exit code (`ziperr()`'s, `EXIT()`'s, or a screen
/// asked for with exit 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exit {
    pub code: i32,
}

/// The flavour a build uses when `STUFFR_ZIP_FLAVOR` is unset or empty:
/// Apple on macOS and the BSDs, Ubuntu everywhere else, Windows included.
pub fn default_flavour() -> Flavour {
    if cfg!(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )) {
        Flavour::Apple
    } else {
        Flavour::Ubuntu
    }
}

/// The flavour `STUFFR_ZIP_FLAVOR`'s value selects: `apple` or `ubuntu`,
/// the default when unset or empty, and `Err(value)` for anything else.
pub(crate) fn flavour_from(value: Option<OsString>) -> Result<Flavour, OsString> {
    match value {
        None => Ok(default_flavour()),
        Some(v) if v.is_empty() => Ok(default_flavour()),
        Some(v) if v == "apple" => Ok(Flavour::Apple),
        Some(v) if v == "ubuntu" => Ok(Flavour::Ubuntu),
        Some(v) => Err(v),
    }
}

/// One run's state: zip's globals (`noisy`, `mesg`, `zipfile` and the
/// rest are in `o` and here), the message layer and the host.
pub(crate) struct Zr<'a> {
    /// The process, or a sandbox's stand-ins for it.
    pub(crate) host: Host,
    /// Which reference this run behaves as.
    pub(crate) flavour: Flavour,
    /// `getenv`: the process's environment, or a sandbox's stand-in.
    pub(crate) env: &'a dyn Fn(&str) -> Option<OsString>,
    /// Standard output, flushed after every message.
    pub(crate) out: BufWriter<Box<dyn Write + Send>>,
    /// Standard error.
    pub(crate) err: &'a mut dyn Write,
    /// The options (zip.c's globals; the helpers read `noisy` here too).
    pub(crate) o: cli::Options,
    /// `mesg` is standard error (the archive goes to standard output, or a
    /// helper keeps standard output for data).
    pub(crate) mesg_err: bool,
    /// `mesg_line_started`: a message began a line it has not ended.
    pub(crate) mesg_line_started: bool,
    /// The log file (`-lf`), once opened.
    pub(crate) log: Option<Box<dyn Write>>,
    /// `logfile_line_started`
    pub(crate) log_line_started: bool,
    /// `seen_doubledash`: the first `--` was met.
    pub(crate) seen_doubledash: bool,
    /// The program, as `ziperr` of a helper names it.
    pub(crate) program: &'static str,
    /// `-g` is writing (zip.c's `tempzip == zipfile`): `ziperr` then says
    /// it is restoring this archive.
    pub(crate) restoring: Option<Vec<u8>>,
    /// zip's `current_in_disk`: the part of a split archive being read.
    pub(crate) current_in_disk: u64,
    /// zip's `total_disks`: the parts of the archive being read.
    pub(crate) total_disks: u64,
    /// zip's `skip_this_disk`: 1 + the part `-F` was told to skip (0: none).
    pub(crate) skip_this_disk: u64,
    /// Standard input as zip's prompts read it (`fgets(..., stdin)`: one
    /// stdio stream for every prompt of the run), once first asked for.
    pub(crate) prompt: Option<split::Prompt>,
    /// `mesg_line_started`, shared with the split writer, which writes its
    /// questions itself.
    pub(crate) line_cell: std::rc::Rc<std::cell::Cell<bool>>,
    /// zip's `using_utf8` (Ubuntu's `UNICODE_SUPPORT`): `en_US.UTF-8`
    /// loads, so names convert as UTF-8 and new ones get bit 11
    /// (`unicode::utf8_locale`); always false for Apple.
    pub(crate) using_utf8: bool,
}

impl<'a> Zr<'a> {
    pub(crate) fn new(
        host: Host,
        flavour: Flavour,
        program: &'static str,
        env: &'a dyn Fn(&str) -> Option<OsString>,
        err: &'a mut dyn Write,
    ) -> Zr<'a> {
        let out = host.out_writer(None);
        let using_utf8 = flavour::unicode_support(flavour) && unicode::utf8_locale(&host);
        Zr {
            host,
            flavour,
            env,
            out,
            err,
            o: cli::Options::new(),
            mesg_err: false,
            mesg_line_started: false,
            log: None,
            log_line_started: false,
            seen_doubledash: false,
            program,
            restoring: None,
            current_in_disk: 0,
            total_disks: 1,
            skip_this_disk: 0,
            prompt: None,
            line_cell: std::rc::Rc::new(std::cell::Cell::new(false)),
            using_utf8,
        }
    }

    /// What putlocal/putcentral need of `UNICODE_SUPPORT` (Ubuntu only):
    /// `using_utf8` and `-UN UTF8`.
    pub(crate) fn unicode_out(&self) -> Option<(bool, bool)> {
        flavour::unicode_support(self.flavour).then_some((self.using_utf8, self.o.utf8_force))
    }

    /// `mesg_line_started = v`, mirrored for the interrupt handler (which
    /// prints a newline first when a line was started).
    pub(crate) fn set_line(&mut self, v: bool) {
        self.mesg_line_started = v;
        self.line_cell.set(v);
        host::zip_mesg_state(&self.host, self.mesg_err, v);
    }

    /// Text written to standard output directly (`printf`, `puts`).
    pub(crate) fn stdout_write(&mut self, b: &[u8]) {
        let _ = self.out.write_all(b);
        let _ = self.out.flush();
    }

    /// Text written to `mesg` (`fprintf(mesg, ...)` + `fflush`).
    pub(crate) fn mesg_write(&mut self, b: &[u8]) {
        if self.mesg_err {
            let _ = self.err.write_all(b);
            let _ = self.err.flush();
        } else {
            self.stdout_write(b);
        }
    }

    /// Text written to the log file, when there is one.
    pub(crate) fn log_write(&mut self, b: &[u8]) {
        // A sandbox charges the log's bytes to the output budget, like any
        // other file; a write the budget cannot hold is lost, as a failed
        // `fprintf` to the log is (its result is never looked at).
        if let Host::Sandbox(s) = &self.host
            && self.log.is_some()
            && crate::compat::host::take(&s.budget, b.len() as u64).is_err()
        {
            return;
        }
        if let Some(l) = self.log.as_mut() {
            let _ = l.write_all(b);
            let _ = l.flush();
        }
    }

    /// zip.c:zipwarn: `\tzip warning: a b` to `mesg` (when noisy) and to
    /// the log.
    pub(crate) fn zipwarn(&mut self, a: &[u8], b: &[u8]) {
        if self.program != "zip" {
            // the helpers' zipwarn: `zipcloak warning: a b`, always
            let mut line = Vec::new();
            printf(
                &mut line,
                m::HELPER_WARNING,
                &[self.program.as_bytes(), a, b],
            );
            self.mesg_write(&line);
            return;
        }
        let mut line = Vec::new();
        printf(&mut line, m::ZIP_WARNING, &[a, b]);
        if self.o.noisy {
            if self.mesg_line_started {
                self.mesg_write(b"\n");
            }
            self.mesg_write(&line);
            self.set_line(false);
        }
        if self.log.is_some() {
            if self.log_line_started {
                self.log_write(b"\n");
            }
            self.log_write(&line);
            self.log_line_started = false;
        }
    }

    /// zip.c:zipmessage: `a` and `b` as one line to `mesg` (when noisy) and
    /// the log.
    pub(crate) fn zipmessage(&mut self, a: &[u8], b: &[u8]) {
        let mut line = a.to_vec();
        line.extend_from_slice(b);
        line.push(b'\n');
        if self.o.noisy {
            if self.mesg_line_started {
                self.mesg_write(b"\n");
            }
            self.mesg_write(&line);
            self.set_line(false);
        }
        if self.log.is_some() {
            if self.log_line_started {
                self.log_write(b"\n");
            }
            self.log_write(&line);
            self.log_line_started = false;
        }
    }

    /// zip.c:zipmessage_nl: `a` to `mesg` (when noisy) and the log, then,
    /// with `nl`, a newline if a line was started.
    // port: zip.c:zipmessage_nl
    pub(crate) fn zipmessage_nl(&mut self, a: &[u8], nl: bool) {
        if self.o.noisy {
            if !a.is_empty() {
                self.mesg_write(a);
                self.set_line(true);
            }
            if nl && self.mesg_line_started {
                self.mesg_write(b"\n");
                self.set_line(false);
            }
        }
        if self.log.is_some() {
            if !a.is_empty() {
                self.log_write(a);
                self.log_line_started = true;
            }
            if nl && self.log_line_started {
                self.log_write(b"\n");
                self.log_line_started = false;
            }
        }
    }

    /// zip.c:ziperr: the message for `code` and `h`, to `mesg` and the log;
    /// the exit it ends the run with is returned.
    // port: zip.c:ziperr
    pub(crate) fn ziperr(&mut self, code: i32, h: &[u8]) -> Exit {
        self.ziperr_with(code, h, None)
    }

    /// [`Zr::ziperr`] for a code whose message also says why the system
    /// refused (`ZE_S_PERR`: `zip I/O error: <strerror>`).
    pub(crate) fn ziperr_os(&mut self, code: i32, h: &[u8], e: &io::Error) -> Exit {
        self.ziperr_with(code, h, Some(host::strerror(e)))
    }

    fn ziperr_with(&mut self, code: i32, h: &[u8], why: Option<Vec<u8>>) -> Exit {
        if self.program != "zip" {
            // the helpers' ziperr: `perror("zipcloak error")`, then the line
            if let Some(why) = &why {
                let mut l = Vec::new();
                printf(&mut l, m::HELPER_PERROR, &[self.program.as_bytes(), why]);
                let _ = self.err.write_all(&l);
                let _ = self.err.flush();
            }
            return self.helper_err(code, h);
        }
        if self.mesg_line_started {
            self.mesg_write(b"\n");
            self.set_line(false);
        }
        if self.log.is_some() && self.log_line_started {
            self.log_write(b"\n");
            self.log_line_started = false;
        }
        let text = usize::try_from(code)
            .ok()
            .and_then(|c| m::ZIPERRORS.get(c))
            .copied()
            .unwrap_or("");
        let mut line = Vec::new();
        printf(&mut line, m::ZIP_ERROR, &[text.as_bytes(), h]);
        let mut io_line = Vec::new();
        if let Some(why) = &why {
            printf(&mut io_line, m::ZIP_IO_ERROR, &[why]);
            self.mesg_write(&io_line);
        }
        self.mesg_write(&line);
        if self.log.is_some() {
            if why.is_some() {
                io_line.push(b'\n');
                self.log_write(&io_line);
            }
            self.log_write(&line);
            self.log_line_started = false;
        }
        if let Some(name) = self.restoring.take() {
            // -g: the C rewrites the old central directory in place;
            // stuffr's archive was never touched (deviation 13)
            let mut l = Vec::new();
            printf(&mut l, m::ATTEMPTING_RESTORE, &[&name]);
            self.mesg_write(&l);
            self.log_write(&l);
        }
        Exit { code }
    }

    /// The helpers' `ziperr` (`zipcloak error: text (h)`, to `mesg`).
    pub(crate) fn helper_err(&mut self, code: i32, h: &[u8]) -> Exit {
        let text = usize::try_from(code)
            .ok()
            .and_then(|c| m::ZIPERRORS.get(c))
            .copied()
            .unwrap_or("");
        let mut line = Vec::new();
        printf(
            &mut line,
            m::HELPER_ERROR,
            &[self.program.as_bytes(), text.as_bytes(), h],
        );
        self.mesg_write(&line);
        Exit { code }
    }
}

/// A broken-down local time (`struct tm`, the fields zip reads).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tm {
    /// The full year (`tm_year + 1900`).
    pub(crate) year: i64,
    /// 0 to 11.
    pub(crate) mon: u32,
    pub(crate) mday: u32,
    pub(crate) hour: u32,
    pub(crate) min: u32,
    pub(crate) sec: u32,
    /// 0 is Sunday.
    pub(crate) wday: u32,
}

/// `localtime(&t)`: the process's zone under `Host::Real` on unix, UTC for a
/// sandbox (and for any other target).
pub(crate) fn localtime(host: &Host, t: i64) -> Tm {
    #[cfg(unix)]
    if matches!(host, Host::Real) {
        // SAFETY: `tm` is plain data that a successful `localtime_r` fills
        // in whole; both pointers are valid for the call.
        let tt = t as libc::time_t;
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        if !unsafe { libc::localtime_r(&tt, &mut tm) }.is_null() {
            return Tm {
                year: i64::from(tm.tm_year) + 1900,
                mon: tm.tm_mon as u32 % 12,
                mday: tm.tm_mday as u32,
                hour: tm.tm_hour as u32,
                min: tm.tm_min as u32,
                sec: tm.tm_sec as u32,
                wday: tm.tm_wday as u32 % 7,
            };
        }
    }
    let _ = host;
    // UTC, from the civil calendar
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if mo <= 2 { y + 1 } else { y };
    Tm {
        year,
        mon: (mo - 1) as u32,
        mday: d as u32,
        hour: (secs / 3600) as u32,
        min: (secs / 60 % 60) as u32,
        sec: (secs % 60) as u32,
        wday: ((days + 4).rem_euclid(7)) as u32,
    }
}

/// `asctime(localtime(t))` with its newline: `Sun Sep 16 01:03:52 1973\n`.
/// A sandbox's zone is UTC; so is any other target's.
pub(crate) fn asctime(host: &Host, t: i64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let tm = localtime(host, t);
    format!(
        "{} {} {:2} {:02}:{:02}:{:02} {}\n",
        DAYS[tm.wday as usize], MONTHS[tm.mon as usize], tm.mday, tm.hour, tm.min, tm.sec, tm.year
    )
}

/// The current time as [`asctime`] shows it.
pub(crate) fn asctime_now(z: &Zr) -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    asctime(&z.host, t)
}

/// Entry point for `zip`, `zipcloak`, `zipnote` and `zipsplit`; `name` is
/// the canonical invoked name, `argv0` the program as invoked (`-sc` shows
/// it) and `args` the arguments after it.
pub fn run(name: &'static str, argv0: &OsStr, args: Vec<OsString>) -> ExitCode {
    // Deviation 1: as the other families.
    host::reset_sigpipe();
    let env = |k: &str| std::env::var_os(k);
    let mut err = io::stderr();
    let flavour = match flavour_from(env(FLAVOR_VAR)) {
        Ok(f) => f,
        Err(v) => {
            printf(
                &mut err,
                m::FLAVOR_REFUSED,
                &[name.as_bytes(), v.as_encoded_bytes()],
            );
            return ExitCode::from(1);
        }
    };
    let argv0 = if argv0.is_empty() {
        name.as_bytes()
    } else {
        argv0.as_encoded_bytes()
    };
    let code = main(flavour, name, argv0, &args, &env, Host::Real, &mut err);
    // The exit status is the code's low byte, as `exit()` makes it (every
    // code here is below 256).
    ExitCode::from(code as u8)
}

/// [`run`] without the process: operands resolve against `dir`, standard
/// input is `stdin` (a pipe of bytes), standard output and error are
/// captured and returned with the exit code, neither is a terminal, the
/// environment is not read (`ZIP` and `ZIPOPT` are unset;
/// `STUFFR_ZIP_FLAVOR` is not consulted), no signal is touched, and
/// standard output and output files share the sandbox's output budget.
/// For the fuzz target and the tests; not a stable interface.
#[doc(hidden)]
pub fn run_in(
    dir: &Path,
    name: &str,
    args: Vec<OsString>,
    stdin: &[u8],
    flavour: Flavour,
) -> (i32, Vec<u8>, Vec<u8>) {
    let (code, out, err, _) = run_in_counted(flavour, dir, name, &args, stdin);
    (code, out, err)
}

/// [`run_in`] in the shape the other families' sandboxed entries have, also
/// returning what each input read (empty until a task counts them).
#[doc(hidden)]
pub fn run_in_counted(
    flavour: Flavour,
    dir: &Path,
    name: &str,
    args: &[OsString],
    stdin: &[u8],
) -> CountedRun {
    let name: &'static str = match name {
        "zipcloak" => "zipcloak",
        "zipnote" => "zipnote",
        "zipsplit" => "zipsplit",
        _ => "zip",
    };
    let stdout = Arc::new(Mutex::new(Vec::new()));
    let reads = Arc::new(Mutex::new(BTreeMap::new()));
    let host = Host::Sandbox(Sandbox {
        dir: dir.to_path_buf(),
        stdin: Some(stdin.to_vec()),
        stdout: stdout.clone(),
        budget: Arc::new(AtomicU64::new(SANDBOX_OUTPUT_CAP)),
        reads: reads.clone(),
    });
    let mut err = Vec::new();
    let env = |_: &str| None;
    let code = main(flavour, name, name.as_bytes(), args, &env, host, &mut err);
    let out = std::mem::take(&mut *stdout.lock().unwrap_or_else(|p| p.into_inner()));
    let reads = std::mem::take(&mut *reads.lock().unwrap_or_else(|p| p.into_inner()));
    (code, out, err, reads)
}

/// The run below the process boundary. Returns the exit code.
fn main(
    flavour: Flavour,
    name: &'static str,
    argv0: &[u8],
    args: &[OsString],
    env: &dyn Fn(&str) -> Option<OsString>,
    host: Host,
    err: &mut dyn Write,
) -> i32 {
    let mut z = Zr::new(host, flavour, name, env, err);
    let args: Vec<Vec<u8>> = args.iter().map(|a| a.as_encoded_bytes().to_vec()).collect();
    if name == "zipcloak" {
        let code = match cli::parse_cloak(&mut z, argv0, &args) {
            Err(Exit { code }) => code,
            Ok(o) => zipcloak::run(&mut z, o).code,
        };
        let _ = z.out.flush();
        return code;
    }
    if name == "zipnote" {
        let code = match cli::parse_note(&mut z, &args) {
            Err(Exit { code }) => code,
            Ok(o) => zipnote::run(&mut z, o).code,
        };
        let _ = z.out.flush();
        return code;
    }
    if name == "zipsplit" {
        let code = match cli::parse_split(&mut z, &args) {
            Err(Exit { code }) => code,
            Ok(o) => zipsplit::run(&mut z, o).code,
        };
        let _ = z.out.flush();
        return code;
    }
    let code = match cli::parse_zip(&mut z, argv0, &args) {
        Err(Exit { code }) => code,
        // A `zip` command line the checks accepted: the names and the archive.
        Ok(()) => scan::run(&mut z).code,
    };
    let _ = z.out.flush();
    code
}

#[cfg(test)]
mod tests;
