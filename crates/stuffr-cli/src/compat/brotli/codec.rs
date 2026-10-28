//! Compression, and the decompression loop's file handling, ported from
//! `c/tools/brotli.c` of brotli 1.2.1 (MIT): `InitializeBuffers`,
//! `ProvideInput`, `WriteOutput`, `ProvideOutput`, `FlushOutput`,
//! `PrintBytes`, `PrintFileProcessingProgress`, `CompressFile`,
//! `CompressFiles` and `DecompressFiles`.
//!
//! The encoder sees exactly the tool's calls: reads of [`FILE_BUFFER_SIZE`]
//! bytes (each filled unless the input ends), `PROCESS` until a read meets
//! the end of the input, then `FINISH`; the output buffer of the same size
//! written whenever it is full and once at the end; a comment (`-C`) emitted
//! once, as a metadata block before the data. That is what makes the C
//! tier's `.br` bytes the reference's.
//!
//! Decoding is `InitDecoder`, `OnMetadataStart`/`OnMetadataChunk` (the
//! comment check, `-C`), `DecompressFile` and `PrettyDecoderErrorString`:
//! the same buffers, a decoder call per step, `corrupt input [f]` (with a
//! `reason:` line at `-v`) for an error, input that ends inside a stream
//! (`truncated input`), input left after it without `-K` (`extra input`)
//! and a comment that is not the one given. With `-K` a fresh decoder
//! starts on what follows a stream, as the tool's does: without the
//! metadata callbacks and with the comment state left as it was. A stream
//! with no comment at all where one is given prints `corrupt input` at the
//! end but succeeds (the tool's "final check" does not fail the run).

use std::cell::RefCell;
use std::io::Write;
use std::rc::Rc;

use stuffr::brotli_opts::{
    Decoder, Encoder, EncoderParams, MAX_WINDOW_BITS, Operation, StreamResult, window_for_length,
};

use super::files::{self, Ctx};
use super::messages as m;
use crate::compat::host::{self, Host};

/// `kFileBufferSize`.
pub(super) const FILE_BUFFER_SIZE: usize = 1 << 19;

/// The tool's two buffers (`context.buffer`), made once for the run.
pub(super) struct Buffers {
    pub(super) input: Box<[u8]>,
    pub(super) output: Box<[u8]>,
}

impl Buffers {
    pub(super) fn new() -> Self {
        Buffers {
            input: vec![0; FILE_BUFFER_SIZE].into_boxed_slice(),
            output: vec![0; FILE_BUFFER_SIZE].into_boxed_slice(),
        }
    }
}

/// `clock()`, in seconds: the processor time the process has used. Frozen
/// at 0 in a sandbox, so a sandboxed run is deterministic.
pub(super) fn clock(host: &Host) -> f64 {
    if matches!(host, Host::Sandbox(_)) {
        return 0.0;
    }
    #[cfg(unix)]
    {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is a valid timespec for the call to fill.
        if unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) } == 0 {
            return ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9;
        }
        0.0
    }
    #[cfg(not(unix))]
    {
        use std::sync::OnceLock;
        use std::time::Instant;
        static START: OnceLock<Instant> = OnceLock::new();
        START.get_or_init(Instant::now).elapsed().as_secs_f64()
    }
}

/// `InitializeBuffers`: the totals cleared and the clock started.
fn initialize(ctx: &mut Ctx) {
    ctx.total_in = 0;
    ctx.total_out = 0;
    if ctx.p.verbosity > 0 {
        ctx.start_time = clock(ctx.host);
    }
}

/// `ProvideInput`: one buffer's worth of input. `None` after a read error
/// (printed); else the number of bytes read.
fn provide_input(ctx: &mut Ctx, buf: &mut [u8]) -> Option<usize> {
    let Some(fin) = ctx.fin.as_mut() else {
        return Some(0);
    };
    let (n, error) = fin.fill(buf);
    ctx.total_in += n as u64;
    if let Some(e) = error {
        let name = ctx.input_name();
        ctx.say(m::READ_INPUT_FAILED, &[&name, &host::strerror(&e)]);
        return None;
    }
    Some(n)
}

/// `HasMoreInput`: `!feof`.
fn has_more_input(ctx: &Ctx) -> bool {
    ctx.fin.as_ref().is_some_and(|f| !f.eof())
}

/// `WriteOutput`: `data` counted, and written unless testing.
pub(super) fn write_output(ctx: &mut Ctx, data: &[u8]) -> bool {
    ctx.total_out += data.len() as u64;
    if data.is_empty() {
        return true;
    }
    if ctx.p.test_integrity {
        // Nothing is written; a sandbox still counts what `-t` decodes
        // against its output budget, so a bomb cannot run unbounded.
        if let Err(e) = ctx.host.charge(data.len() as u64) {
            let name = ctx.output_name();
            ctx.say(m::WRITE_OUTPUT_FAILED, &[&name, &host::strerror(&e)]);
            return false;
        }
        return true;
    }
    let Some(out) = ctx.fout.as_mut() else {
        return true;
    };
    if let Err(e) = out.write_all(data) {
        let name = ctx.output_name();
        ctx.say(m::WRITE_OUTPUT_FAILED, &[&name, &host::strerror(&e)]);
        return false;
    }
    true
}

/// `PrintBytes`.
fn print_bytes(err: &mut dyn Write, value: u64) {
    let v = value as f64;
    let _ = if value < 1024 {
        write!(err, "{value} B")
    } else if value < 1_048_576 {
        write!(err, "{:.3} KiB", v / 1024.0)
    } else if value < 1_073_741_824 {
        write!(err, "{:.3} MiB", v / 1_048_576.0)
    } else {
        write!(err, "{:.3} GiB", v / 1_073_741_824.0)
    };
}

/// `PrintFileProcessingProgress`: `[name]: A -> B in S sec`, no newline.
pub(super) fn print_file_processing_progress(err: &mut dyn Write, ctx: &Ctx) {
    printf(err, m::PROGRESS_NAME, &[&ctx.input_name()]);
    print_bytes(err, ctx.total_in);
    printf(err, m::PROGRESS_ARROW, &[]);
    print_bytes(err, ctx.total_out);
    let secs = format!("{:1.2}", ctx.end_time - ctx.start_time);
    printf(err, m::PROGRESS_TIME, &[secs.as_bytes()]);
}

use host::printf;

/// The encoder parameters `CompressFiles` sets for the current input.
fn encoder_params(ctx: &Ctx) -> EncoderParams {
    let p = ctx.p;
    let len = ctx.input_file_length;
    let (lgwin, large_window) = if p.lgwin > 0 {
        // Specified by the user; large-window only when it needs it.
        (p.lgwin as u32, p.lgwin as u32 > MAX_WINDOW_BITS)
    } else {
        // 0, or not given: limited by the file's size.
        (window_for_length(u64::try_from(len).ok()), false)
    };
    let size_hint = (len > 0).then(|| len.min(1 << 30) as u32);
    EncoderParams {
        quality: p.quality,
        lgwin,
        large_window,
        size_hint,
    }
}

/// `CompressFile`.
fn compress_file(ctx: &mut Ctx, enc: &mut Encoder, bufs: &mut Buffers) -> bool {
    let p = ctx.p;
    let mut is_eof = false;
    let mut prologue = !p.comment.is_empty();
    let (mut in_pos, mut in_end) = (0, 0);
    let mut out_pos = 0;
    initialize(ctx);
    loop {
        if in_pos == in_end && !is_eof {
            let Some(n) = provide_input(ctx, &mut bufs.input) else {
                return false;
            };
            (in_pos, in_end) = (0, n);
            is_eof = !has_more_input(ctx);
        }

        let mut out = &mut bufs.output[out_pos..];
        let room = out.len();
        if prologue {
            prologue = false;
            let mut meta: &[u8] = &p.comment;
            let ok = enc.compress_stream(Operation::EmitMetadata, &mut meta, &mut out);
            out_pos += room - out.len();
            if !ok || !meta.is_empty() {
                let name = ctx.input_name();
                ctx.say(m::EMIT_METADATA_FAILED, &[&name]);
                return false;
            }
        } else {
            let op = if is_eof {
                Operation::Finish
            } else {
                Operation::Process
            };
            let mut input = &bufs.input[in_pos..in_end];
            let ok = enc.compress_stream(op, &mut input, &mut out);
            in_pos = in_end - input.len();
            out_pos += room - out.len();
            if !ok {
                let name = ctx.input_name();
                ctx.say(m::COMPRESS_FAILED, &[&name]);
                return false;
            }
        }

        // `ProvideOutput`.
        if out_pos == FILE_BUFFER_SIZE {
            if !write_output(ctx, &bufs.output) {
                return false;
            }
            out_pos = 0;
        }

        if enc.is_finished() {
            // `FlushOutput`.
            if !write_output(ctx, &bufs.output[..out_pos]) {
                return false;
            }
            if ctx.p.verbosity > 0 {
                ctx.end_time = clock(ctx.host);
                let mut line = m::COMPRESSED.as_bytes().to_vec();
                print_file_processing_progress(&mut line, ctx);
                line.push(b'\n');
                let _ = ctx.err.write_all(&line);
            }
            return true;
        }
    }
}

/// `CompressFiles`: each input in turn; the first failure ends the run.
pub(super) fn compress_files(ctx: &mut Ctx, bufs: &mut Buffers) -> bool {
    while files::next_file(ctx) {
        let params = encoder_params(ctx);
        let Ok(mut enc) = Encoder::new(&params, ctx.prepared.as_ref()) else {
            ctx.say(m::OUT_OF_MEMORY, &[]);
            return false;
        };
        let mut is_ok = files::open_files(ctx);
        if is_ok && ctx.output_path.is_none() && !ctx.p.force_overwrite && ctx.host.stdout_is_tty()
        {
            ctx.say(m::FORCE_OUTPUT_TTY, &[]);
            is_ok = false;
        }
        if is_ok {
            is_ok = compress_file(ctx, &mut enc, bufs);
        }
        drop(enc);
        let mut rm_output = !is_ok;
        if is_ok && ctx.p.reject_uncompressible && ctx.total_out >= ctx.total_in {
            rm_output = true;
            if ctx.p.verbosity > 0 {
                ctx.say(m::OUTPUT_LARGER, &[]);
            }
        }
        let rm_input = !rm_output && ctx.p.junk_source;
        if !files::close_files(ctx, rm_input, rm_output) {
            is_ok = false;
        }
        if !is_ok {
            return false;
        }
    }
    true
}

/// `InitDecoder`: a decoder taking large-window streams, with the
/// dictionary attached. `None` (printed) when none can be made.
fn init_decoder(ctx: &mut Ctx) -> Option<Decoder> {
    match Decoder::new(true, ctx.dictionary.as_deref()) {
        Ok(d) => Some(d),
        Err(_) => {
            ctx.say(m::OUT_OF_MEMORY, &[]);
            None
        }
    }
}

/// `CommentState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommentState {
    Init,
    Read,
    Ok,
    Bad,
}

/// The comment check's part of `Context`: what `OnMetadataStart` and
/// `OnMetadataChunk` read and change.
struct CommentCheck {
    comment: Vec<u8>,
    pos: usize,
    state: CommentState,
}

impl CommentCheck {
    /// `OnMetadataStart`.
    fn on_start(&mut self, size: usize) {
        if self.state == CommentState::Init {
            if self.comment.len() != size {
                self.state = CommentState::Bad;
                return;
            }
            self.pos = 0;
            self.state = CommentState::Read;
        }
    }

    /// `OnMetadataChunk`.
    fn on_chunk(&mut self, data: &[u8]) {
        if self.state == CommentState::Read {
            for &b in data {
                if self.pos >= self.comment.len() {
                    self.state = CommentState::Bad;
                    return;
                }
                let want = self.comment[self.pos];
                self.pos += 1;
                if want != b {
                    self.state = CommentState::Bad;
                    return;
                }
            }
            if self.pos == self.comment.len() {
                self.state = CommentState::Ok;
            }
        }
    }
}

/// `PrettyDecoderErrorString`: the name without its `_ERROR_` prefix.
fn pretty_decoder_error(name: &str) -> &str {
    const PREFIX: &str = "_ERROR_";
    if name.len() > PREFIX.len() {
        name.strip_prefix(PREFIX).unwrap_or(name)
    } else {
        name
    }
}

/// `corrupt input [f]`, and at `-v` the reason line.
fn corrupt(ctx: &mut Ctx, reason: &[u8]) {
    let name = ctx.input_name();
    ctx.say(m::CORRUPT_INPUT, &[&name]);
    if ctx.p.verbosity > 0 {
        ctx.say(m::REASON, &[reason]);
    }
}

/// `fgetc(fin)`: one more byte, `None` at the end of the input (or after
/// a read error, which `fgetc` also reports as `EOF`).
fn get_byte(ctx: &mut Ctx) -> Option<u8> {
    let fin = ctx.fin.as_mut()?;
    let mut b = [0u8; 1];
    match fin.fill(&mut b) {
        (1, _) => Some(b[0]),
        _ => None,
    }
}

/// `DecompressFile`.
fn decompress_file(ctx: &mut Ctx, dec: &mut Decoder, bufs: &mut Buffers) -> bool {
    let check = Rc::new(RefCell::new(CommentCheck {
        comment: ctx.p.comment.clone(),
        pos: 0,
        state: CommentState::Ok,
    }));
    if !ctx.p.comment.is_empty() {
        check.borrow_mut().state = CommentState::Init;
        let (a, b) = (Rc::clone(&check), Rc::clone(&check));
        // Set before the first call: the pure tier reads metadata only
        // from a decoder that has had them from the start.
        let _ = dec.set_metadata_callbacks(
            Box::new(move |size| a.borrow_mut().on_start(size)),
            Box::new(move |data| b.borrow_mut().on_chunk(data)),
        );
    }
    let state = || check.borrow().state;

    // `InitializeBuffers`.
    let (mut in_pos, mut in_end) = (0usize, 0usize);
    let mut out_pos = 0usize;
    let mut out_end = FILE_BUFFER_SIZE;
    initialize(ctx);

    // The decoder `-K` starts on what follows a stream, in place of `dec`.
    let mut fresh: Option<Decoder> = None;
    let mut result = StreamResult::NeedsMoreInput;
    loop {
        // Early check.
        if state() == CommentState::Bad {
            corrupt(ctx, m::REASON_COMMENT.as_bytes());
            return false;
        }
        match result {
            StreamResult::NeedsMoreInput => {
                if !has_more_input(ctx) {
                    corrupt(ctx, m::REASON_TRUNCATED.as_bytes());
                    return false;
                }
                let Some(n) = provide_input(ctx, &mut bufs.input) else {
                    return false;
                };
                (in_pos, in_end) = (0, n);
            }
            StreamResult::NeedsMoreOutput => {
                // `ProvideOutput`.
                if !write_output(ctx, &bufs.output[..out_pos]) {
                    return false;
                }
                (out_pos, out_end) = (0, FILE_BUFFER_SIZE);
            }
            StreamResult::Success => {
                // `FlushOutput`.
                if !write_output(ctx, &bufs.output[..out_pos]) {
                    return false;
                }
                // (`available_out` 0: every way on from here resets it.)
                out_pos = 0;
                let mut has_more_input = in_pos != in_end;
                if !has_more_input && let Some(b) = get_byte(ctx) {
                    has_more_input = true;
                    bufs.input[0] = b;
                    (in_pos, in_end) = (0, 1);
                }
                if has_more_input {
                    if ctx.p.allow_concatenated {
                        if ctx.p.verbosity > 0 {
                            ctx.say(m::EXTRA_INPUT, &[]);
                        }
                        // `ProvideOutput` (nothing is pending).
                        if !write_output(ctx, &bufs.output[..out_pos]) {
                            return false;
                        }
                        (out_pos, out_end) = (0, FILE_BUFFER_SIZE);
                        // `BrotliDecoderDestroyInstance`, then `InitDecoder`.
                        drop(fresh.take());
                        let Some(d) = init_decoder(ctx) else {
                            return false;
                        };
                        fresh = Some(d);
                    } else {
                        corrupt(ctx, m::REASON_EXTRA.as_bytes());
                        return false;
                    }
                } else {
                    if ctx.p.verbosity > 0 {
                        ctx.end_time = clock(ctx.host);
                        let mut line = m::DECOMPRESSED.as_bytes().to_vec();
                        print_file_processing_progress(&mut line, ctx);
                        line.push(b'\n');
                        let _ = ctx.err.write_all(&line);
                    }
                    // Final check: printed, but the run goes on.
                    if state() != CommentState::Ok {
                        corrupt(ctx, m::REASON_COMMENT.as_bytes());
                    }
                    return true;
                }
            }
            StreamResult::Error => {
                let d = fresh.as_ref().unwrap_or(&*dec);
                let e = d.error();
                let name = ctx.input_name();
                ctx.say(m::CORRUPT_INPUT, &[&name]);
                if ctx.p.verbosity > 0 {
                    let reason = pretty_decoder_error(e.name);
                    let code = e.code.to_string();
                    ctx.say(m::REASON_CODE, &[reason.as_bytes(), code.as_bytes()]);
                }
                return false;
            }
        }

        let d = match fresh.as_mut() {
            Some(d) => d,
            None => &mut *dec,
        };
        let mut input = &bufs.input[in_pos..in_end];
        let mut output = &mut bufs.output[out_pos..out_end];
        let room = output.len();
        result = d.decompress_stream(&mut input, &mut output);
        in_pos = in_end - input.len();
        out_pos += room - output.len();
    }
}

/// `DecompressFiles` (also `-t`): each input in turn; the first failure
/// ends the run.
pub(super) fn decompress_files(ctx: &mut Ctx, bufs: &mut Buffers) -> bool {
    while files::next_file(ctx) {
        let Some(mut dec) = init_decoder(ctx) else {
            return false;
        };
        let mut is_ok = files::open_files(ctx);
        if is_ok && ctx.input_path.is_none() && !ctx.p.force_overwrite && ctx.host.stdin_is_tty() {
            ctx.say(m::FORCE_INPUT_TTY, &[]);
            is_ok = false;
        }
        if is_ok {
            is_ok = decompress_file(ctx, &mut dec, bufs);
        }
        drop(dec);
        let rm_output = !is_ok;
        let rm_input = !rm_output && ctx.p.junk_source;
        if !files::close_files(ctx, rm_input, rm_output) {
            is_ok = false;
        }
        if !is_ok {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_bytes_is_printf_s() {
        let cases: [(u64, &str); 7] = [
            (0, "0 B"),
            (1023, "1023 B"),
            (1024, "1.000 KiB"),
            // An exact tie: `%0.3f` rounds it to even, as `{:.3}` does.
            (1088, "1.062 KiB"),
            (1_048_575, "1023.999 KiB"),
            (1_048_576, "1.000 MiB"),
            (1 << 30, "1.000 GiB"),
        ];
        for (v, want) in cases {
            let mut out = Vec::new();
            print_bytes(&mut out, v);
            assert_eq!(String::from_utf8(out).unwrap(), want, "{v}");
        }
    }
}
