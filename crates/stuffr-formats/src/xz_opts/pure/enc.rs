//! The pure tier's [`Encoder`].

use std::io::Write;
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};

use lzma_rust2::filter::bcj::BcjWriter;
use lzma_rust2::filter::delta::DeltaWriter;
use lzma_rust2::{CheckType, Lzma2Options, Lzma2Writer, LzmaWriter, XzOptions, XzWriterMt};

use super::super::check::{Running, crc32};
use super::super::memusage;
use super::super::{Bcj, Check, EncodeOptions, Filter, Format, Lzma, Progress, XzError};
use super::{FOOTER_MAGIC, HEADER_MAGIC, bcj_aligned, bcj_id, limit_of, lzma_options, vli_encode};

/// The coder chain under one Block (or the whole raw stream): the pre-
/// filters, outermost first, over the LZMA1 or LZMA2 coder that writes into
/// a `Vec` this module drains.
enum ChainWriter {
    Lzma2(Lzma2Writer<Vec<u8>>),
    Lzma1(LzmaWriter<Vec<u8>>),
    Bcj(BcjWriter<Box<ChainWriter>>),
    Delta(DeltaWriter<Box<ChainWriter>>),
}

impl ChainWriter {
    /// The writers for `chain`, already validated: LZMA1 always with its
    /// end-of-payload marker (`.lzma`, raw LZMA1 and LZMA1EXT as this layer
    /// builds it all have an unknown size).
    fn new(chain: &[Filter]) -> Result<ChainWriter, XzError> {
        let (last, pre) = chain.split_last().ok_or(XzError::Options)?;
        let mut w = match last {
            Filter::Lzma2(l) => ChainWriter::Lzma2(Lzma2Writer::new(
                Vec::new(),
                Lzma2Options {
                    lzma_options: lzma_options(l),
                    chunk_size: None,
                },
            )),
            Filter::Lzma1(l) | Filter::Lzma1Ext(l) => ChainWriter::Lzma1(
                LzmaWriter::new_no_header(Vec::new(), &lzma_options(l), true)
                    .map_err(|_| XzError::Options)?,
            ),
            _ => return Err(XzError::Options),
        };
        for f in pre.iter().rev() {
            let inner = Box::new(w);
            w = match *f {
                Filter::Delta { dist } => {
                    ChainWriter::Delta(DeltaWriter::new(inner, dist as usize))
                }
                Filter::Bcj { kind, start } => {
                    if !bcj_aligned(kind, start) {
                        return Err(XzError::Options);
                    }
                    let start = start as usize;
                    ChainWriter::Bcj(match kind {
                        Bcj::X86 => BcjWriter::new_x86(inner, start),
                        Bcj::PowerPc => BcjWriter::new_ppc(inner, start),
                        Bcj::Ia64 => BcjWriter::new_ia64(inner, start),
                        Bcj::Arm => BcjWriter::new_arm(inner, start),
                        Bcj::ArmThumb => BcjWriter::new_arm_thumb(inner, start),
                        Bcj::Arm64 => BcjWriter::new_arm64(inner, start),
                        Bcj::Sparc => BcjWriter::new_sparc(inner, start),
                        Bcj::RiscV => BcjWriter::new_riscv(inner, start),
                    })
                }
                _ => return Err(XzError::Options),
            };
        }
        Ok(w)
    }

    /// The `Vec` the LZ coder writes into.
    fn sink(&mut self) -> &mut Vec<u8> {
        match self {
            ChainWriter::Lzma2(w) => w.inner_mut(),
            ChainWriter::Lzma1(w) => w.inner_mut(),
            ChainWriter::Bcj(w) => w.inner_mut().sink(),
            ChainWriter::Delta(w) => w.inner_mut().sink(),
        }
    }

    /// Ends the chain: what the BCJ filters hold, the LZ coder's last bytes
    /// and end marker. Returns the sink with the rest of the output.
    fn finish(self) -> std::io::Result<Vec<u8>> {
        match self {
            ChainWriter::Lzma2(w) => w.finish(),
            ChainWriter::Lzma1(w) => w.finish(),
            ChainWriter::Bcj(w) => w.finish()?.finish(),
            ChainWriter::Delta(w) => w.into_inner().finish(),
        }
    }
}

impl Write for ChainWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            ChainWriter::Lzma2(w) => w.write(buf),
            ChainWriter::Lzma1(w) => w.write(buf),
            ChainWriter::Bcj(w) => w.write(buf),
            ChainWriter::Delta(w) => w.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            ChainWriter::Lzma2(w) => w.flush(),
            ChainWriter::Lzma1(w) => w.flush(),
            ChainWriter::Bcj(w) => w.flush(),
            ChainWriter::Delta(w) => w.flush(),
        }
    }
}

/// What [`ChainWriter::new`] refuses, without building the coders: a
/// misaligned BCJ start offset.
fn chain_supported(chain: &[Filter]) -> Result<(), XzError> {
    for f in chain {
        if let Filter::Bcj { kind, start } = *f
            && !bcj_aligned(kind, start)
        {
            return Err(XzError::Options);
        }
    }
    Ok(())
}

/// Whether liblzma's chain takes `LZMA_SYNC_FLUSH`: LZMA2 under delta
/// filters only (LZMA1's `lzma_encode` and `simple_coder.c` answer
/// `LZMA_OPTIONS_ERROR`).
fn flushable(chain: &[Filter]) -> bool {
    chain
        .iter()
        .all(|f| matches!(f, Filter::Lzma2(_) | Filter::Delta { .. }))
}

/// The Filter Flags of `f` (`lzma_filter_flags_encode`): ID, size of the
/// properties, properties.
fn filter_flags(f: &Filter, out: &mut Vec<u8>) {
    let (id, props): (u64, Vec<u8>) = match f {
        Filter::Lzma2(l) => (0x21, vec![lzma2_props(l.dict_size)]),
        Filter::Delta { dist } => (0x03, vec![(dist - 1) as u8]),
        Filter::Bcj { kind, start } => (
            bcj_id(*kind),
            if *start == 0 {
                Vec::new()
            } else {
                start.to_le_bytes().to_vec()
            },
        ),
        // Refused before any Block Header is written.
        Filter::Lzma1(_) | Filter::Lzma1Ext(_) => unreachable!("not in .xz"),
    };
    vli_encode(id, out);
    vli_encode(props.len() as u64, out);
    out.extend_from_slice(&props);
}

/// `lzma_lzma2_props_encode`: the dictionary size rounded up to `2^n` or
/// `2^n + 2^(n-1)`, as its distance slot less 24.
fn lzma2_props(dict_size: u32) -> u8 {
    let mut d = dict_size.max(4096) - 1;
    d |= d >> 2;
    d |= d >> 3;
    d |= d >> 4;
    d |= d >> 8;
    d |= d >> 16;
    if d == u32::MAX {
        return 40;
    }
    let v = d + 1;
    let bits = 31 - v.leading_zeros();
    // `get_dist_slot`.
    let slot = 2 * bits + ((v >> (bits - 1)) & 1);
    (slot - 24) as u8
}

/// `lzma_block_header_encode` for a Block with no sizes recorded.
fn block_header(chain: &[Filter]) -> Vec<u8> {
    let mut flags = Vec::new();
    for f in chain {
        filter_flags(f, &mut flags);
    }
    // `lzma_block_header_size`: size byte, flags byte, Filter Flags and the
    // CRC32, rounded up to four.
    let size = (1 + 1 + flags.len() + 4 + 3) & !3;
    let mut h = Vec::with_capacity(size);
    h.push((size / 4 - 1) as u8);
    h.push((chain.len() - 1) as u8);
    h.extend_from_slice(&flags);
    h.resize(size - 4, 0);
    let crc = crc32(&h, 0);
    h.extend_from_slice(&crc.to_le_bytes());
    h
}

/// The two Stream Flags bytes for `check`.
fn stream_flags(check: Check) -> [u8; 2] {
    [0, check.id() as u8]
}

/// `lzma_stream_header_encode`.
fn stream_header(check: Check) -> Vec<u8> {
    let flags = stream_flags(check);
    let mut h = HEADER_MAGIC.to_vec();
    h.extend_from_slice(&flags);
    h.extend_from_slice(&crc32(&flags, 0).to_le_bytes());
    h
}

/// `lzma_index_encode` and `lzma_stream_footer_encode` for the Blocks
/// `records` (`(unpadded, uncompressed)` each).
fn index_and_footer(records: &[(u64, u64)], check: Check, out: &mut Vec<u8>) {
    let start = out.len();
    out.push(0);
    vli_encode(records.len() as u64, out);
    for &(unpadded, uncompressed) in records {
        vli_encode(unpadded, out);
        vli_encode(uncompressed, out);
    }
    while !(out.len() - start).is_multiple_of(4) {
        out.push(0);
    }
    let crc = crc32(&out[start..], 0);
    out.extend_from_slice(&crc.to_le_bytes());
    let backward = ((out.len() - start) / 4 - 1) as u32;
    let mut tail = backward.to_le_bytes().to_vec();
    tail.extend_from_slice(&stream_flags(check));
    out.extend_from_slice(&crc32(&tail, 0).to_le_bytes());
    out.extend_from_slice(&tail);
    out.extend_from_slice(&FOOTER_MAGIC);
}

/// An open `.xz` Block.
struct Block {
    w: ChainWriter,
    check: Running,
    header_size: u64,
    compressed: u64,
    uncompressed: u64,
}

/// The single-threaded `.xz` writer: Blocks cut as `coder.c`'s
/// `coder_normal`/`split_block` cut them, each with its own chain.
struct XzSerial {
    check: Check,
    /// Index 0 is [`EncodeOptions::filters`], then the block list's other
    /// chains.
    chains: Vec<Vec<Filter>>,
    /// The block list as `(size, chain index)`.
    list: Vec<(u64, usize)>,
    /// The Block size cut inside list entries (`0`: none).
    block_size: u64,
    block_remaining: u64,
    next_block_remaining: u64,
    list_pos: usize,
    chain: usize,
    block: Option<Block>,
    records: Vec<(u64, u64)>,
}

impl XzSerial {
    /// The first chain is checked here, as liblzma's single-threaded
    /// encoder initialises the first Block's encoder with the Stream's; a
    /// later chain of the block list is checked when its Block opens
    /// (`lzma_filters_update`). For `threaded` output every chain is checked
    /// when its Block opens, as liblzma's threaded encoder initialises each
    /// Block's encoder then: an empty input makes an empty Stream, and
    /// otherwise the Stream Header is out before the refusal.
    fn new(o: &EncodeOptions, block_size: u64, threaded: bool) -> Result<XzSerial, XzError> {
        let mut chains = vec![o.filters.clone()];
        let mut list = Vec::new();
        for (size, chain) in &o.block_list {
            let chain = chain.as_ref().unwrap_or(&o.filters);
            let i = match chains.iter().position(|c| c == chain) {
                Some(i) => i,
                None => {
                    chains.push(chain.clone());
                    chains.len() - 1
                }
            };
            list.push((*size, i));
        }
        // `coder_normal`'s set-up of `block_remaining`.
        let mut block_remaining = if block_size > 0 { block_size } else { u64::MAX };
        let mut next_block_remaining = 0;
        if let Some(&(size, _)) = list.first() {
            if block_remaining < size {
                next_block_remaining = size - block_remaining;
            } else {
                block_remaining = size;
            }
        }
        let chain = list.first().map_or(0, |&(_, i)| i);
        if !threaded {
            chain_supported(&chains[chain])?;
        }
        Ok(XzSerial {
            check: o.check,
            chains,
            list,
            block_size,
            block_remaining,
            next_block_remaining,
            list_pos: 0,
            chain,
            block: None,
            records: Vec::new(),
        })
    }

    fn open_block(&mut self, out: &mut Vec<u8>) -> Result<&mut Block, XzError> {
        if self.block.is_none() {
            let chain = &self.chains[self.chain];
            let w = ChainWriter::new(chain)?;
            let header = block_header(chain);
            out.extend_from_slice(&header);
            self.block = Some(Block {
                w,
                check: Running::of(self.check),
                header_size: header.len() as u64,
                compressed: 0,
                uncompressed: 0,
            });
        }
        Ok(self.block.as_mut().expect("opened above"))
    }

    fn feed(&mut self, mut input: &[u8], out: &mut Vec<u8>) -> Result<(), XzError> {
        while !input.is_empty() {
            let take =
                usize::try_from(self.block_remaining).map_or(input.len(), |r| r.min(input.len()));
            let (piece, rest) = input.split_at(take);
            input = rest;
            let b = self.open_block(out)?;
            b.w.write_all(piece)?;
            b.check.update(piece);
            b.uncompressed += take as u64;
            let sink = b.w.sink();
            b.compressed += sink.len() as u64;
            out.append(sink);
            if self.block_remaining != u64::MAX {
                self.block_remaining -= take as u64;
                if self.block_remaining == 0 {
                    self.end_block(out)?;
                    self.split_block();
                }
            }
        }
        Ok(())
    }

    /// `LZMA_FULL_BARRIER`'s end of the Block, if one is open.
    fn end_block(&mut self, out: &mut Vec<u8>) -> Result<(), XzError> {
        let Some(b) = self.block.take() else {
            return Ok(());
        };
        let mut rest = b.w.finish()?;
        let compressed = b.compressed + rest.len() as u64;
        out.append(&mut rest);
        out.resize(out.len() + ((4 - compressed % 4) % 4) as usize, 0);
        let check = b.check.finish();
        out.extend_from_slice(&check);
        self.records.push((
            b.header_size + compressed + check.len() as u64,
            b.uncompressed,
        ));
        Ok(())
    }

    /// `coder.c`'s `split_block` (and, without a list, the next
    /// `--block-size` Block).
    fn split_block(&mut self) {
        if self.list.is_empty() {
            self.block_remaining = self.block_size;
            return;
        }
        if self.next_block_remaining > 0 {
            self.block_remaining = if self.block_size > 0 {
                self.next_block_remaining.min(self.block_size)
            } else {
                self.next_block_remaining
            };
            self.next_block_remaining -= self.block_remaining;
            return;
        }
        if self.list_pos + 1 < self.list.len() {
            self.list_pos += 1;
            self.chain = self.list[self.list_pos].1;
        }
        self.block_remaining = self.list[self.list_pos].0;
        if self.block_size > 0 && self.block_remaining > self.block_size {
            self.next_block_remaining = self.block_remaining - self.block_size;
            self.block_remaining = self.block_size;
        }
    }

    /// Between Blocks there is nothing to flush (`stream_encoder.c`'s
    /// `SEQ_BLOCK_INIT`); in one, the chain must take it.
    fn flush(&mut self, out: &mut Vec<u8>) -> Result<(), XzError> {
        if let Some(b) = self.block.as_mut() {
            if !flushable(&self.chains[self.chain]) {
                return Err(XzError::Options);
            }
            b.w.flush()?;
            let sink = b.w.sink();
            b.compressed += sink.len() as u64;
            out.append(sink);
        }
        Ok(())
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), XzError> {
        self.end_block(out)?;
        index_and_footer(&self.records, self.check, out);
        Ok(())
    }
}

/// A `Write` the threaded writer owns while this module drains it.
#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Vec<u8>>>);

impl Shared {
    fn take(&self, out: &mut Vec<u8>) {
        let mut buf = self.0.lock().unwrap_or_else(|e| e.into_inner());
        out.append(&mut buf);
    }
}

impl Write for Shared {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut v = self.0.lock().unwrap_or_else(|e| e.into_inner());
        v.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

enum Inner {
    Xz(Box<XzSerial>),
    XzMt {
        w: Option<XzWriterMt<Shared>>,
        sink: Shared,
    },
    /// `.lzma`: the header, then raw LZMA1 with an end marker.
    Lzma(Option<ChainWriter>),
    Raw {
        w: Option<ChainWriter>,
        flushable: bool,
    },
}

/// A streaming encoder over [`EncodeOptions`]: the pure tier's
/// counterpart of `c::Encoder`, with the same contract. Its
/// bytes are compatible with, not identical to, liblzma's (see the module
/// doc); they depend on the options and the input, never on how the input
/// is split across [`Encoder::feed`] calls.
pub struct Encoder {
    inner: Inner,
    /// liblzma's threaded encoder, which does not take `LZMA_SYNC_FLUSH`.
    threaded: bool,
    /// Output produced at set-up (a header) not yet handed out.
    pending: Vec<u8>,
    in_bytes: u64,
    out_bytes: u64,
    done: bool,
}

impl std::fmt::Debug for Encoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Encoder").finish_non_exhaustive()
    }
}

/// The `.lzma` header `lzma_alone_encoder` writes: properties, the
/// dictionary size rounded up to `2^n` or `2^n + 2^(n-1)`, an unknown size.
fn alone_header(l: &Lzma) -> Vec<u8> {
    let mut d = l.dict_size - 1;
    d |= d >> 2;
    d |= d >> 3;
    d |= d >> 4;
    d |= d >> 8;
    d |= d >> 16;
    d = d.saturating_add(1);
    let mut h = vec![((l.pb * 5 + l.lp) * 9 + l.lc) as u8];
    h.extend_from_slice(&d.to_le_bytes());
    h.extend_from_slice(&[0xFF; 8]);
    h
}

impl Encoder {
    /// Initialises the encoder, refusing what liblzma refuses:
    /// [`XzError::Options`] for an unsupported chain or [`Format::Lzip`],
    /// [`XzError::MemLimit`] for an [`super::encoder_memusage`] over
    /// [`EncodeOptions::memlimit`].
    pub fn new(o: &EncodeOptions) -> Result<Encoder, XzError> {
        let needed = memusage::encoder_memusage(o).ok_or(XzError::Options)?;
        let limit = limit_of(o.memlimit);
        if needed > limit {
            return Err(XzError::MemLimit { needed, limit });
        }
        let mut pending = Vec::new();
        let mut threaded = false;
        let inner = match o.format {
            Format::Lzip => return Err(XzError::Options),
            Format::Lzma => match o.filters.as_slice() {
                [Filter::Lzma1(l)] => {
                    if l.preset_dict.is_some() {
                        return Err(XzError::Options);
                    }
                    pending = alone_header(l);
                    Inner::Lzma(Some(ChainWriter::new(&o.filters)?))
                }
                _ => return Err(XzError::Options),
            },
            Format::Raw => Inner::Raw {
                w: Some(ChainWriter::new(&o.filters)?),
                flushable: flushable(&o.filters),
            },
            Format::Xz => {
                // LZMA1 has a Filter ID past `LZMA_FILTER_RESERVED_START`,
                // which `lzma_filter_flags_encode` calls a programming error.
                for chain in memusage::used_chains(o) {
                    if !matches!(chain.last(), Some(Filter::Lzma2(_))) {
                        return Err(XzError::Prog);
                    }
                }
                pending = stream_header(o.check);
                if o.threads == 0 {
                    Inner::Xz(Box::new(XzSerial::new(o, o.block_size, false)?))
                } else {
                    let chains = memusage::used_chains(o);
                    let block_size =
                        memusage::mt_block_size_for(o, &chains).ok_or(XzError::Options)?;
                    if o.block_list.is_empty() && o.filters.len() == 1 {
                        pending.clear();
                        threaded = true;
                        mt_writer(o, block_size)?
                    } else {
                        threaded = true;
                        Inner::Xz(Box::new(XzSerial::new(o, block_size, true)?))
                    }
                }
            }
        };
        Ok(Encoder {
            inner,
            threaded,
            pending,
            in_bytes: 0,
            out_bytes: 0,
            done: false,
        })
    }

    fn emit(&mut self, out: &[u8], start: usize) {
        self.out_bytes += (out.len() - start) as u64;
    }

    /// Compresses `input`, appending what is ready to `out`.
    pub fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), XzError> {
        if self.done {
            return Err(XzError::Prog);
        }
        let start = out.len();
        out.append(&mut self.pending);
        let r = match &mut self.inner {
            Inner::Xz(x) => x.feed(input, out),
            Inner::XzMt { w, sink } => {
                let r = w
                    .as_mut()
                    .expect("live until finish")
                    .write_all(input)
                    .map_err(XzError::from);
                sink.take(out);
                r
            }
            Inner::Lzma(w) | Inner::Raw { w, .. } => {
                let w = w.as_mut().expect("live until finish");
                let r = w.write_all(input).map_err(XzError::from);
                out.append(w.sink());
                r
            }
        };
        self.in_bytes += input.len() as u64;
        self.emit(out, start);
        self.done = r.is_err();
        r
    }

    /// `LZMA_SYNC_FLUSH`: everything fed so far becomes decodable from
    /// `out`. [`XzError::Prog`] where liblzma refuses it (see the module
    /// doc).
    pub fn flush(&mut self, out: &mut Vec<u8>) -> Result<(), XzError> {
        if self.done {
            return Err(XzError::Prog);
        }
        let start = out.len();
        out.append(&mut self.pending);
        let r = match &mut self.inner {
            _ if self.threaded => Err(XzError::Prog),
            Inner::Xz(x) => x.flush(out),
            Inner::Raw {
                w: Some(w),
                flushable,
            } => {
                if *flushable {
                    let r = w.flush().map_err(XzError::from);
                    out.append(w.sink());
                    r
                } else {
                    Err(XzError::Options)
                }
            }
            _ => Err(XzError::Prog),
        };
        self.emit(out, start);
        self.done = r.is_err();
        r
    }

    /// `LZMA_FINISH`: the rest of the stream, through its footer.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), XzError> {
        if self.done {
            return Err(XzError::Prog);
        }
        self.done = true;
        let start = out.len();
        out.append(&mut self.pending);
        let r = match &mut self.inner {
            Inner::Xz(x) => x.finish(out),
            Inner::XzMt { w, sink } => {
                let r = w
                    .take()
                    .expect("live until finish")
                    .finish()
                    .map(drop)
                    .map_err(XzError::from);
                sink.take(out);
                r
            }
            Inner::Lzma(w) | Inner::Raw { w, .. } => match w.take().expect("live").finish() {
                Ok(mut rest) => {
                    out.append(&mut rest);
                    Ok(())
                }
                Err(e) => Err(e.into()),
            },
        };
        self.emit(out, start);
        r
    }

    /// Bytes in and out so far.
    pub fn progress(&self) -> Progress {
        Progress {
            in_bytes: self.in_bytes,
            out_bytes: self.out_bytes,
        }
    }
}

/// The threaded `.xz` writer for `o` (a lone LZMA2) with `block_size`.
fn mt_writer(o: &EncodeOptions, block_size: u64) -> Result<Inner, XzError> {
    let [Filter::Lzma2(l)] = o.filters.as_slice() else {
        return Err(XzError::Options);
    };
    let options = XzOptions {
        lzma_options: lzma_options(l),
        check_type: match o.check {
            Check::None => CheckType::None,
            Check::Crc32 => CheckType::Crc32,
            Check::Crc64 => CheckType::Crc64,
            Check::Sha256 => CheckType::Sha256,
        },
        block_size: NonZeroU64::new(block_size),
        filters: Vec::new(),
    };
    let sink = Shared::default();
    let w = XzWriterMt::new(sink.clone(), options, o.threads).map_err(|_| XzError::Options)?;
    Ok(Inner::XzMt { w: Some(w), sink })
}
