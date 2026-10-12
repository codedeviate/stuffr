//! What `--list` reads of a `.xz` file, in pure Rust on both tiers: the
//! Streams' footers, Indexes and headers, walked from the end
//! (liblzma's `common/file_info.c`, `common/index_decoder.c` and the parts
//! of `common/index.c` they reach), and one Block Header
//! (`common/block_header_decoder.c`, `common/filter_flags_decoder.c` and
//! the filters' `props_decode`), from XZ Utils 5.8.4 (0BSD, `LICENSE-xz`).
//!
//! **Errors are liblzma's return codes**, decided in liblzma's order, so
//! list.c says what xz says. The walk does not keep file_info.c's 8 KiB
//! window: it reads each field where it lies. That gives the same verdict
//! because every check the window adds (`reverse_seek`'s "at least 24
//! bytes before the target") comes down to two rules kept here: Stream
//! Padding never reaches into the first Stream Header, and a later Stream
//! Header may not overlap it.
//!
//! **Bounded against hostile input.** Nothing is allocated from a declared
//! count: an Index's Number of Records is checked against its Backward Size
//! (`number_of_records_max`) and the memory limit, and a Record is stored
//! only once its bytes have been read, so memory follows the bytes the file
//! really holds. Every loop consumes input or ends.

use super::file_io::IO_BUFFER_SIZE;

/// `LZMA_STREAM_HEADER_SIZE`.
pub(crate) const HEADER_SIZE: u64 = 12;
/// `LZMA_VLI_MAX`.
pub(crate) const VLI_MAX: u64 = u64::MAX / 2;
const UNPADDED_SIZE_MIN: u64 = 5;
const UNPADDED_SIZE_MAX: u64 = VLI_MAX & !3;
/// `LZMA_BACKWARD_SIZE_MAX`.
const BACKWARD_SIZE_MAX: u64 = 1 << 34;
/// index.c: `STREAMS_MAX`.
const STREAMS_MAX: u64 = u32::MAX as u64;
/// `LZMA_FILTER_RESERVED_START`.
const FILTER_RESERVED_START: u64 = 1 << 62;
/// `LZMA_VLI_BYTES_MAX`.
const VLI_BYTES_MAX: usize = 9;
const HEADER_MAGIC: [u8; 6] = [0xFD, b'7', b'z', b'X', b'Z', 0x00];
const FOOTER_MAGIC: [u8; 2] = *b"YZ";

/// check.c: lzma_check_size, by check ID (0..=15).
pub(crate) const CHECK_SIZES: [u32; 16] = [0, 4, 4, 4, 8, 8, 8, 16, 16, 16, 32, 32, 32, 64, 64, 64];

/// The liblzma return codes the walk can end with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    /// `LZMA_FORMAT_ERROR`: the file does not begin with a Stream Header.
    Format,
    /// `LZMA_DATA_ERROR`.
    Data,
    /// `LZMA_OPTIONS_ERROR`.
    Options,
    /// `LZMA_MEMLIMIT_ERROR`, with what `lzma_memusage` then reports.
    MemLimit { needed: u64 },
    /// `LZMA_BUF_ERROR`: the file ended before its size said.
    Buf,
    /// An I/O error, already said by the reader.
    Said,
}

/// Where the walk reads the file.
pub(crate) trait Source {
    /// Exactly `buf.len()` bytes at `pos`: [`Error::Buf`] if the file is
    /// shorter, [`Error::Said`] after an I/O error the reader has said.
    fn read_at(&mut self, pos: u64, buf: &mut [u8]) -> Result<(), Error>;
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(data);
    c.sum()
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// index.h: vli_ceil4.
fn ceil4(v: u64) -> u64 {
    (v + 3) & !3
}

/// vli_encoder.c: lzma_vli_size, for a valid integer.
fn vli_size(mut v: u64) -> u64 {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

/// index.h: index_size_unpadded.
fn index_size_unpadded(count: u64, list_size: u64) -> u64 {
    1 + vli_size(count) + list_size + 4
}

/// index.h: index_size.
fn index_size(count: u64, list_size: u64) -> u64 {
    ceil4(index_size_unpadded(count, list_size))
}

/// index.c: lzma_index_memusage, with the structure sizes of a 64-bit
/// build (`sizeof(lzma_index)` 104, `index_stream` 168, `index_group` 64,
/// `index_record` 16; measured on the 5.8.4 binary: 432 bytes for one
/// Stream with no Blocks, 8288 more per 512 Blocks, 296 per Stream).
/// `u64::MAX` for arguments liblzma refuses.
pub(crate) fn index_memusage(streams: u64, blocks: u64) -> u64 {
    const ALLOC_OVERHEAD: u64 = 4 * 8;
    const STREAM_BASE: u64 = 168 + 64 + 2 * ALLOC_OVERHEAD;
    const GROUP_BASE: u64 = 64 + 512 * 16 + ALLOC_OVERHEAD;
    const INDEX_BASE: u64 = 104 + ALLOC_OVERHEAD;
    if streams == 0 || streams > STREAMS_MAX || blocks > VLI_MAX {
        return u64::MAX;
    }
    let groups = blocks.div_ceil(512);
    let limit = u64::MAX - INDEX_BASE;
    if streams > limit / STREAM_BASE || groups > limit / GROUP_BASE {
        return u64::MAX;
    }
    let (streams_mem, groups_mem) = (streams * STREAM_BASE, groups * GROUP_BASE);
    if limit - streams_mem < groups_mem {
        return u64::MAX;
    }
    INDEX_BASE + streams_mem + groups_mem
}

/// One Index Record, as index.c's `index_record` keeps it: sums from the
/// beginning of its Stream (`unpadded_sum` adds each Unpadded Size to the
/// previous sum rounded up to four).
#[derive(Debug, Clone, Copy)]
struct Record {
    unpadded_sum: u64,
    uncompressed_sum: u64,
}

/// One Stream (`index_stream`) and what `lzma_index_iter`'s stream part
/// says of it.
#[derive(Debug)]
pub(crate) struct Stream {
    /// The check ID of its Stream Flags.
    pub(crate) check: u8,
    /// The Stream Padding after it.
    pub(crate) padding: u64,
    records: Vec<Record>,
    index_list_size: u64,
    /// 1 for the first Stream.
    pub(crate) number: u64,
    /// Where it begins in the file.
    pub(crate) compressed_offset: u64,
    /// Where its data begins in the uncompressed whole.
    pub(crate) uncompressed_offset: u64,
    /// The Blocks of the Streams before it.
    block_number_base: u64,
}

impl Stream {
    fn new() -> Stream {
        Stream {
            check: 0,
            padding: 0,
            records: Vec::new(),
            index_list_size: 0,
            number: 0,
            compressed_offset: 0,
            uncompressed_offset: 0,
            block_number_base: 0,
        }
    }

    pub(crate) fn block_count(&self) -> u64 {
        self.records.len() as u64
    }

    /// The Blocks' total size (`vli_ceil4` of the last `unpadded_sum`).
    fn blocks_size(&self) -> u64 {
        self.records.last().map_or(0, |r| ceil4(r.unpadded_sum))
    }

    pub(crate) fn uncompressed_size(&self) -> u64 {
        self.records.last().map_or(0, |r| r.uncompressed_sum)
    }

    /// Stream Header + Blocks + Index + Stream Footer, without its padding
    /// (iter_set_info).
    pub(crate) fn compressed_size(&self) -> u64 {
        2 * HEADER_SIZE + index_size(self.block_count(), self.index_list_size) + self.blocks_size()
    }

    /// index.c: index_file_size for this Stream alone, padding included;
    /// `None` past `LZMA_VLI_MAX`.
    fn file_size(&self) -> Option<u64> {
        file_size(
            0,
            self.records.last().map_or(0, |r| r.unpadded_sum),
            self.block_count(),
            self.index_list_size,
            self.padding,
        )
    }

    /// index.c: lzma_index_append, to this Stream's own Index.
    fn append(&mut self, unpadded: u64, uncompressed: u64) -> Result<(), Error> {
        let (compressed_base, uncompressed_base) = self
            .records
            .last()
            .map_or((0, 0), |r| (ceil4(r.unpadded_sum), r.uncompressed_sum));
        let list_add = vli_size(unpadded) + vli_size(uncompressed);
        if uncompressed_base + uncompressed > VLI_MAX
            || compressed_base + unpadded > UNPADDED_SIZE_MAX
        {
            return Err(Error::Data);
        }
        let count = self.block_count() + 1;
        let list = self.index_list_size + list_add;
        if file_size(0, compressed_base + unpadded, count, list, self.padding).is_none()
            || index_size(count, list) > BACKWARD_SIZE_MAX
        {
            return Err(Error::Data);
        }
        self.records.push(Record {
            unpadded_sum: compressed_base + unpadded,
            uncompressed_sum: uncompressed_base + uncompressed,
        });
        self.index_list_size = list;
        Ok(())
    }
}

/// index.c: index_file_size; `None` is its `LZMA_VLI_UNKNOWN`.
fn file_size(
    compressed_base: u64,
    unpadded_sum: u64,
    count: u64,
    list_size: u64,
    padding: u64,
) -> Option<u64> {
    let size = compressed_base
        .checked_add(2 * HEADER_SIZE + padding)?
        .checked_add(ceil4(unpadded_sum))?;
    if size > VLI_MAX {
        return None;
    }
    let size = size + index_size(count, list_size);
    (size <= VLI_MAX).then_some(size)
}

/// One Block, as `lzma_index_iter`'s block part says it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Block {
    /// The Stream it is in (an index into [`Index::streams`]).
    pub(crate) stream: usize,
    pub(crate) number_in_stream: u64,
    pub(crate) number_in_file: u64,
    pub(crate) compressed_file_offset: u64,
    pub(crate) uncompressed_file_offset: u64,
    pub(crate) unpadded_size: u64,
    pub(crate) total_size: u64,
    pub(crate) uncompressed_size: u64,
}

/// The combined Index of a whole file (`lzma_index`), Streams in file
/// order.
#[derive(Debug)]
pub(crate) struct Index {
    pub(crate) streams: Vec<Stream>,
}

impl Index {
    pub(crate) fn stream_count(&self) -> u64 {
        self.streams.len() as u64
    }

    pub(crate) fn block_count(&self) -> u64 {
        self.streams.iter().map(Stream::block_count).sum()
    }

    /// lzma_index_file_size: the whole file, the last Stream Padding
    /// included.
    pub(crate) fn file_size(&self) -> u64 {
        self.streams
            .last()
            .map_or(0, |s| s.compressed_offset + s.compressed_size() + s.padding)
    }

    pub(crate) fn uncompressed_size(&self) -> u64 {
        self.streams.iter().map(Stream::uncompressed_size).sum()
    }

    /// lzma_index_checks: a bit per check ID used.
    pub(crate) fn checks(&self) -> u32 {
        self.streams.iter().fold(0, |c, s| c | 1 << s.check)
    }

    /// The Stream Padding of every Stream (list.c: parse_indexes).
    pub(crate) fn stream_padding(&self) -> u64 {
        self.streams.iter().map(|s| s.padding).sum()
    }

    /// `lzma_index_iter_next(LZMA_INDEX_ITER_BLOCK)` from the start.
    pub(crate) fn blocks(&self) -> impl Iterator<Item = Block> + '_ {
        self.streams.iter().enumerate().flat_map(|(si, s)| {
            s.records.iter().enumerate().map(move |(ri, r)| {
                let (cbase, ubase) = match ri {
                    0 => (0, 0),
                    _ => {
                        let p = &s.records[ri - 1];
                        (ceil4(p.unpadded_sum), p.uncompressed_sum)
                    }
                };
                let unpadded_size = r.unpadded_sum - cbase;
                Block {
                    stream: si,
                    number_in_stream: ri as u64 + 1,
                    number_in_file: s.block_number_base + ri as u64 + 1,
                    compressed_file_offset: s.compressed_offset + HEADER_SIZE + cbase,
                    uncompressed_file_offset: s.uncompressed_offset + ubase,
                    unpadded_size,
                    total_size: ceil4(unpadded_size),
                    uncompressed_size: r.uncompressed_sum - ubase,
                }
            })
        })
    }
}

/// stream_flags_decoder.c: stream_flags_decode: the check ID, `None` when
/// a reserved bit is set.
fn flags_check(b: &[u8]) -> Option<u8> {
    (b[0] == 0 && b[1] & 0xF0 == 0).then_some(b[1] & 0x0F)
}

/// lzma_stream_header_decode: the check ID.
fn header_decode(b: &[u8; 12]) -> Result<u8, Error> {
    if b[..6] != HEADER_MAGIC {
        return Err(Error::Format);
    }
    if crc32(&b[6..8]) != le32(&b[8..12]) {
        return Err(Error::Data);
    }
    flags_check(&b[6..8]).ok_or(Error::Options)
}

/// lzma_stream_footer_decode: the check ID and Backward Size.
fn footer_decode(b: &[u8; 12]) -> Result<(u8, u64), Error> {
    if b[10..12] != FOOTER_MAGIC {
        return Err(Error::Format);
    }
    if crc32(&b[4..10]) != le32(&b[0..4]) {
        return Err(Error::Data);
    }
    let check = flags_check(&b[8..10]).ok_or(Error::Options)?;
    Ok((check, (u64::from(le32(&b[4..8])) + 1) * 4))
}

/// file_info.c: hide_format_error, for every Stream Header and Footer but
/// the first header.
fn hide_format(e: Error) -> Error {
    if e == Error::Format { Error::Data } else { e }
}

fn read12(src: &mut dyn Source, pos: u64) -> Result<[u8; 12], Error> {
    let mut b = [0u8; 12];
    src.read_at(pos, &mut b)?;
    Ok(b)
}

/// file_info.c: file_info_decode, all the way: the combined Index of a
/// file of `size` bytes, its Indexes held to `memlimit`
/// (`hardware_memlimit_get(MODE_LIST)`).
pub(crate) fn decode(src: &mut dyn Source, size: u64, memlimit: u64) -> Result<Index, Error> {
    let memlimit = memlimit.max(1);
    // SEQ_MAGIC_BYTES.
    if size < HEADER_SIZE {
        return Err(Error::Format);
    }
    let first_check = header_decode(&read12(src, 0)?)?;
    if size > VLI_MAX || size & 3 != 0 {
        return Err(Error::Data);
    }
    // Streams as they are decoded, last first.
    let mut found: Vec<Stream> = Vec::new();
    let (mut records_total, mut list_total, mut uncompressed_total, mut file_total) =
        (0u64, 0u64, 0u64, 0u64);
    let mut target = size;
    loop {
        // SEQ_PADDING_SEEK/_DECODE: zeros backwards, never into the first
        // Stream Header (file_info.c's window starts at 12 at the lowest).
        // reverse_seek refuses a target this low before reading anything.
        if target < 2 * HEADER_SIZE {
            return Err(Error::Data);
        }
        let padding = padding_before(src, target)?;
        target -= padding;
        if target < 2 * HEADER_SIZE {
            return Err(Error::Data);
        }
        if padding & 3 != 0 {
            return Err(Error::Data);
        }
        // SEQ_FOOTER.
        target -= HEADER_SIZE;
        let (footer_check, backward) = footer_decode(&read12(src, target)?).map_err(hide_format)?;
        if target < backward + HEADER_SIZE {
            return Err(Error::Data);
        }
        target -= backward;
        // SEQ_INDEX_INIT/_DECODE.
        let used = match found.len() {
            0 => 0,
            n => index_memusage(n as u64, records_total),
        };
        let mut stream = decode_index(src, target, backward, memlimit.saturating_sub(used).max(1))
            .map_err(|e| match e {
                Error::MemLimit { needed } => Error::MemLimit {
                    needed: used.saturating_add(needed),
                },
                e => e,
            })?;
        let seek_amount = stream.blocks_size() + HEADER_SIZE;
        if target < seek_amount {
            return Err(Error::Data);
        }
        target -= seek_amount;
        // SEQ_HEADER_DECODE: a later Stream Header overlapping the first
        // one is refused where file_info.c's reverse_seek refuses it.
        let header_check = match target {
            0 => first_check,
            t if t < HEADER_SIZE => return Err(Error::Data),
            t => header_decode(&read12(src, t)?).map_err(hide_format)?,
        };
        // SEQ_HEADER_COMPARE.
        if header_check != footer_check {
            return Err(Error::Data);
        }
        stream.check = footer_check;
        // lzma_index_stream_padding.
        if stream
            .file_size()
            .is_none_or(|f| f.saturating_add(padding) > VLI_MAX)
        {
            return Err(Error::Data);
        }
        stream.padding = padding;
        // lzma_index_cat(this, combined).
        if !found.is_empty() {
            let this_size = stream.file_size().ok_or(Error::Data)?;
            if STREAMS_MAX - 1 < found.len() as u64
                || this_size.saturating_add(file_total) > VLI_MAX
                || stream.uncompressed_size() + uncompressed_total > VLI_MAX
                || ceil4(
                    index_size_unpadded(stream.block_count(), stream.index_list_size)
                        + index_size_unpadded(records_total, list_total),
                ) > BACKWARD_SIZE_MAX
            {
                return Err(Error::Data);
            }
        }
        records_total += stream.block_count();
        list_total += stream.index_list_size;
        uncompressed_total += stream.uncompressed_size();
        file_total += stream.file_size().ok_or(Error::Data)?;
        found.push(stream);
        if target == 0 {
            break;
        }
    }
    // The Streams in file order, with their offsets and numbers.
    found.reverse();
    let (mut coff, mut uoff, mut blocks) = (0u64, 0u64, 0u64);
    for (i, s) in found.iter_mut().enumerate() {
        s.number = i as u64 + 1;
        s.compressed_offset = coff;
        s.uncompressed_offset = uoff;
        s.block_number_base = blocks;
        coff += s.compressed_size() + s.padding;
        uoff += s.uncompressed_size();
        blocks += s.block_count();
    }
    Ok(Index { streams: found })
}

/// The run of zero bytes that ends at `end`, reading back no further than
/// the end of the first Stream Header.
fn padding_before(src: &mut dyn Source, end: u64) -> Result<u64, Error> {
    let mut buf = [0u8; IO_BUFFER_SIZE];
    let mut pos = end;
    while pos > HEADER_SIZE {
        let n = (pos - HEADER_SIZE).min(IO_BUFFER_SIZE as u64) as usize;
        let chunk = &mut buf[..n];
        src.read_at(pos - n as u64, chunk)?;
        let zeros = chunk.iter().rev().take_while(|&&b| b == 0).count();
        pos -= zeros as u64;
        if zeros < n {
            break;
        }
    }
    Ok(end - pos)
}

/// index_decoder.c's states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seq {
    Indicator,
    Count,
    Unpadded,
    Uncompressed,
    PaddingInit,
    Padding,
    Crc32,
}

/// index_decoder.c: one Index of `backward` bytes at `pos`, read in
/// `IO_BUFFER_SIZE` pieces; its Records in a new [`Stream`].
fn decode_index(
    src: &mut dyn Source,
    pos: u64,
    backward: u64,
    memlimit: u64,
) -> Result<Stream, Error> {
    let mut d = IndexDecoder {
        seq: Seq::Indicator,
        memlimit,
        records_max: backward / 2,
        count: 0,
        vli: 0,
        vli_pos: 0,
        unpadded: 0,
        pos: 0,
        crc: flate2::Crc::new(),
        stream: Stream::new(),
    };
    let mut buf = [0u8; IO_BUFFER_SIZE];
    let mut done = 0u64;
    while done < backward {
        let n = (backward - done).min(IO_BUFFER_SIZE as u64) as usize;
        src.read_at(pos + done, &mut buf[..n])?;
        match d.feed(&buf[..n])? {
            // The Index ended before its Backward Size did.
            Some(used) if used < n || done + (n as u64) < backward => return Err(Error::Data),
            Some(_) => return Ok(d.stream),
            None => done += n as u64,
        }
    }
    // It wants more than its Backward Size.
    Err(Error::Data)
}

struct IndexDecoder {
    seq: Seq,
    memlimit: u64,
    /// `number_of_records_max`.
    records_max: u64,
    /// Records left to read.
    count: u64,
    vli: u64,
    vli_pos: usize,
    unpadded: u64,
    /// Padding bytes left, or the CRC32 byte being compared.
    pos: u32,
    crc: flate2::Crc,
    stream: Stream,
}

impl IndexDecoder {
    /// lzma_vli_decode, multi-call, one byte: `Some` when the integer ends.
    fn vli_byte(&mut self, b: u8) -> Result<Option<u64>, Error> {
        if self.vli_pos == 0 {
            self.vli = 0;
        }
        self.vli |= u64::from(b & 0x7F) << (self.vli_pos * 7);
        self.vli_pos += 1;
        if b & 0x80 == 0 {
            if b == 0 && self.vli_pos > 1 {
                return Err(Error::Data);
            }
            self.vli_pos = 0;
            return Ok(Some(self.vli));
        }
        if self.vli_pos == VLI_BYTES_MAX {
            return Err(Error::Data);
        }
        Ok(None)
    }

    /// index_decode over `input`: `Some(bytes used)` once the Index is
    /// complete, `None` when it wants more.
    fn feed(&mut self, input: &[u8]) -> Result<Option<usize>, Error> {
        let mut i = 0;
        let mut crc_from = 0;
        while i < input.len() {
            match self.seq {
                Seq::Indicator => {
                    i += 1;
                    if input[i - 1] != 0 {
                        return Err(Error::Data);
                    }
                    self.seq = Seq::Count;
                }
                Seq::Count => {
                    i += 1;
                    let Some(count) = self.vli_byte(input[i - 1])? else {
                        continue;
                    };
                    if count > self.records_max {
                        return Err(Error::Data);
                    }
                    // SEQ_MEMUSAGE.
                    let used = index_memusage(1, count);
                    if used > self.memlimit {
                        return Err(Error::MemLimit { needed: used });
                    }
                    self.count = count;
                    self.seq = if count == 0 {
                        Seq::PaddingInit
                    } else {
                        Seq::Unpadded
                    };
                }
                Seq::Unpadded => {
                    i += 1;
                    if let Some(v) = self.vli_byte(input[i - 1])? {
                        if !(UNPADDED_SIZE_MIN..=UNPADDED_SIZE_MAX).contains(&v) {
                            return Err(Error::Data);
                        }
                        self.unpadded = v;
                        self.seq = Seq::Uncompressed;
                    }
                }
                Seq::Uncompressed => {
                    i += 1;
                    if let Some(v) = self.vli_byte(input[i - 1])? {
                        self.stream.append(self.unpadded, v)?;
                        self.count -= 1;
                        self.seq = if self.count == 0 {
                            Seq::PaddingInit
                        } else {
                            Seq::Unpadded
                        };
                    }
                }
                Seq::PaddingInit => {
                    let unpadded =
                        index_size_unpadded(self.stream.block_count(), self.stream.index_list_size);
                    self.pos = (4 - (unpadded & 3) as u32) & 3;
                    self.seq = Seq::Padding;
                }
                Seq::Padding => {
                    if self.pos > 0 {
                        self.pos -= 1;
                        i += 1;
                        if input[i - 1] != 0 {
                            return Err(Error::Data);
                        }
                    } else {
                        self.crc.update(&input[crc_from..i]);
                        crc_from = i;
                        self.seq = Seq::Crc32;
                    }
                }
                Seq::Crc32 => {
                    let want = (self.crc.sum() >> (self.pos * 8)) as u8;
                    i += 1;
                    if input[i - 1] != want {
                        return Err(Error::Data);
                    }
                    self.pos += 1;
                    if self.pos == 4 {
                        return Ok(Some(i));
                    }
                }
            }
        }
        if self.seq != Seq::Crc32 {
            self.crc.update(&input[crc_from..]);
        }
        Ok(None)
    }
}

/// One filter of a Block Header, as its `props_decode` leaves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeaderFilter {
    /// `LZMA_FILTER_LZMA2` with its dictionary size.
    Lzma2 { dict_size: u32 },
    /// A BCJ filter (its ID) with its start offset (0 when none was
    /// stored, or a stored 0: liblzma keeps no options for either).
    Bcj { id: u64, start: u32 },
    /// `LZMA_FILTER_DELTA` with its distance.
    Delta { dist: u32 },
}

/// The filter IDs liblzma 5.8.4 decodes.
pub(crate) const FILTER_X86: u64 = 0x04;
pub(crate) const FILTER_POWERPC: u64 = 0x05;
pub(crate) const FILTER_IA64: u64 = 0x06;
pub(crate) const FILTER_ARM: u64 = 0x07;
pub(crate) const FILTER_ARMTHUMB: u64 = 0x08;
pub(crate) const FILTER_SPARC: u64 = 0x09;
pub(crate) const FILTER_ARM64: u64 = 0x0A;
pub(crate) const FILTER_RISCV: u64 = 0x0B;
const FILTER_DELTA: u64 = 0x03;
const FILTER_LZMA2: u64 = 0x21;

/// A decoded Block Header (`lzma_block` after lzma_block_header_decode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BlockHeader {
    pub(crate) header_size: u32,
    pub(crate) compressed_size: Option<u64>,
    pub(crate) uncompressed_size: Option<u64>,
    pub(crate) filters: Vec<HeaderFilter>,
}

/// lzma_vli_decode, single-call: an integer that must end inside `b`.
fn vli_single(b: &[u8], pos: &mut usize) -> Result<u64, Error> {
    if *pos >= b.len() {
        return Err(Error::Data);
    }
    let mut v = 0u64;
    let mut n = 0;
    while *pos < b.len() {
        let byte = b[*pos];
        *pos += 1;
        v |= u64::from(byte & 0x7F) << (n * 7);
        n += 1;
        if byte & 0x80 == 0 {
            if byte == 0 && n > 1 {
                return Err(Error::Data);
            }
            return Ok(v);
        }
        if n == VLI_BYTES_MAX {
            return Err(Error::Data);
        }
    }
    Err(Error::Data)
}

/// filter_decoder.c: lzma_properties_decode, for the filters liblzma
/// 5.8.4 decodes.
fn properties_decode(id: u64, props: &[u8]) -> Result<HeaderFilter, Error> {
    match id {
        // lzma2_decoder.c: lzma_lzma2_props_decode.
        FILTER_LZMA2 => {
            if props.len() != 1 || props[0] & 0xC0 != 0 || props[0] > 40 {
                return Err(Error::Options);
            }
            let dict_size = if props[0] == 40 {
                u32::MAX
            } else {
                (2 | u32::from(props[0] & 1)) << (props[0] / 2 + 11)
            };
            Ok(HeaderFilter::Lzma2 { dict_size })
        }
        // simple_decoder.c: lzma_simple_props_decode.
        FILTER_X86..=FILTER_RISCV => match props.len() {
            0 => Ok(HeaderFilter::Bcj { id, start: 0 }),
            4 => Ok(HeaderFilter::Bcj {
                id,
                start: le32(props),
            }),
            _ => Err(Error::Options),
        },
        // delta_decoder.c: lzma_delta_props_decode.
        FILTER_DELTA => match props {
            [d] => Ok(HeaderFilter::Delta {
                dist: u32::from(*d) + 1,
            }),
            _ => Err(Error::Options),
        },
        _ => Err(Error::Options),
    }
}

/// block_header_decoder.c: lzma_block_header_decode of `b`, exactly the
/// header's `(b[0] + 1) * 4` bytes, in a Stream with check `check`.
pub(crate) fn block_header_decode(b: &[u8], check: u8) -> Result<BlockHeader, Error> {
    let header_size = b.len() as u32;
    let in_size = b.len() - 4;
    if crc32(&b[..in_size]) != le32(&b[in_size..]) {
        return Err(Error::Data);
    }
    let flags = b[1];
    if flags & 0x3C != 0 {
        return Err(Error::Options);
    }
    let body = &b[..in_size];
    let mut pos = 2;
    let compressed_size = if flags & 0x40 != 0 {
        let c = vli_single(body, &mut pos)?;
        // lzma_block_unpadded_size returning 0.
        let unpadded = c + u64::from(header_size) + u64::from(CHECK_SIZES[usize::from(check)]);
        if c == 0 || unpadded > UNPADDED_SIZE_MAX {
            return Err(Error::Data);
        }
        Some(c)
    } else {
        None
    };
    let uncompressed_size = if flags & 0x80 != 0 {
        Some(vli_single(body, &mut pos)?)
    } else {
        None
    };
    let mut filters = Vec::with_capacity(4);
    for _ in 0..=(flags & 3) {
        // filter_flags_decoder.c: lzma_filter_flags_decode.
        let id = vli_single(body, &mut pos)?;
        if id >= FILTER_RESERVED_START {
            return Err(Error::Data);
        }
        let size = vli_single(body, &mut pos)?;
        if ((in_size - pos) as u64) < size {
            return Err(Error::Data);
        }
        let size = size as usize;
        filters.push(properties_decode(id, &body[pos..pos + size])?);
        pos += size;
    }
    if body[pos..].iter().any(|&b| b != 0) {
        return Err(Error::Options);
    }
    Ok(BlockHeader {
        header_size,
        compressed_size,
        uncompressed_size,
        filters,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Bytes<'a>(&'a [u8], u64);

    impl Source for Bytes<'_> {
        fn read_at(&mut self, pos: u64, buf: &mut [u8]) -> Result<(), Error> {
            let pos = usize::try_from(pos).map_err(|_| Error::Buf)?;
            let end = pos.checked_add(buf.len()).ok_or(Error::Buf)?;
            let src = self.0.get(pos..end).ok_or(Error::Buf)?;
            self.1 += buf.len() as u64;
            buf.copy_from_slice(src);
            Ok(())
        }
    }

    fn walk(b: &[u8], memlimit: u64) -> (Result<Index, Error>, u64) {
        let mut src = Bytes(b, 0);
        let r = decode(&mut src, b.len() as u64, memlimit);
        (r, src.1)
    }

    fn vli(mut n: u64, out: &mut Vec<u8>) {
        while n >= 0x80 {
            out.push(n as u8 | 0x80);
            n >>= 7;
        }
        out.push(n as u8);
    }

    /// A Stream with no Blocks whose Index is `index` (Indicator onwards;
    /// Index Padding and CRC32 appended here) and check CRC64.
    fn stream_with_index(index: &[u8]) -> Vec<u8> {
        let mut s = HEADER_MAGIC.to_vec();
        s.extend([0, 4]);
        s.extend(crc32(&[0, 4]).to_le_bytes());
        let mut idx = index.to_vec();
        while !idx.len().is_multiple_of(4) {
            idx.push(0);
        }
        idx.extend(crc32(&idx).to_le_bytes());
        s.extend(&idx);
        let mut tail = ((idx.len() / 4 - 1) as u32).to_le_bytes().to_vec();
        tail.extend([0, 4]);
        s.extend(crc32(&tail).to_le_bytes());
        s.extend(tail);
        s.extend(FOOTER_MAGIC);
        s
    }

    /// The empty Stream xz writes for empty input lists as one Stream and
    /// no Blocks; padding is counted and refused when not a multiple of 4.
    #[test]
    fn an_empty_stream_and_its_padding() {
        let s = stream_with_index(&[0, 0, 0, 0]);
        assert_eq!(s.len(), 32);
        let (idx, _) = walk(&s, u64::MAX);
        let idx = idx.unwrap();
        assert_eq!((idx.stream_count(), idx.block_count()), (1, 0));
        assert_eq!((idx.file_size(), idx.checks()), (32, 1 << 4));
        let padded = [s.clone(), vec![0; 8], s.clone(), vec![0; 4]].concat();
        let idx = walk(&padded, u64::MAX).0.unwrap();
        assert_eq!(idx.stream_count(), 2);
        assert_eq!(idx.stream_padding(), 12);
        assert_eq!(idx.streams[1].compressed_offset, 40);
        assert_eq!(idx.file_size(), padded.len() as u64);
        let odd = [s.clone(), vec![0; 3]].concat();
        assert_eq!(walk(&odd, u64::MAX).0.unwrap_err(), Error::Data);
        // Padding reaching back to the first Stream Header.
        let zeros = [&s[..12], &[0u8; 20][..]].concat();
        assert_eq!(walk(&zeros, u64::MAX).0.unwrap_err(), Error::Data);
        let mut bad = s.clone();
        bad[0] ^= 1;
        assert_eq!(walk(&bad, u64::MAX).0.unwrap_err(), Error::Format);
        let mut bad = s.clone();
        bad[31] ^= 1;
        assert_eq!(walk(&bad, u64::MAX).0.unwrap_err(), Error::Data);
    }

    /// A declared Number of Records is never trusted: past half the
    /// Backward Size it is corrupt, past the memory limit it is refused
    /// with what it would need, and within both only the Records actually
    /// read are stored.
    #[test]
    fn a_declared_count_allocates_nothing() {
        let mut index = vec![0];
        vli(1 << 40, &mut index);
        while !index.len().is_multiple_of(4) {
            index.push(0);
        }
        let s = stream_with_index(&index);
        let (r, read) = walk(&s, u64::MAX);
        assert_eq!(r.unwrap_err(), Error::Data);
        assert!(read < 100, "read {read}");
        // Within Backward Size / 2 but past the limit.
        let mut index = vec![0];
        vli(2, &mut index);
        index.extend([0; 5]);
        let s = stream_with_index(&index);
        let (r, _) = walk(&s, 8719);
        assert_eq!(r.unwrap_err(), Error::MemLimit { needed: 8720 });
        // Within both, but the Records are not there.
        let (r, _) = walk(&s, u64::MAX);
        assert_eq!(r.unwrap_err(), Error::Data);
    }

    #[test]
    fn index_memusage_is_liblzmas() {
        assert_eq!(index_memusage(1, 0), 432);
        assert_eq!(index_memusage(1, 1), 8720);
        assert_eq!(index_memusage(1, 512), 8720);
        assert_eq!(index_memusage(1, 513), 17008);
        assert_eq!(index_memusage(2, 1), 9016);
        assert_eq!(index_memusage(3, 1025), 25888);
        assert_eq!(index_memusage(1, 1 << 33), 139_049_566_640);
        assert_eq!(index_memusage(0, 1), u64::MAX);
        assert_eq!(index_memusage(1 << 32, 1), u64::MAX);
        assert_eq!(index_memusage(1, VLI_MAX + 1), u64::MAX);
    }

    /// Arbitrary bytes, and every truncation and single-bit flip of a
    /// small valid file: never a panic, and never more read than a few
    /// passes over the file.
    #[test]
    fn hostile_input_ends_cleanly() {
        let s = stream_with_index(&[0, 0, 0, 0]);
        let base = [s.clone(), vec![0; 4], s].concat();
        let mut inputs: Vec<Vec<u8>> = (0..base.len()).map(|n| base[..n].to_vec()).collect();
        for i in 0..base.len() * 8 {
            let mut b = base.clone();
            b[i / 8] ^= 1 << (i % 8);
            inputs.push(b);
        }
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        for len in [24usize, 32, 64, 100, 400, 4096, 20000] {
            for _ in 0..50 {
                let mut b = HEADER_MAGIC.to_vec();
                b.extend([0, 1]);
                b.extend(crc32(&[0, 1]).to_le_bytes());
                while b.len() < len {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    b.push(if x & 3 == 0 { 0 } else { x as u8 });
                }
                inputs.push(b);
            }
        }
        for b in &inputs {
            for limit in [1, 9000, u64::MAX] {
                let (_, read) = walk(b, limit);
                assert!(
                    read <= 4 * b.len() as u64 + 64,
                    "read {read} of {}",
                    b.len()
                );
            }
        }
    }

    #[test]
    fn block_headers_decode_as_liblzma_does() {
        fn hdr(body: &[u8]) -> Vec<u8> {
            let mut h = vec![0u8];
            h.extend(body);
            while !h.len().is_multiple_of(4) {
                h.push(0);
            }
            h[0] = ((h.len() + 4) / 4 - 1) as u8;
            h.extend(crc32(&h).to_le_bytes());
            h
        }
        let ok = block_header_decode(&hdr(&[0x00, 0x21, 1, 22]), 4).unwrap();
        assert_eq!(ok.filters, [HeaderFilter::Lzma2 { dict_size: 8 << 20 }]);
        assert_eq!((ok.compressed_size, ok.uncompressed_size), (None, None));
        let d40 = block_header_decode(&hdr(&[0x00, 0x21, 1, 40]), 4).unwrap();
        assert_eq!(
            d40.filters,
            [HeaderFilter::Lzma2 {
                dict_size: u32::MAX
            }]
        );
        let sized = block_header_decode(&hdr(&[0xC1, 9, 7, 4, 0, 0x21, 1, 0]), 1).unwrap();
        assert_eq!(
            (sized.compressed_size, sized.uncompressed_size),
            (Some(9), Some(7))
        );
        assert_eq!(sized.filters[0], HeaderFilter::Bcj { id: 4, start: 0 });
        for (body, e) in [
            (&[0x04, 0x21, 1, 22][..], Error::Options),
            (&[0x00, 0x21, 1, 41], Error::Options),
            (&[0x00, 0x21, 2, 22, 0], Error::Options),
            (&[0x00, 0x19, 0], Error::Options),
            (&[0x00, 0x21, 1, 22, 5], Error::Options),
            (
                &[
                    0x00, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x40, 0,
                ],
                Error::Data,
            ),
            (&[0x40, 0, 0x21, 1, 22], Error::Data),
            (&[0x00, 0x21, 9, 22], Error::Data),
            (&[0x00, 0x21, 0x80, 0x00], Error::Data),
            (&[0x01, 0x21, 1, 22], Error::Options),
        ] {
            assert_eq!(
                block_header_decode(&hdr(body), 4).unwrap_err(),
                e,
                "{body:?}"
            );
        }
        let mut bad = hdr(&[0x00, 0x21, 1, 22]);
        bad[3] ^= 1;
        assert_eq!(block_header_decode(&bad, 4).unwrap_err(), Error::Data);
    }
}
