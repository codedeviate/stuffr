//! `zipsplit`: zipsplit.c's `main()` after its arguments. The archive is
//! read as zip reads it (`readzip.rs`, every byte through `Host::track`),
//! the entries are divided among as many archives as are needed so that
//! none is larger than `-n` (default 36000 bytes; the end record's 22
//! bytes counted), by the better of a sequential split and a greedy one
//! (`-s`: the sequential only), and each archive is written as
//! `<name><n>.zip` (the archive's name cut to eight characters with the
//! digits), in `-b`'s directory if one is given. `-i` also writes an index
//! (`zipsplit.idx`) and counts it against the first archive, `-r` leaves
//! room on it, `-t` only reports how many archives would be made, `-p`
//! waits for a return before each (and offers to redo a disk that failed).
//! Messages go to standard output (`mesg`).
//!
//! Each output is written directly under its name (`fopen(path, "w")`, no
//! temporary); an error removes every file made so far, the index too
//! (`ziperr`). An interrupt (INT, TERM, ABRT, BUS, ILL, SEGV) prints
//! `zipsplit error: Interrupted (aborting)`, removes the index and every
//! part made, and exits 9, as the C's handler does through `ziperr`
//! (`host::arm_split_cleanup`: the handler forms the names from the
//! template itself, in pre-allocated statics).
//!
//! `zipsplit` never sets `out_path`, so a split archive, or an archive that
//! is missing, ends in the C's SIGSEGV (`strcmp(in_path, NULL)`): the same
//! `Interrupted (aborting)`, exit 9 (`readzip::null_out_crash`).
//!
//! Not reproduced: a `%` in the archive's name is a conversion in the C's
//! name template (`sprintf(name, template, n)`, undefined behaviour);
//! stuffr takes it as the character; and an error writing the index under
//! `-p`, after which the C's loop variable is the failure flag, not the
//! disk (deviation 27).

use std::io::Write;

use super::cli::{SplitOptions, ZE_OK};
use super::messages::{self as m, printf};
use super::readzip::ZFile;
use super::readzip::{self, CFile, InArchive, cstr};
use super::sink::{Closed, FileSink};
use super::split::{self, Prompt};
use super::zipcloak::fail_exit;
use super::zipfile::{self, CENHEAD, LOCHEAD, PutError, ZEntry, ZOut};
use super::zipup::write_failed;
use super::{Exit, Flavour, Zr, scan};
use crate::compat::host::{self, Host};

/// ziperr.h codes zipsplit raises.
const ZE_PARMS: i32 = 16;
const ZE_BIG: i32 = 6;
const ZE_WRITE: i32 = 14;
const ZE_NAME: i32 = 13;
const ZE_CREAT: i32 = 15;
/// zip.h:ENDHEAD plus the signature.
const END_RECORD: u64 = 18 + 4;
/// The buffer of a stdio stream opened with `fopen` (`st_blksize`).
const STDIO_BUF: usize = 4096;
/// zipsplit.c:INDEX
const INDEX: &[u8] = b"zipsplit.idx";

/// zipsplit.c:simple: the number of bins of capacity `c` needed to hold
/// the sizes `a` placed one after the other, `d` deducted from the first
/// bin; `a` becomes each item's bin.
// port: zipsplit.c:simple
fn simple(a: &mut [u64], c: u64, d: u64) -> usize {
    let (mut t, mut k) = (0u64, 0usize);
    for x in a.iter_mut() {
        let room = c.wrapping_sub(if k == 0 { d } else { 0 });
        if x.wrapping_add(t) > room {
            k += 1;
            t = 0;
        }
        t = t.wrapping_add(*x);
        *x = k as u64;
    }
    k + 1
}

/// zipsplit.c:greedy: the number of bins of capacity `c` needed when the
/// items go (largest first, with the platform's `qsort` order among equal
/// ones) each into the bin with the least room that still holds it, `d`
/// deducted from the first bin; `a` becomes each item's bin.
// port: zipsplit.c:greedy
fn greedy(z: &Zr, a: &mut [u64], c: u64, d: u64) -> usize {
    let n = a.len();
    let e: Vec<u64> = a.to_vec();
    let mut s: Vec<usize> = (0..n).collect();
    let tot = e.iter().fold(0u64, |t, &x| t.wrapping_add(x));
    // pre-decrement for the loop
    let mut m = (tot.wrapping_add(c).wrapping_sub(1) / c).wrapping_sub(1) as usize;
    // descending
    scan::qsort(z.flavour, &mut s, &|x, y| e[y].cmp(&e[x]));
    let over = c.wrapping_add(1);
    // Stuff bins until successful
    loop {
        m = m.wrapping_add(1);
        // the bins by (room, number): the smallest room that holds an
        // item, the lowest bin among equals
        let mut rooms = std::collections::BTreeSet::new();
        let mut b = vec![c; m];
        if m > 0 {
            b[0] = c.wrapping_sub(d);
        }
        for (j, &r) in b.iter().enumerate() {
            rooms.insert((r, j));
        }
        let mut i = 0;
        while i < n {
            let item = e[s[i]];
            // find smallest bin that will hold item i
            let Some(&(r, k)) = rooms.range((item, 0usize)..).next() else {
                break;
            };
            // no bin big enough for it: try the next m
            if r >= over {
                break;
            }
            // diminish that bin and save where it goes
            rooms.remove(&(r, k));
            rooms.insert((r - item, k));
            b[k] = r - item;
            a[s[i]] = k as u64;
            i += 1;
        }
        // do until all items put in a bin
        if i >= n {
            return m;
        }
    }
}

/// zipsplit.c's name template: `<up to 8 - k characters of the archive's
/// name><k digits>.zip`.
struct Template {
    prefix: Vec<u8>,
    digits: usize,
}

impl Template {
    /// `sprintf(name, template, n)`.
    fn name(&self, n: u64) -> Vec<u8> {
        let mut v = self.prefix.clone();
        v.extend_from_slice(format!("{n:0width$}.zip", width = self.digits).as_bytes());
        v
    }
}

/// What has been made, for `ziperr` to remove (`indexmade`, `zipsmade`).
struct Made {
    /// `path`: `-b`'s directory with its separator, or nothing.
    dir: Vec<u8>,
    template: Template,
    index: bool,
    parts: u64,
}

impl Made {
    /// zipsplit.c:ziperr's cleanup: the index, then every part, last first.
    fn destroy(&self, z: &Zr) {
        if self.index {
            let mut n = self.dir.clone();
            n.extend_from_slice(INDEX);
            let _ = std::fs::remove_file(z.host.path(&n));
        }
        for k in (1..=self.parts).rev() {
            let mut n = self.dir.clone();
            n.extend_from_slice(&self.template.name(k));
            let _ = std::fs::remove_file(z.host.path(&n));
        }
    }
}

/// Why a part was not made: the disk to redo, or the run's end.
enum Part {
    Redo,
    End(Exit),
}

/// zipsplit.c:retry: `Error writing to disk--redo entire disk? `. The end
/// of standard input is a no (the C's answer is whatever its buffer held).
fn retry(z: &mut Zr, p: &Prompt) -> bool {
    z.mesg_write(m::REDO_DISK.as_bytes());
    split::fgets_n(p, 10).is_some_and(|l| matches!(l.first(), Some(b'y' | b'Y')))
}

/// zipsplit.c:main, from the archive's name to the end.
// port: zipsplit.c:main
pub(crate) fn run(z: &mut Zr, o: SplitOptions) -> Exit {
    // signal(SIGINT, handler) and the others
    host::install_zip_abort(&z.host, m::SPLIT_INTERRUPTED);
    z.set_line(false);
    let zipfile = o.zipfile.clone();
    z.o.zipfile = Some(zipfile.clone());
    z.o.in_path = Some(zipfile.clone());
    z.o.out_path = Some(zipfile.clone());

    // Read zip file
    let mut ar = match readzip::read_archive(z) {
        Ok(ar) => ar,
        Err(x) => return x,
    };
    if ar.zfiles.is_empty() {
        return z.ziperr(ZE_NAME, &zipfile);
    }

    // Make a list of sizes and check against capacity. Also compute the
    // size of the index file.
    let zcount = ar.zfiles.len();
    // subtract overhead/zipfile
    let c = o.capacity.wrapping_sub(END_RECORD);
    let mut i = o.room;
    let mut a: Vec<u64> = Vec::with_capacity(zcount);
    let mut t: u64 = 0;
    for zf in &ar.zfiles {
        let e = &zf.e;
        if o.index {
            i = i.wrapping_add(e.iname.len() as i64 + 6 + 1);
        }
        // the central directory is all that is read: cext is the extra
        let sz = (8 + LOCHEAD + CENHEAD)
            .wrapping_add(2 * e.iname.len() as u64)
            .wrapping_add(2 * e.cextra.len() as u64)
            .wrapping_add(e.comment.len() as u64)
            .wrapping_add(e.siz);
        a.push(sz);
        t = t.wrapping_add(sz);
        if sz > c {
            let mut w = Vec::new();
            printf(
                &mut w,
                m::ENTRY_LARGER_THAN_MAX,
                &[c.to_string().as_bytes()],
            );
            z.zipwarn(&w, b"");
            z.zipwarn(m::USE_N_TO_SET.as_bytes(), b"");
            return z.ziperr(ZE_BIG, cstr(&zf.zname));
        }
    }

    // Decide on split to use, report number of files
    let d = i as u64;
    let s = if o.simple {
        simple(&mut a, c, d)
    } else {
        let mut p = a.clone();
        let s = simple(&mut a, c, d);
        let g = greedy(z, &mut p, c, d);
        if s <= g {
            s
        } else {
            a = p;
            g
        }
    };
    let eff = (200u64.wrapping_mul(t.wrapping_add(c).wrapping_sub(1) / c) / s as u64).div_ceil(2);
    let mut line = Vec::new();
    printf(
        &mut line,
        m::SPLIT_WILL_BE_MADE,
        &[
            s.to_string().as_bytes(),
            if o.report_only { b"ould" } else { b"ill" },
            (eff as i64).to_string().as_bytes(),
        ],
    );
    z.stdout_write(&line);
    if o.report_only {
        return Exit { code: ZE_OK };
    }

    // Set up path for output files
    let mut dir = o.tempath.clone().unwrap_or_default();
    if o.tempath.is_some() && !dir.is_empty() && dir.last() != Some(&b'/') {
        dir.push(b'/');
    }

    // Make linked lists of results
    let mut bins: Vec<Vec<usize>> = vec![Vec::new(); s];
    for (j, &g) in a.iter().enumerate() {
        bins[g as usize].push(j);
    }

    // Make a name template for the zip files that is eight or less
    // characters before the .zip, and that will not overwrite the original
    // zip file.
    let mut k = 1usize;
    let mut j = s;
    while j >= 10 {
        k += 1;
        j /= 10;
    }
    if k > 7 {
        return z.ziperr(ZE_PARMS, m::WAY_TOO_MANY.as_bytes());
    }
    // Find the final "path" separator character
    let name = cstr(&zipfile);
    let q = match name.iter().rposition(|&b| b == b'/') {
        Some(p) => &name[p + 1..],
        None => name,
    };
    let mut prefix = Vec::new();
    let mut g = 0u8;
    for &ch in q.iter().chain(std::iter::once(&0u8)) {
        g = ch;
        if g == 0 || g == b'.' || prefix.len() >= 8 - k {
            break;
        }
        prefix.push(g);
    }
    if prefix.is_empty() {
        prefix.push(b'_');
    } else if g.is_ascii_digit() {
        let last = prefix.len() - 1;
        prefix[last] = if prefix[last] == b'_' { b'-' } else { b'_' };
    }
    let mut made = Made {
        dir,
        template: Template { prefix, digits: k },
        index: false,
        parts: 0,
    };
    // an interrupt removes what has been made, as ziperr does
    let _guard = host::arm_split_cleanup(&z.host, &made.dir, &made.template.prefix, k);

    // Make the zip files from the linked lists of entry numbers
    let mut ia = InArchive { f: None };
    match CFile::open(z, &zipfile) {
        Ok(f) => ia.f = Some(f),
        Err(_) => return z.ziperr(ZE_NAME, &zipfile),
    }
    z.current_in_disk = 0;
    let p = split::prompt(z);
    let budget = match &z.host {
        Host::Sandbox(s) => Some(s.budget.clone()),
        Host::Real => None,
    };
    let mut out = ZOut::new(Box::new(Closed), z.o.force_zip64, None);
    out.unicode = z.unicode_out();
    let job = Job {
        o: &o,
        p,
        a: &a,
        bins: &bins,
        budget,
    };
    let mut j = 0usize;
    while j < s {
        match make_part(z, &mut ar.zfiles, &job, j, &mut made, &mut ia, &mut out) {
            Ok(()) => j += 1,
            // jump here on a disk retry
            Err(Part::Redo) => {}
            Err(Part::End(x)) => {
                made.destroy(z);
                return x;
            }
        }
    }

    // Done!
    if o.pause {
        z.mesg_write(m::SPLIT_DONE.as_bytes());
    }
    Exit { code: ZE_OK }
}

/// What the parts are made from.
struct Job<'a> {
    o: &'a SplitOptions,
    /// Standard input, for `-p`'s questions.
    p: Prompt,
    /// Each entry's part.
    a: &'a [u64],
    /// The entries of each part, in order.
    bins: &'a [Vec<usize>],
    budget: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
}

/// An error making a part or the index: asks to redo the disk under `-p`
/// and the answer is yes (`if (u && retry()) goto redobin`), else
/// `ziperr(code, path)` (with the system's answer when it gave one).
fn part_error(z: &mut Zr, job: &Job, code: i32, path: &[u8], e: &std::io::Error) -> Part {
    if job.o.pause && retry(z, &job.p) {
        return Part::Redo;
    }
    Part::End(z.ziperr_os(code, path, e))
}

/// zipsplit.c:main, one pass of the loop over the parts: the question under
/// `-p`, the index on the first, then part `j` (entries copied, their
/// central headers, the end record).
// port: zipsplit.c:main (redobin)
fn make_part(
    z: &mut Zr,
    zfiles: &mut [ZFile],
    job: &Job,
    j: usize,
    made: &mut Made,
    ia: &mut InArchive,
    out: &mut ZOut,
) -> Result<(), Part> {
    let s = job.bins.len();
    z.current_in_disk = 0;
    // prompt if requested
    if job.o.pause {
        let mut l = Vec::new();
        printf(
            &mut l,
            m::INSERT_DISK,
            &[(j + 1).to_string().as_bytes(), s.to_string().as_bytes()],
        );
        z.mesg_write(&l);
        let _ = split::fgets_n(&job.p, 10);
    }

    // write index file on first disk if requested
    if j == 0 && job.o.index {
        let mut path = made.dir.clone();
        path.extend_from_slice(INDEX);
        let mut l = Vec::new();
        printf(&mut l, m::SPLIT_CREATING, &[&path]);
        z.mesg_write(&l);
        made.index = true;
        host::split_progress(made.parts, made.index);
        let f = match std::fs::File::create(z.host.path(&path)) {
            Ok(f) => f,
            Err(e) => return Err(part_error(z, job, ZE_CREAT, &path, &e)),
        };
        let mut w = FileSink::stdio(
            STDIO_BUF,
            f,
            job.budget.clone(),
            z.flavour == Flavour::Apple,
        );
        let mut buf = Vec::new();
        for (idx, zf) in zfiles.iter().enumerate() {
            let n = format!("{:>5}", job.a[idx] + 1);
            printf(&mut buf, m::INDEX_LINE, &[n.as_bytes(), cstr(&zf.zname)]);
        }
        let r = w.write_all(&buf).and_then(|()| w.flush());
        if let Err(e) = r {
            return Err(part_error(z, job, ZE_WRITE, &path, &e));
        }
    }

    // create output zip file j
    let mut path = made.dir.clone();
    path.extend_from_slice(&made.template.name(j as u64 + 1));
    let mut l = Vec::new();
    printf(&mut l, m::SPLIT_CREATING, &[&path]);
    z.mesg_write(&l);
    made.parts = j as u64 + 1;
    host::split_progress(made.parts, made.index);
    let f = match std::fs::File::create(z.host.path(&path)) {
        Ok(f) => f,
        Err(e) => return Err(part_error(z, job, ZE_CREAT, &path, &e)),
    };
    out.restart(Box::new(FileSink::stdio(
        STDIO_BUF,
        f,
        job.budget.clone(),
        z.flavour == Flavour::Apple,
    )));
    let mut tempzn = 0u64;

    // write local headers and copy compressed data
    for &g in &job.bins[j] {
        if let Err(f) = readzip::zipcopy(z, ia, out, &mut tempzn, &mut zfiles[g]) {
            return Err(Part::End(fail_exit(z, f, m::NULL_TEXT.as_bytes())));
        }
    }

    // write central headers and the end of central directory record
    let mut central: Vec<ZEntry> = job.bins[j].iter().map(|&g| zfiles[g].e.clone()).collect();
    let mut at = out.w.offset();
    match zipfile::write_central_as(&mut central, b"", out, &mut at, &mut |_, _| {}, true) {
        Ok(_) => {}
        Err(PutError::Big { .. }) => {
            if job.o.pause && retry(z, &job.p) {
                return Err(Part::Redo);
            }
            return Err(Part::End(z.ziperr(ZE_WRITE, &path)));
        }
        Err(PutError::Write(err)) => return Err(Part::End(write_failed(z, &err))),
    }
    let flushed = out.w.flush();
    let failed = flushed.err().or_else(|| out.w.ferror());
    if let Some(e) = failed {
        return Err(part_error(z, job, ZE_WRITE, &path, &e));
    }
    Ok(())
}

/// [`simple`], for the tests.
#[cfg(test)]
pub(super) fn simple_for_tests(a: &mut [u64], c: u64, d: u64) -> usize {
    simple(a, c, d)
}
