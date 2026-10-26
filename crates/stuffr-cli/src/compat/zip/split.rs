//! Split archives (`fileio.c`): the names of the parts (`get_in_split_path`,
//! `get_out_split_path`), the questions zip asks about them
//! (`ask_for_split_read_path`, `ask_for_split_write_path`), and the half of
//! `bfwrite` that moves to the next split (`close_split`, `rename_split`).
//!
//! **A split being written** is a temporary (`ziXXXXXX`, in `-b`'s
//! directory or the archive's) until it is full; it is then renamed to
//! `name.z01`, `name.z02`, ... (`-s`), unless (`split_method` 1) it holds
//! the local header of the entry being written, which zip rewrites once
//! the entry is done: that split stays open until then. The last split is
//! the temporary the run publishes as `name.zip`. Only the newest
//! temporary is armed for zip's interrupt handler, as zip's handler removes
//! only `tempzip`.
//!
//! **Questions at the end of standard input (ruling Z5, deviation 18).**
//! zip reads its answers with `fgets` and does not look at what it
//! returns: at the end of standard input the buffer keeps whatever it held
//! (uninitialised at the first question), and `-FF` asks again for ever
//! (both references; gigabytes of prompts), as does Ubuntu's `-sp`. stuffr
//! never loops: the end of standard input at a question about a part to
//! read answers `q` (abort, as an explicit `q` does: measured on both
//! references), and at `-sp`'s question about where to write it answers
//! ENTER (the question has no way out but an interrupt; ENTER is what
//! Apple's build does there).

use std::cell::RefCell;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use super::cli::ZE_ABORT;
use super::messages::{self as m, printf};
use super::sink::FileSink;
use super::zipfile::{Bf, Pend, ZOut, ZWrite};
use super::{Exit, Zr};
use crate::compat::host::{self, CleanupGuard, Host};

/// ziperr.h codes this file raises.
const ZE_EOF: i32 = 2;
const ZE_FORM: i32 = 3;
const ZE_BIG: i32 = 6;
const ZE_TEMP: i32 = 10;
const ZE_WRITE: i32 = 14;
pub(crate) const ZE_OK: i32 = 0;

/// Standard input as zip's prompts read it: the process's (`None`, locked
/// for each read, so `-c`/`-z`'s reads share its buffer), or a sandbox's
/// bytes, shared by every question of the run.
pub(crate) type Prompt = Option<Rc<RefCell<Box<dyn BufRead>>>>;

/// The run's prompt stream (`stdin`), made at the first question.
pub(crate) fn prompt(z: &mut Zr) -> Prompt {
    if let Some(p) = &z.prompt {
        return p.clone();
    }
    let p = match &mut z.host {
        Host::Real => None,
        h @ Host::Sandbox(_) => {
            let r: Box<dyn BufRead> = Box::new(h.stdin());
            Some(Rc::new(RefCell::new(r)))
        }
    };
    z.prompt = Some(p.clone());
    p
}

/// `fgets(buf, n, stdin)`: at most `n - 1` bytes, up to and with a
/// newline. `None` at the end with nothing read (zip's buffer would keep
/// what it held: ruling Z5 decides what that answers).
pub(crate) fn fgets_n(p: &Prompt, n: usize) -> Option<Vec<u8>> {
    match p {
        None => fgets_from(&mut io::stdin().lock(), n),
        Some(rc) => fgets_from(&mut **rc.borrow_mut(), n),
    }
}

fn fgets_from(r: &mut dyn BufRead, n: usize) -> Option<Vec<u8>> {
    let mut line = Vec::new();
    let max = n.saturating_sub(1);
    while line.len() < max {
        let buf = match r.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        if buf.is_empty() {
            break;
        }
        let take = buf.len().min(max - line.len());
        if let Some(i) = buf[..take].iter().position(|&b| b == b'\n') {
            line.extend_from_slice(&buf[..=i]);
            r.consume(i + 1);
            return Some(line);
        }
        line.extend_from_slice(&buf[..take]);
        r.consume(take);
    }
    (!line.is_empty()).then_some(line)
}

/// An answer as zip reads it: up to the first newline, then up to the
/// first NUL (`strlen`).
fn answer(mut l: Vec<u8>) -> Vec<u8> {
    if let Some(i) = l.iter().position(|&b| b == b'\n') {
        l.truncate(i);
    }
    super::readzip::cstr(&l).to_vec()
}

/// `base` without its last three bytes (`zip`), then `zNN`: the name of
/// split `num` (1-based). `None` past 99999.
fn split_name(base: &[u8], num: u64) -> Option<Vec<u8>> {
    if num > 99999 {
        return None;
    }
    let mut p = base[..base.len().saturating_sub(3)].to_vec();
    p.extend_from_slice(format!("z{num:02}").as_bytes());
    Some(p)
}

/// fileio.c:get_in_split_path: the path of disk `disk` (0-based) of the
/// archive whose last part is `base`: `base` itself for the last disk
/// (`total_disks`), else `.z01`, `.z02`, ...
// port: fileio.c:get_in_split_path
pub(crate) fn get_in_split_path(z: &mut Zr, base: &[u8], disk: u64) -> Result<Vec<u8>, Exit> {
    let num = disk.wrapping_add(1);
    if num == z.total_disks {
        return Ok(base.to_vec());
    }
    split_name(base, num).ok_or_else(|| z.ziperr(ZE_BIG, m::MORE_THAN_99999.as_bytes()))
}

/// fileio.c:get_out_split_path: `.z01`, `.z02`, ... for disk `disk`.
// port: fileio.c:get_out_split_path
fn get_out_split_path(base: &[u8], disk: u64) -> Option<Vec<u8>> {
    split_name(base, disk.wrapping_add(1))
}

/// The directory part of `p`: up to its last `/`, `\` or `:`, with it;
/// `None` when it has none.
fn dir_of(p: &[u8], seps: &[u8]) -> Option<usize> {
    p.iter().rposition(|b| seps.contains(b)).map(|i| i + 1)
}

/// fileio.c:ask_for_split_read_path: the part `current_disk` of the
/// archive being read could not be opened; ask where it is. `ZE_OK` once
/// it can be opened (`z.o.in_path` may have changed), `ZE_ABORT` (`q`),
/// `ZE_FORM` (`s`, under `-F`/`-FF`: skip it), `ZE_EOF` (`e`, `-FF`: no
/// more parts). The end of standard input answers `q` (ruling Z5).
// port: fileio.c:ask_for_split_read_path
pub(crate) fn ask_for_split_read_path(z: &mut Zr, current_disk: u64) -> Result<i32, Exit> {
    let fix = z.o.fix;
    let maxpath = super::flavour::fnmax(z.flavour) + 4010;
    let p = prompt(z);
    let mut in_path = z.o.in_path.clone().unwrap_or_default();
    let mut split_path = get_in_split_path(z, &in_path, current_disk)?;
    // the name of the archive, without its directory
    let archive_name = match dir_of(&in_path, b"/\\:") {
        Some(i) => in_path[i..].to_vec(),
        None => in_path.clone(),
    };
    let mut is_readable = false;
    let mut s = Vec::new();
    printf(&mut s, m::COULD_NOT_FIND, &[&split_path]);
    z.mesg_write(&s);
    loop {
        let mut q = m::HIT_C.as_bytes().to_vec();
        if is_readable {
            q.extend_from_slice(m::HIT_Q.as_bytes());
            q.extend_from_slice(m::HIT_ENTER_CONTINUE.as_bytes());
        } else if fix == 1 {
            q.extend_from_slice(m::HIT_S.as_bytes());
            q.extend_from_slice(m::HIT_Q.as_bytes());
            q.extend_from_slice(m::HIT_ENTER_AGAIN.as_bytes());
        } else if fix == 2 {
            q.extend_from_slice(m::HIT_S.as_bytes());
            q.extend_from_slice(m::HIT_Q.as_bytes());
            q.extend_from_slice(m::HIT_E.as_bytes());
            q.extend_from_slice(m::HIT_Z.as_bytes());
            q.extend_from_slice(m::HIT_ENTER_AGAIN.as_bytes());
        } else {
            q.extend_from_slice(m::HIT_Q.as_bytes());
            q.extend_from_slice(m::HIT_ENTER_AGAIN.as_bytes());
        }
        z.mesg_write(&q);
        // ruling Z5: the end of standard input answers q
        let Some(l) = fgets_n(&p, maxpath) else {
            return Ok(ZE_ABORT);
        };
        let mut buf = answer(l);
        let first = buf.first().map(u8::to_ascii_uppercase);
        if first == Some(b'Q') {
            return Ok(ZE_ABORT);
        } else if (fix == 1 || fix == 2) && first == Some(b'S') {
            z.skip_this_disk = z.current_in_disk + 1;
            return Ok(ZE_FORM);
        } else if first == Some(b'C') {
            z.mesg_write(m::ENTER_SPLIT_PATH.as_bytes());
            let Some(l) = fgets_n(&p, maxpath) else {
                return Ok(ZE_ABORT);
            };
            is_readable = false;
            buf = answer(l);
            if buf.is_empty() {
                // ENTER: the same path again (removable media changed)
                buf = split_path.clone();
            }
        } else if fix == 2 && first == Some(b'E') {
            return Ok(ZE_EOF);
        } else if fix == 2 && first == Some(b'Z') {
            z.total_disks = current_disk + 1;
            split_path = get_in_split_path(z, &in_path, current_disk)?;
            buf = split_path.clone();
            buf.truncate(maxpath);
        }
        if !buf.is_empty() {
            // a new place: its directory, then the archive's name
            if buf == b"." {
                buf.clear();
            }
            match dir_of(&buf, b"/\\:") {
                None => in_path = archive_name.clone(),
                Some(i) => {
                    buf.truncate(i);
                    // only up to a `/` this time
                    let d = dir_of(&buf, b"/").unwrap_or(0);
                    buf.truncate(d);
                    in_path = buf.clone();
                    in_path.extend_from_slice(&archive_name);
                }
            }
            z.o.in_path = Some(in_path.clone());
            split_path = get_in_split_path(z, &in_path, current_disk)?;
            if !readable(z, &split_path) {
                let mut s = Vec::new();
                printf(&mut s, m::COULD_NOT_FIND_OR_OPEN, &[&split_path]);
                z.mesg_write(&s);
                continue;
            }
            is_readable = true;
            let mut s = Vec::new();
            printf(&mut s, m::FOUND_SPLIT, &[&split_path]);
            z.mesg_write(&s);
        } else {
            if !readable(z, &split_path) {
                let mut s = Vec::new();
                printf(&mut s, m::COULD_NOT_FIND_OR_OPEN, &[&split_path]);
                z.mesg_write(&s);
                continue;
            }
            let mut s = Vec::new();
            printf(&mut s, m::FOUND_SPLIT_NL, &[&split_path]);
            z.mesg_write(&s);
            return Ok(ZE_OK);
        }
    }
}

/// `fopen(path, "r")` succeeds (through `Host::track`, nothing read).
fn readable(z: &Zr, path: &[u8]) -> bool {
    super::readzip::CFile::open(z, path).is_ok()
}

// ---- writing splits ----

/// Where the split writer makes its files: a sandbox's directory and
/// output budget, or the process's.
pub(crate) struct SplitEnv {
    pub(crate) dir: Option<PathBuf>,
    pub(crate) budget: Option<Arc<AtomicU64>>,
}

impl SplitEnv {
    pub(crate) fn of(h: &Host) -> SplitEnv {
        match h {
            Host::Real => SplitEnv {
                dir: None,
                budget: None,
            },
            Host::Sandbox(s) => SplitEnv {
                dir: Some(s.dir.clone()),
                budget: Some(s.budget.clone()),
            },
        }
    }

    pub(crate) fn path(&self, b: &[u8]) -> PathBuf {
        match &self.dir {
            None => host::path(b),
            Some(d) => d.join(host::path(b)),
        }
    }
}

/// A split kept open for its local header's rewrite (`current_local_file`,
/// `current_local_tempname`).
pub(crate) struct LocalSplit {
    pub(crate) w: Box<dyn ZWrite>,
    pub(crate) tempname: Vec<u8>,
}

/// The splits being written (`split_method`, `split_size`, the split
/// options, `out_path`, `tempzip`).
pub(crate) struct SplitW {
    /// 1: `-s` (local headers rewritten); 2: `-sp` (descriptors, a question
    /// before each split).
    pub(crate) method: i8,
    pub(crate) bell: bool,
    pub(crate) noisy_splits: bool,
    /// `out_path`, which `-sp`'s answers change.
    pub(crate) out_path: Vec<u8>,
    /// The directory new temporaries go to (`-b`'s, or the archive's).
    pub(crate) temp_dir: Vec<u8>,
    pub(crate) env: SplitEnv,
    /// `tempzip`: the current split's temporary name, and its guard.
    pub(crate) tempzip: Vec<u8>,
    pub(crate) guard: Option<CleanupGuard>,
    /// The current temporary is removed when the run fails (`destroy`).
    pub(crate) published: bool,
    /// `current_local_file` when it is not the current split.
    pub(crate) local: Option<LocalSplit>,
    /// Splits zip lost track of (a local header split never rewritten, as
    /// with `-fd`): left under their temporary names, as zip leaves them.
    pub(crate) lost: Vec<LocalSplit>,
    /// `zip_attributes`: the mode each split is given once renamed.
    pub(crate) zip_attributes: u32,
    pub(crate) prompt: Prompt,
    pub(crate) fnmax: usize,
}

impl Drop for SplitW {
    fn drop(&mut self) {
        // ziperr: destroy(tempzip); the local split's file is closed only
        self.guard = None;
        if !self.published {
            let _ = std::fs::remove_file(self.env.path(&self.tempzip));
        }
    }
}

/// A failure inside `bfwrite`'s split half, carried in an `io::Error` to
/// whoever ends the run (`zipup::write_failed`): `ZIPERR(code, text)`, the
/// `zip I/O error:` line's system answer for the codes that print one, and
/// zip's warning before it.
#[derive(Debug)]
pub(crate) struct SplitFail {
    pub(crate) code: i32,
    pub(crate) text: Vec<u8>,
    pub(crate) os: Option<io::Error>,
    pub(crate) warn: Option<(Vec<u8>, Vec<u8>)>,
}

impl std::fmt::Display for SplitFail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "split failure {}", self.code)
    }
}

impl std::error::Error for SplitFail {}

fn split_fail(code: i32, text: &[u8], os: Option<io::Error>) -> io::Error {
    io::Error::other(SplitFail {
        code,
        text: text.to_vec(),
        os,
        warn: None,
    })
}

/// The run's end for a [`SplitFail`] carried by `err`, if it carries one.
pub(crate) fn split_fail_exit(z: &mut Zr, err: &io::Error) -> Option<Exit> {
    let f = err.get_ref()?.downcast_ref::<SplitFail>()?;
    if let Some((a, b)) = &f.warn {
        z.zipwarn(a, b);
    }
    Some(match &f.os {
        Some(e) if super::zipup::perr(f.code) => z.ziperr_os(f.code, &f.text, e),
        _ => z.ziperr(f.code, &f.text),
    })
}

impl SplitW {
    /// A new local header goes to the current split: a local split still
    /// open is lost track of (zip overwrites `current_local_file`).
    pub(crate) fn local_header_starts(&mut self) {
        if let Some(l) = self.local.take() {
            self.lost.push(l);
        }
    }

    /// fileio.c:close_split: close `w` and rename it (`tempname`) to the
    /// name of split `disk`, with `-sv`'s message.
    // port: fileio.c:close_split
    fn close_split(
        &mut self,
        pending: &mut Vec<Pend>,
        disk: u64,
        mut w: Box<dyn ZWrite>,
        tempname: &[u8],
    ) -> io::Result<()> {
        let Some(split_path) = get_out_split_path(&self.out_path, disk) else {
            return Err(split_fail(ZE_BIG, m::MORE_THAN_99999.as_bytes(), None));
        };
        if self.noisy_splits {
            let mut l = m::CLOSING_SPLIT.as_bytes().to_vec();
            l.extend_from_slice(&split_path);
            pending.push(Pend::Message(l));
        }
        // fclose: a buffered write failing here is not looked at by zip
        let _ = w.flush();
        drop(w);
        // zip.c:rename_split
        let to = self.env.path(&split_path);
        if let Err((code, e)) = super::sink::replace(&to, &self.env.path(tempname)) {
            return Err(io::Error::other(SplitFail {
                code,
                text: m::WAS_REPLACING_SPLIT.as_bytes().to_vec(),
                os: Some(e),
                warn: Some((m::NEW_ZIP_LEFT_AS.as_bytes().to_vec(), tempname.to_vec())),
            }));
        }
        if self.zip_attributes != 0 {
            super::write::set_mode(&to, self.zip_attributes);
        }
        Ok(())
    }

    /// fileio.c:ask_for_split_write_path: before split `current_disk`
    /// (`-sp`), where to write it. The end of standard input answers ENTER
    /// (ruling Z5).
    // port: fileio.c:ask_for_split_write_path
    fn ask_for_split_write_path(&mut self, pending: &mut Vec<Pend>, current_disk: u64) {
        let num = (current_disk as u32).wrapping_add(1);
        // a name with no directory leaves the directory the whole name and
        // the name empty (the C's loop finds no separator)
        let (split_dir, mut split_name) = match dir_of(&self.out_path, b"/\\:") {
            Some(i) => (self.out_path[..i].to_vec(), self.out_path[i..].to_vec()),
            None => (m::CURRENT_DIRECTORY.as_bytes().to_vec(), Vec::new()),
        };
        pending.push(Pend::NlIfLine);
        let mut s = Vec::new();
        printf(
            &mut s,
            m::OPENING_DISK,
            &[num.to_string().as_bytes(), &split_dir],
        );
        pending.push(Pend::Raw(s));
        loop {
            pending.push(Pend::Raw(m::SPLIT_PATH_PROMPT.as_bytes().to_vec()));
            // ruling Z5: the end of standard input answers ENTER
            let Some(l) = fgets_n(&self.prompt, self.fnmax) else {
                break;
            };
            let mut buf = answer(l);
            if buf.is_empty() {
                break;
            }
            if buf == b"." {
                buf.clear();
            }
            match dir_of(&buf, b"/\\:") {
                None => {
                    buf = m::CURRENT_DIRECTORY.as_bytes().to_vec();
                    self.out_path = split_name.clone();
                }
                Some(i) => {
                    buf.truncate(i);
                    let d = dir_of(&buf, b"/").unwrap_or(0);
                    buf.truncate(d);
                    let mut o = buf.clone();
                    o.extend_from_slice(&split_name);
                    self.out_path = o;
                }
            }
            let mut s = Vec::new();
            printf(&mut s, m::WRITING_TO, &[&buf]);
            pending.push(Pend::Raw(s));
            // the C's loop again: no `/`, no name
            split_name = match dir_of(&self.out_path, b"/") {
                Some(i) => self.out_path[i..].to_vec(),
                None => Vec::new(),
            };
        }
    }

    /// `mkstemp` of the next split's temporary, armed in place of the
    /// previous one.
    fn open_temp(&mut self) -> io::Result<Box<dyn ZWrite>> {
        // only the newest temporary is zip's `tempzip`
        self.guard = None;
        let env = &self.env;
        let (name, r) =
            super::sink::mkstemp_with(env.dir.is_none(), &|b: &[u8]| env.path(b), &self.temp_dir);
        self.tempzip = name;
        match r {
            Err(e) => Err(split_fail(ZE_TEMP, &self.tempzip.clone(), Some(e))),
            Ok((f, guard)) => {
                self.guard = Some(guard);
                Ok(Box::new(FileSink::new(f, self.env.budget.clone())))
            }
        }
    }
}

impl ZOut {
    /// fileio.c:bfwrite, the split half: `rest` did not fit in the current
    /// split (or its write failed: `err`); close the split (or keep it for
    /// its local header), open the next and write `rest` there.
    // port: fileio.c:bfwrite
    pub(crate) fn next_split(
        &mut self,
        rest: &[u8],
        mode: Bf,
        err: Option<io::Error>,
    ) -> io::Result<()> {
        let header = mode != Bf::Data;
        let mut sp = self.split.take().expect("splitting");
        let r = (|| -> io::Result<()> {
            self.bytes_prev_splits += self.w.offset();
            if let Some(e) = err {
                if sp.method == 1 {
                    // writing all splits to the same place: bad
                    return Err(split_fail(
                        ZE_WRITE,
                        m::COULD_NOT_WRITE_SPLIT.as_bytes(),
                        Some(e),
                    ));
                }
                // a split must be at least 64K, except the last
                if self.w.offset() < 64 * 0x400 {
                    return Err(split_fail(
                        ZE_WRITE,
                        m::NOT_ENOUGH_SPACE_SPLIT.as_bytes(),
                        Some(e),
                    ));
                }
            }
            let old = std::mem::replace(&mut self.w, Box::new(super::sink::Closed));
            let oldname = sp.tempzip.clone();
            if sp.method == 1 && self.current_local_disk == self.current_disk {
                // keep this split open so its local header can be updated
                sp.local = Some(LocalSplit {
                    w: old,
                    tempname: oldname,
                });
            } else {
                sp.close_split(&mut self.pending, self.current_disk, old, &oldname)?;
                sp.published = true;
            }
            self.cd_entries_this_disk = 0;
            self.current_disk += 1;
            if sp.method == 2 && sp.bell {
                // bell when pausing to ask for the next split
                self.pending.push(Pend::Raw(b"\x07".to_vec()));
            }
            if sp.method == 2 {
                sp.ask_for_split_write_path(&mut self.pending, self.current_disk);
            }
            self.w = sp.open_temp()?;
            sp.published = false;
            let r = self.w.write_all(rest);
            let n = if r.is_ok() { rest.len() } else { 0 };
            if !header {
                self.bytes_this_entry += n as u64;
            }
            if let Err(e) = r {
                // the buffer is bigger than a split
                if sp.method == 2 {
                    self.pending.push(Pend::Message({
                        let mut l = Vec::new();
                        printf(
                            &mut l,
                            m::ZIP_WARNING,
                            &[m::NOT_ENOUGH_ROOM.as_bytes(), b""],
                        );
                        l.pop();
                        l
                    }));
                }
                return Err(split_fail(ZE_WRITE, m::NOT_ENOUGH_ROOM.as_bytes(), Some(e)));
            }
            if header {
                if sp.method == 1 && self.current_local_disk != self.current_disk {
                    // the header did not fit in the last split: that one
                    // can be closed now
                    if let Some(l) = sp.local.take() {
                        sp.close_split(
                            &mut self.pending,
                            self.current_local_disk,
                            l.w,
                            &l.tempname,
                        )?;
                    }
                }
                self.current_local_offset = 0;
                self.current_local_disk = self.current_disk;
            }
            Ok(())
        })();
        self.split = Some(sp);
        r
    }

    /// zipfile.c:putlocal's rewrite under `-s`: to the split with the local
    /// header (the current one, or the one kept open for it), which is then
    /// closed if it is not the current one.
    pub(crate) fn rewrite_in_local_split(&mut self, b: &[u8]) -> io::Result<()> {
        let mut sp = self.split.take().expect("splitting");
        let r = (|| -> io::Result<()> {
            match sp.local.as_mut() {
                Some(l) => l.w.write_here(b)?,
                None => self.w.write_here(b)?,
            }
            if self.current_local_disk != self.current_disk
                && let Some(l) = sp.local.take()
            {
                sp.close_split(&mut self.pending, self.current_local_disk, l.w, &l.tempname)?;
            }
            Ok(())
        })();
        self.split = Some(sp);
        r
    }

    /// zipup.c's seek of `current_local_file` to the local header, when it
    /// is not the current split.
    pub(crate) fn seek_local_split(&mut self, at: u64) -> io::Result<()> {
        match self.split.as_mut() {
            Some(s) if s.method == 1 => match s.local.as_mut() {
                Some(l) => l.w.seek_to(at),
                None => Ok(()),
            },
            _ => Ok(()),
        }
    }

    /// zipfile.c:zipcopy's end under `-s`: the split with the local header
    /// can be closed once the entry is copied.
    pub(crate) fn close_local_split(&mut self) -> io::Result<()> {
        let Some(mut sp) = self.split.take() else {
            return Ok(());
        };
        let r = if sp.method == 1 && self.current_local_disk != self.current_disk {
            match sp.local.take() {
                Some(l) => {
                    sp.close_split(&mut self.pending, self.current_local_disk, l.w, &l.tempname)
                }
                None => Ok(()),
            }
        } else {
            Ok(())
        };
        self.split = Some(sp);
        r
    }
}

/// zip.c:main's `ZIPERR(ZE_ABORT, ...)` and friends for the split prompts:
/// the code an answer gave, as `scanzipf_*` returns it.
pub(crate) fn is_abort(code: i32) -> bool {
    code == ZE_ABORT
}

/// The codes an answer can give besides `ZE_OK`.
pub(crate) const ANSWER_EOF: i32 = ZE_EOF;
pub(crate) const ANSWER_SKIP: i32 = ZE_FORM;

#[cfg(test)]
mod tests;
