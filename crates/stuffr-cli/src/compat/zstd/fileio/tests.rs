//! fileio.rs unit tests: the read pool's job rule, the sparse writer's
//! 32 KiB segment rule, the names, and the parameter bounds the pure tier
//! answers with.

use std::ffi::OsString;

use super::*;
use crate::compat::host::Cores;
use crate::compat::zstd::cli;

/// A reader handing out at most `step` bytes per `read`, as a pipe does.
struct Trickle {
    data: Vec<u8>,
    at: usize,
    step: usize,
}

impl Read for Trickle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.step.min(buf.len()).min(self.data.len() - self.at);
        buf[..n].copy_from_slice(&self.data[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

fn pool(data: Vec<u8>, job: usize) -> ReadPool {
    ReadPool::new(
        Box::new(Trickle {
            data,
            at: 0,
            step: 7,
        }),
        job,
    )
}

#[test]
fn a_fill_reads_one_whole_job_when_fewer_than_asked_are_loaded() {
    let mut rp = pool((0..100u8).collect(), 32);
    // Nothing loaded: one whole job, however the reads trickle.
    assert_eq!(rp.fill(4).unwrap(), 32);
    assert_eq!(rp.loaded().len(), 32);
    // Enough loaded: nothing read.
    assert_eq!(rp.fill(32).unwrap(), 0);
    rp.consume(30);
    // Two left, four asked: the next job is appended to them.
    assert_eq!(rp.fill(4).unwrap(), 32);
    assert_eq!(rp.loaded(), &(30..64u8).collect::<Vec<_>>()[..]);
    // A request above the job size is the job size.
    rp.consume(34);
    assert_eq!(rp.fill(1000).unwrap(), 32);
    rp.consume(32);
    // The short last job, then end of input, sticky.
    assert_eq!(rp.fill(1).unwrap(), 4);
    rp.consume(4);
    assert_eq!(rp.fill(1).unwrap(), 0);
    assert_eq!(rp.fill(1).unwrap(), 0);
    assert!(rp.loaded().is_empty());
}

/// A scratch directory removed on drop.
struct Dir(std::path::PathBuf);
impl Dir {
    fn new(tag: &str) -> Dir {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "stuffr-zstd-fileio-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        Dir(d)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn command(args: &[&str]) -> Command {
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    cli::parse("zstd", &|_| None, &args, Cores::SANDBOX, &mut out, &mut err).expect("parses")
}

/// Write `blocks` through the sparse writer (`--sparse`) into a real file
/// and return the file's bytes and its allocated size in 512-byte blocks.
fn sparse_write(dir: &Dir, blocks: &[Vec<u8>]) -> (Vec<u8>, u64) {
    let cmd = command(&["--sparse", "-d"]);
    let mut host = Host::Real;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut io = Io::new(&cmd, &mut host, &mut out, &mut err);
    assert_eq!(io.prefs.sparse, 2);
    let path = dir.0.join("sparse");
    io.sink = Sink::File(Box::new(FileSink {
        w: FileW::Raw(File::create(&path).unwrap()),
        tmp: None,
        path: path.clone(),
        name: b"sparse".to_vec(),
        guard: None,
    }));
    for b in blocks {
        io.write_block(b).unwrap();
    }
    io.sparse_end().unwrap();
    let (closed, _) = io.close_sink().unwrap();
    closed.unwrap();
    drop(io);
    assert!(err.is_empty());
    #[cfg(unix)]
    let allocated = {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(&path).unwrap().blocks()
    };
    #[cfg(not(unix))]
    let allocated = 0;
    (fs::read(&path).unwrap(), allocated)
}

#[test]
fn the_sparse_writer_keeps_the_bytes_and_ends_with_an_explicit_zero() {
    let d = Dir::new("sparse");
    // Leading zero words of each 32 KiB segment are skipped; a trailing
    // run of zeros ends with one written zero, so the size is right.
    let mut a = vec![0u8; 100_000];
    a[40_000] = 9;
    a[40_001] = 8;
    let b = vec![0u8; 70_003];
    let mut c = vec![0u8; 13];
    c[12] = 5;
    let (bytes, _) = sparse_write(&d, &[a.clone(), b.clone(), c.clone()]);
    let want: Vec<u8> = [a, b, c].concat();
    assert_eq!(bytes.len(), want.len());
    assert!(bytes == want);
    // All zeros: the file is its size, as zeros.
    let (bytes, _) = sparse_write(&d, &[vec![0u8; 5000]]);
    assert_eq!(bytes, vec![0u8; 5000]);
    // A tail shorter than a word.
    let (bytes, _) = sparse_write(&d, &[vec![1, 0, 0]]);
    assert_eq!(bytes, vec![1, 0, 0]);
}

#[test]
fn the_names_follow_the_suffix_rules() {
    assert_eq!(compressed_name(b"a", None, ".zst"), b"a.zst");
    assert_eq!(compressed_name(b"d/a", Some(b"o"), ".zst"), b"o/a.zst");
    assert_eq!(compressed_name(b"d/a", Some(b"o/"), ".zst"), b"o/a.zst");
    assert_eq!(compressed_name(STDINMARK, Some(b"o"), ".zst"), STDOUTMARK);
    let cmd = command(&["-d"]);
    let mut host = Host::Real;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut io = Io::new(&cmd, &mut host, &mut out, &mut err);
    let mut name = |src: &[u8], dir: Option<&[u8]>| decompressed_name(&mut io, src, dir);
    assert_eq!(name(b"a.zst", None).unwrap(), b"a");
    assert_eq!(name(b"a.tzst", None).unwrap(), b"a.tar");
    assert_eq!(name(b"a.zstd", None).unwrap(), b"a");
    assert_eq!(name(b"a.tlz4", None).unwrap(), b"a.tar");
    assert_eq!(name(b"d/a.gz", Some(b"o")).unwrap(), b"o/a");
    assert!(name(b".zst", None).is_none());
    assert!(name(b"a", None).is_none());
    assert!(name(b"a.ZST", None).is_none());
    assert!(name(b"d.x/a", None).is_none());
    drop(io);
    let err = String::from_utf8(err).unwrap();
    assert_eq!(err.matches("unknown suffix").count(), 4, "{err}");
}

#[test]
fn parameter_bounds_are_libzstds() {
    let ok = |o: &EncodeOptions| check_cparam_bounds(o).is_ok();
    let with = |k: CParamKey, v: u32| EncodeOptions {
        overrides: vec![(k, v)],
        ..EncodeOptions::default()
    };
    assert!(ok(&EncodeOptions::default()));
    assert!(ok(&with(CParamKey::Strategy, 9)));
    assert!(!ok(&with(CParamKey::Strategy, 10)));
    assert!(!ok(&with(CParamKey::WindowLog, 9)));
    assert!(ok(&with(CParamKey::WindowLog, 31)));
    assert!(!ok(&with(CParamKey::MinMatch, 8)));
    assert!(ok(&with(CParamKey::TargetLength, 1 << 17)));
    assert!(!ok(&with(CParamKey::TargetLength, (1 << 17) + 1)));
    // A target block size below the minimum is raised to it; above the
    // maximum it is out of bound.
    let tcb = |v| EncodeOptions {
        target_cblock_size: v,
        ..EncodeOptions::default()
    };
    assert!(ok(&tcb(1)));
    assert!(ok(&tcb(u32::MAX)), "(int)-1 is raised to the minimum");
    assert!(!ok(&tcb(200_000)));
    let ldm = |l: Ldm| EncodeOptions {
        ldm_params: l,
        ..EncodeOptions::default()
    };
    assert!(!ok(&ldm(Ldm {
        hash_rate_log: 26,
        ..Ldm::default()
    })));
    assert!(ok(&ldm(Ldm {
        hash_rate_log: 25,
        ..Ldm::default()
    })));
}

#[test]
fn highbit64_is_fio_highbit64() {
    assert_eq!(highbit64(1), 0);
    assert_eq!(highbit64(2), 1);
    assert_eq!(highbit64(3), 1);
    assert_eq!(highbit64(1 << 31), 31);
    assert_eq!(highbit64(u64::MAX), 63);
}

/// The SIGINT bit of a `/proc/<pid>/task/<tid>/status` `SigBlk` mask, or
/// `None` when the task is gone.
#[cfg(all(target_os = "linux", feature = "zstd-c"))]
fn sigint_blocked(tid: &str) -> Option<bool> {
    let status = fs::read_to_string(format!("/proc/self/task/{tid}/status")).ok()?;
    let hex = status
        .lines()
        .find_map(|l| l.strip_prefix("SigBlk:"))?
        .trim();
    let mask = u64::from_str_radix(hex, 16).expect("SigBlk is hex");
    Some(mask & (1 << (libc::SIGINT - 1)) != 0)
}

/// The tasks of this process named `name` (`/proc` `comm`) other than
/// `me`, with whether each has SIGINT blocked.
#[cfg(all(target_os = "linux", feature = "zstd-c"))]
fn named_tasks(name: &str, me: &str) -> Vec<(String, bool)> {
    let mut found = Vec::new();
    for entry in fs::read_dir("/proc/self/task").unwrap() {
        let tid = entry.unwrap().file_name().into_string().unwrap();
        if tid == me {
            continue;
        }
        let comm = fs::read_to_string(format!("/proc/self/task/{tid}/comm")).unwrap_or_default();
        if comm.trim_end() != name {
            continue;
        }
        if let Some(blocked) = sigint_blocked(&tid) {
            found.push((tid, blocked));
        }
    }
    found
}

/// `compress_step`'s hold, through `compress_zstd_frame` (the production
/// path): libzstd's workers are born with SIGINT blocked, so the SIGINT
/// `create_temp_armed_exit` holds back for a later file can only reach the
/// main thread; and the calling thread's own mask is put back.
///
/// Linux only: macOS has no view of another thread's signal mask. The
/// compression runs on a thread of its own with a name nothing else in the
/// test binary uses; a new thread inherits its creator's name (`comm`), so
/// libzstd's workers are exactly the other tasks that carry it, whatever
/// other tests start meanwhile.
///
/// Two frames on one context, as two files would be: the first is too
/// small for workers (`ZSTDMT_JOBSIZE_MIN`, 512 KiB), so libzstd creates its
/// pool on the second frame's first call. Holding only the run's first call
/// would fail here.
#[cfg(all(target_os = "linux", feature = "zstd-c"))]
#[test]
fn libzstd_workers_are_born_with_sigint_blocked() {
    const NAME: &str = "stuffr-zsigblk";
    std::thread::Builder::new()
        .name(NAME.into())
        .spawn(|| {
            // SAFETY: gettid takes no arguments and cannot fail.
            let me = unsafe { libc::gettid() }.to_string();
            // A launcher may hand the test process SIGINT already blocked
            // (the mask survives exec): start from a known unblocked state.
            // SAFETY: sigset_t is plain data set by sigemptyset/sigaddset;
            // only this thread's mask changes.
            unsafe {
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, libc::SIGINT);
                libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
            }
            assert_eq!(
                sigint_blocked(&me),
                Some(false),
                "the test starts unblocked"
            );
            let cmd = command(&["-T2"]);
            assert_eq!(cmd.prefs.workers, 2);
            let mut host = Host::Real;
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let mut io = Io::new(&cmd, &mut host, &mut out, &mut err);
            // Into `out`, a vector: no sparse seeks.
            io.prefs.sparse = 0;
            io.sink = Sink::Stdout;
            let mut ress = io
                .create_cresources(&cmd, FILESIZE_UNKNOWN, cmd.level)
                .expect("the context");
            let mut seed = 0x2545_f491_4f6c_dd1du64;
            for (frame, len) in [(1, 64usize << 10), (2, 2 << 20)] {
                // Text-like noise: compressible, not trivially.
                let data: Vec<u8> = (0..len)
                    .map(|_| {
                        seed ^= seed << 13;
                        seed ^= seed >> 7;
                        seed ^= seed << 17;
                        b"abcdefgh ijklmnop"[(seed % 17) as usize]
                    })
                    .collect();
                let mut rp = ReadPool::new(Box::new(io::Cursor::new(data)), CSTREAM_IN_SIZE);
                let mut read = 0;
                io.compress_zstd_frame(&mut ress, &mut rp, b"in", len as u64, &mut read)
                    .expect("compresses");
                assert_eq!(read, len as u64);
                let workers = named_tasks(NAME, &me);
                if frame == 1 {
                    assert!(workers.is_empty(), "frame 1 started workers: {workers:?}");
                } else {
                    assert!(workers.len() >= 2, "no libzstd workers seen: {workers:?}");
                    let unblocked: Vec<_> = workers.iter().filter(|(_, b)| !b).collect();
                    assert!(
                        unblocked.is_empty(),
                        "libzstd workers with SIGINT unblocked: {unblocked:?}"
                    );
                }
                assert_eq!(sigint_blocked(&me), Some(false), "the mask is restored");
            }
            drop(ress);
            drop(io);
            // `err` holds progress lines only.
            assert!(!out.is_empty());
        })
        .unwrap()
        .join()
        .unwrap();
}
