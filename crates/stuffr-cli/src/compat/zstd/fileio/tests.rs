//! fileio.rs unit tests: the read pool's job rule, the sparse writer's
//! 32 KiB segment rule, the names, and the parameter bounds the pure tier
//! answers with.

use std::ffi::OsString;

use super::*;
use crate::compat::zstd::cli;
use crate::compat::zstd::util::Cores;

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
    let (closed, _) = io.close_sink();
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
