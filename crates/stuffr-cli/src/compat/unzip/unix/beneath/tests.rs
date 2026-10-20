//! The beneath walk on its own: nothing it does may reach outside the root,
//! whatever symlinks the destination already holds.

use super::*;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

/// A scratch directory removed on drop, holding `root/` and `outside/`.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p =
            std::env::temp_dir().join(format!("stuffr-beneath-{}-{tag}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(p.join("root")).unwrap();
        std::fs::create_dir_all(p.join("outside")).unwrap();
        Scratch(p)
    }
    fn root(&self) -> PathBuf {
        self.0.join("root")
    }
    fn outside(&self) -> PathBuf {
        self.0.join("outside")
    }
    fn open(&self) -> Root {
        Root::open(&self.root()).unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn empty(p: &Path) -> bool {
    std::fs::read_dir(p).unwrap().next().is_none()
}

#[test]
fn a_symlink_inside_the_root_is_followed() {
    let s = Scratch::new("inside");
    std::fs::create_dir(s.root().join("bar")).unwrap();
    symlink("bar", s.root().join("link")).unwrap();
    open_beneath(&s.open(), b"link/f.txt", true).unwrap();
    assert!(s.root().join("bar/f.txt").is_file());
    // and a chain of them, through `..` that stays beneath
    std::fs::create_dir(s.root().join("bar/deep")).unwrap();
    symlink("../bar/deep", s.root().join("bar/up")).unwrap();
    open_beneath(&s.open(), b"link/up/g.txt", true).unwrap();
    assert!(s.root().join("bar/deep/g.txt").is_file());
}

#[test]
fn a_preexisting_symlink_never_leads_out() {
    let s = Scratch::new("out");
    let out = s.outside();
    symlink("../outside", s.root().join("rel")).unwrap();
    symlink(&out, s.root().join("abs")).unwrap();
    // an absolute link escapes even when it points inside the root
    symlink(s.root(), s.root().join("selfabs")).unwrap();
    std::fs::create_dir(s.root().join("d")).unwrap();
    symlink("../../outside", s.root().join("d/up2")).unwrap();
    let r = s.open();
    for rel in [
        &b"rel/f.txt"[..],
        b"abs/f.txt",
        b"selfabs/f.txt",
        b"d/up2/f.txt",
        b"d/../../outside/f.txt",
        b"../outside/f.txt",
        b"rel/sub/f.txt",
    ] {
        let e = open_beneath(&r, rel, true).unwrap_err();
        assert!(
            is_escape(&e) || e.raw_os_error() == Some(libc::ENOENT),
            "{}: {e}",
            String::from_utf8_lossy(rel)
        );
        assert!(r.dir(rel).is_err());
        assert!(r.parent(rel).is_err());
    }
    // a walk that refused leaves nothing behind, and the root still works
    let (d, name) = r.parent(b"d/made").unwrap();
    d.mkdir(&name, 0o755).unwrap();
    assert!(s.root().join("d/made").is_dir());
    assert!(empty(&out), "something was written outside the root");
}

#[test]
fn the_last_component_is_never_followed() {
    let s = Scratch::new("last");
    let target = s.outside().join("victim");
    std::fs::write(&target, b"keep").unwrap();
    symlink(&target, s.root().join("f")).unwrap();
    let r = s.open();
    // creating over the symlink fails (O_NOFOLLOW): the target is untouched
    let e = open_beneath(&r, b"f", true).unwrap_err();
    assert_eq!(e.raw_os_error(), Some(libc::ELOOP), "{e}");
    assert!(open_beneath(&r, b"f", false).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    // lstat sees the link itself; removing it removes the link only
    let (d, name) = r.parent(b"f").unwrap();
    assert!(d.lstat(&name).unwrap().is_symlink());
    d.lchmod(&name, 0o700).ok();
    d.unlink(&name, false).unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    assert!(std::fs::symlink_metadata(s.root().join("f")).is_err());
    // the root-relative stat follows only beneath
    symlink("../outside/victim", s.root().join("g")).unwrap();
    assert!(r.lstat(b"g").unwrap().is_symlink());
    assert!(is_escape(&r.stat(b"g").unwrap_err()));
}

#[test]
fn dead_and_looping_links_are_errors() {
    let s = Scratch::new("dead");
    symlink("nowhere", s.root().join("dead")).unwrap();
    symlink("loop", s.root().join("loop")).unwrap();
    let r = s.open();
    let e = open_beneath(&r, b"dead/f", true).unwrap_err();
    assert_eq!(e.raw_os_error(), Some(libc::ENOENT));
    let e = open_beneath(&r, b"loop/f", true).unwrap_err();
    assert_eq!(e.raw_os_error(), Some(libc::ELOOP));
    assert!(empty(&s.outside()));
}

#[test]
fn names_made_of_dots_stay_at_the_root() {
    let s = Scratch::new("dots");
    std::fs::create_dir(s.root().join("a")).unwrap();
    let r = s.open();
    for rel in [&b"."[..], b"./", b"", b"a/..", b"a/."] {
        assert!(r.lstat(rel).unwrap().is_dir(), "{rel:?}");
    }
    for rel in [&b".."[..], b"../", b"../..", b"a/../.."] {
        assert!(is_escape(&r.lstat(rel).unwrap_err()), "{rel:?}");
    }
    // `..` as a last component is kept as a name, which nothing that
    // changes a name accepts: making it is the kernel's EEXIST, and the rest
    // refuse it (it may be above the root)
    let (d, name) = r.parent(b"..").unwrap();
    assert_eq!(name, b"..");
    assert_eq!(
        d.mkdir(&name, 0o755).unwrap_err().kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert!(is_escape(&d.unlink(&name, true).unwrap_err()));
    assert!(is_escape(&d.lchmod(&name, 0o700).unwrap_err()));
    assert!(is_escape(&d.create_file(&name).unwrap_err()));
    assert!(is_escape(&d.symlink(b"x", &name).unwrap_err()));
    assert!(is_escape(&d.rename_to(b"a", &d, &name).unwrap_err()));
    assert!(empty(&s.outside()));
}

/// `stat()` beneath the root follows a last symlink to a file as to a
/// directory (fix round 1), while it stays beneath; a link out is the
/// escape.
#[test]
fn stat_follows_a_last_link_to_a_file_beneath() {
    let s = Scratch::new("statfile");
    std::fs::create_dir(s.root().join("d")).unwrap();
    std::fs::write(s.root().join("d/f"), b"f").unwrap();
    symlink("d/f", s.root().join("tofile")).unwrap();
    symlink("../d/f", s.root().join("d/up")).unwrap();
    symlink("d", s.root().join("todir")).unwrap();
    symlink("todir/up", s.root().join("chain")).unwrap();
    symlink("../outside", s.root().join("out")).unwrap();
    let r = s.open();
    assert!(is_file(&r.stat(b"tofile").unwrap()));
    assert!(is_file(&r.stat(b"d/up").unwrap()));
    assert!(r.stat(b"todir").unwrap().is_dir());
    assert!(is_file(&r.stat(b"chain").unwrap()));
    assert!(is_escape(&r.stat(b"out").unwrap_err()));
    assert!(r.lstat(b"tofile").unwrap().is_symlink());
}

fn is_file(st: &Stat) -> bool {
    st.mode & 0o170000 == 0o100000
}
