//! Walking a folder into a `Listing` for `stuffr ls`.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use stuffr::Registry;
use stuffr::probe::Chain;

use super::identify::{Identified, identify};

pub struct WalkOptions {
    pub recursive: bool,
    pub all: bool,
    pub by_name: bool,
}

pub enum RowKind {
    File { chain: Chain, size: u64 },
    Folder,
}

pub struct Row {
    pub name: OsString,
    pub kind: RowKind,
    pub modified: SystemTime,
}

pub struct Block {
    /// Empty for the top folder.
    pub rel_path: PathBuf,
    pub rows: Vec<Row>,
}

pub struct Listing {
    pub blocks: Vec<Block>,
    pub shown: u64,
    pub not_openable: u64,
    /// Full stderr lines, in encounter order.
    pub warnings: Vec<String>,
}

#[derive(Default)]
struct Acc {
    shown: u64,
    not_openable: u64,
    warnings: Vec<String>,
}

/// What one directory entry turned out to be.
enum Entry {
    Row(Row),
    /// A real (non-symlink) folder, to descend into under `recursive`.
    Dir(Row, PathBuf),
}

fn mtime(md: &fs::Metadata) -> SystemTime {
    md.modified().unwrap_or(UNIX_EPOCH)
}

fn warn(acc: &mut Acc, root: &Path, path: &Path, e: &std::io::Error) {
    let rel = path.strip_prefix(root).unwrap_or(path);
    let shown = if rel.as_os_str().is_empty() {
        root
    } else {
        rel
    };
    acc.warnings.push(format!(
        "stuffr: cannot read {}: {e}",
        stuffr::fmt_name(&shown.to_string_lossy())
    ));
}

/// A symlink target stat error meaning "nothing there": NotFound or ELOOP.
fn link_is_dangling(e: &std::io::Error) -> bool {
    if e.kind() == std::io::ErrorKind::NotFound {
        return true;
    }
    #[cfg(unix)]
    if e.raw_os_error() == Some(libc::ELOOP) {
        return true;
    }
    false
}

/// Classifies one entry. `listed_was_file` is what the directory listing said
/// (a vanished file still counts as not openable).
fn visit_entry(
    reg: &Registry,
    root: &Path,
    path: &Path,
    name: OsString,
    listed_was_file: bool,
    _opts: &WalkOptions,
    acc: &mut Acc,
) -> Option<Entry> {
    let md = match fs::metadata(path) {
        Ok(md) => md,
        Err(e) => {
            let is_symlink = fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink());
            if is_symlink {
                // Dangling (target NotFound) or a link loop (ELOOP) is
                // skipped silently; any other error warns. Not counted:
                // the target may not have been a file.
                if !link_is_dangling(&e) {
                    warn(acc, root, path, &e);
                }
            } else {
                warn(acc, root, path, &e);
                if listed_was_file {
                    acc.not_openable += 1;
                }
            }
            return None;
        }
    };
    let is_link = fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink());
    let modified = mtime(&md);
    if md.is_dir() {
        let row = Row {
            name,
            kind: RowKind::Folder,
            modified,
        };
        return Some(if is_link {
            Entry::Row(row)
        } else {
            Entry::Dir(row, path.to_path_buf())
        });
    }
    if !md.is_file() {
        return None;
    }
    match identify(reg, path) {
        Ok(Identified::Openable(chain)) => {
            acc.shown += 1;
            Some(Entry::Row(Row {
                name,
                kind: RowKind::File {
                    chain,
                    size: md.len(),
                },
                modified,
            }))
        }
        Ok(Identified::NotOpenable) => {
            acc.not_openable += 1;
            None
        }
        Err(e) => {
            warn(acc, root, path, &e);
            acc.not_openable += 1;
            None
        }
    }
}

fn sort_rows(rows: &mut [Row], by_name: bool) {
    if by_name {
        rows.sort_by(|a, b| a.name.cmp(&b.name));
    } else {
        rows.sort_by(|a, b| {
            b.modified
                .cmp(&a.modified)
                .then_with(|| a.name.cmp(&b.name))
        });
    }
}

/// What the directory listing says an entry is, without following a link
/// for anything but the file/not-file question.
fn listed_as_file(entry: &fs::DirEntry) -> bool {
    match entry.file_type() {
        Ok(t) if t.is_file() => true,
        Ok(t) if t.is_symlink() => fs::metadata(entry.path()).is_ok_and(|m| m.is_file()),
        _ => false,
    }
}

pub fn walk(reg: &Registry, root: &Path, opts: &WalkOptions) -> Listing {
    let mut acc = Acc::default();
    let mut blocks = Vec::new();
    // Depth-first, pre-order; siblings pushed reversed so they pop in order.
    let mut stack: Vec<(PathBuf, PathBuf)> = vec![(PathBuf::new(), root.to_path_buf())];
    while let Some((rel, dir)) = stack.pop() {
        let top = rel.as_os_str().is_empty();
        let mut rows: Vec<Row> = Vec::new();
        let mut subdirs: Vec<(Row, PathBuf)> = Vec::new();
        match fs::read_dir(&dir) {
            Err(e) => warn(&mut acc, root, &dir, &e),
            Ok(rd) => {
                for ent in rd {
                    let ent = match ent {
                        Ok(ent) => ent,
                        Err(e) => {
                            warn(&mut acc, root, &dir, &e);
                            continue;
                        }
                    };
                    let name = ent.file_name();
                    if !opts.all && name.to_string_lossy().starts_with('.') {
                        continue;
                    }
                    let was_file = listed_as_file(&ent);
                    let path = ent.path();
                    match visit_entry(reg, root, &path, name, was_file, opts, &mut acc) {
                        None => {}
                        // A symlinked folder is a row only without `-r`.
                        Some(Entry::Row(row))
                            if !matches!(row.kind, RowKind::Folder) || !opts.recursive =>
                        {
                            rows.push(row);
                        }
                        Some(Entry::Row(_)) => {}
                        Some(Entry::Dir(row, p)) => {
                            if opts.recursive {
                                subdirs.push((row, p));
                            } else {
                                rows.push(row);
                            }
                        }
                    }
                }
            }
        }
        sort_rows(&mut rows, opts.by_name);
        if top || !rows.is_empty() {
            blocks.push(Block {
                rel_path: rel.clone(),
                rows,
            });
        }
        let mut order: Vec<Row> = Vec::new();
        let mut paths = std::collections::HashMap::new();
        for (row, p) in subdirs {
            paths.insert(row.name.clone(), p);
            order.push(row);
        }
        sort_rows(&mut order, opts.by_name);
        for row in order.into_iter().rev() {
            let p = paths.remove(&row.name).expect("subdir path");
            stack.push((rel.join(&row.name), p));
        }
    }
    Listing {
        blocks,
        shown: acc.shown,
        not_openable: acc.not_openable,
        warnings: acc.warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    struct Dir {
        root: PathBuf,
        restore: std::cell::RefCell<Vec<PathBuf>>,
    }
    impl Dir {
        fn new() -> Dir {
            use std::sync::atomic::{AtomicU64, Ordering};
            static N: AtomicU64 = AtomicU64::new(0);
            let mut p = std::env::temp_dir();
            p.push(format!(
                "stuffr-ls-{}-w{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Dir {
                root: p,
                restore: Default::default(),
            }
        }
        /// Writes `rel` with `bytes`; `age` is seconds before a fixed base.
        fn file(&self, rel: &str, bytes: &[u8], age: u64) -> PathBuf {
            let p = self.root.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, bytes).unwrap();
            set_age(&p, age);
            p
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            #[cfg(unix)]
            for p in self.restore.borrow().iter() {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o700));
            }
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn base() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }
    fn set_age(p: &Path, age: u64) {
        let f = fs::OpenOptions::new().write(true).open(p).unwrap();
        f.set_modified(base() - Duration::from_secs(age)).unwrap();
    }

    const GZ: &[u8] = &[0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 3];
    const ZIP: &[u8] = b"PK\x03\x04\x14\0\0\0\0\0";
    const XZ: &[u8] = &[0xfd, b'7', b'z', b'X', b'Z', 0, 0, 0, 0, 0];

    fn opts(recursive: bool, all: bool, by_name: bool) -> WalkOptions {
        WalkOptions {
            recursive,
            all,
            by_name,
        }
    }
    fn run(d: &Dir, o: WalkOptions) -> Listing {
        walk(stuffr::registry(), &d.root, &o)
    }
    fn names(b: &Block) -> Vec<String> {
        b.rows
            .iter()
            .map(|r| r.name.to_string_lossy().into_owned())
            .collect()
    }
    fn rels(l: &Listing) -> Vec<String> {
        l.blocks
            .iter()
            .map(|b| b.rel_path.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn lists_only_openable_files_newest_first() {
        let d = Dir::new();
        d.file("a.gz", GZ, 300);
        d.file("b.tar.gz", GZ, 100);
        d.file("c.zip", ZIP, 200);
        d.file("notes.txt", b"hello", 50);
        let l = run(&d, opts(false, false, false));
        assert_eq!(l.blocks.len(), 1);
        assert_eq!(names(&l.blocks[0]), ["b.tar.gz", "c.zip", "a.gz"]);
        assert_eq!((l.shown, l.not_openable), (3, 1));
        assert!(l.warnings.is_empty());
    }

    #[test]
    fn folders_listed_without_r_with_folder_kind() {
        let d = Dir::new();
        fs::create_dir(d.root.join("screenshots")).unwrap();
        d.file("a.gz", GZ, 10);
        let l = run(&d, opts(false, false, true));
        let rows = &l.blocks[0].rows;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].name, "screenshots");
        assert!(matches!(rows[1].kind, RowKind::Folder));
        assert_eq!(l.shown, 1);
        assert_eq!(l.not_openable, 0);
    }

    #[test]
    fn r_lists_only_folders_with_openable_files() {
        let d = Dir::new();
        d.file("old/a.gz", GZ, 10);
        d.file("screenshots/x.txt", b"x", 20);
        d.file("deep/er/b.xz", XZ, 30);
        d.file("top.gz", GZ, 5);
        // folder mtimes decide sibling order: deep newest, old oldest
        let set = |rel: &str, age: u64| {
            let f = fs::File::open(d.root.join(rel)).unwrap();
            f.set_modified(base() - Duration::from_secs(age)).unwrap();
        };
        set("deep", 1);
        set("screenshots", 2);
        set("old", 3);
        let l = run(&d, opts(true, false, false));
        assert_eq!(rels(&l), ["", "deep/er", "old"]);
        assert_eq!(names(&l.blocks[0]), ["top.gz"]);
        assert!(l.blocks.iter().all(|b| {
            b.rows
                .iter()
                .all(|r| matches!(r.kind, RowKind::File { .. }))
        }));
        assert_eq!((l.shown, l.not_openable), (3, 1));
        let l = run(&d, opts(true, false, true));
        assert_eq!(rels(&l), ["", "deep/er", "old"]);
        // name order differs from mtime order: make mtime order reversed
        set("deep", 3);
        set("old", 1);
        let l = run(&d, opts(true, false, false));
        assert_eq!(rels(&l), ["", "old", "deep/er"]);
        let l = run(&d, opts(true, false, true));
        assert_eq!(rels(&l), ["", "deep/er", "old"]);
    }

    #[test]
    fn empty_top_block_exists() {
        let d = Dir::new();
        let l = run(&d, opts(true, false, false));
        assert_eq!(l.blocks.len(), 1);
        assert!(l.blocks[0].rel_path.as_os_str().is_empty());
        assert!(l.blocks[0].rows.is_empty());
    }

    #[test]
    fn hidden_skipped_unless_all() {
        let d = Dir::new();
        d.file("vis.gz", GZ, 1);
        d.file(".secret.gz", GZ, 2);
        d.file(".hidden/a.gz", GZ, 3);
        d.file(".notes", b"x", 4);
        let l = run(&d, opts(true, false, true));
        assert_eq!(rels(&l), [""]);
        assert_eq!(names(&l.blocks[0]), ["vis.gz"]);
        assert_eq!((l.shown, l.not_openable), (1, 0));
        let l = run(&d, opts(true, true, true));
        assert_eq!(rels(&l), ["", ".hidden"]);
        assert_eq!(names(&l.blocks[0]), [".secret.gz", "vis.gz"]);
        assert_eq!((l.shown, l.not_openable), (3, 1));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_to_file_uses_target_metadata() {
        let d = Dir::new();
        let t = d.file("real.gz", GZ, 500);
        std::os::unix::fs::symlink(&t, d.root.join("link.gz")).unwrap();
        let l = run(&d, opts(false, false, true));
        let tmd = fs::metadata(&t).unwrap();
        let r = l.blocks[0]
            .rows
            .iter()
            .find(|r| r.name == "link.gz")
            .unwrap();
        assert_eq!(r.modified, tmd.modified().unwrap());
        assert!(matches!(&r.kind, RowKind::File { size, .. } if *size == tmd.len()));
        assert_eq!(l.shown, 2);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_folders_are_never_descended() {
        let d = Dir::new();
        d.file("sub/a.gz", GZ, 1);
        std::os::unix::fs::symlink(".", d.root.join("loop")).unwrap();
        std::os::unix::fs::symlink("..", d.root.join("sub/up")).unwrap();
        let l = run(&d, opts(true, false, true));
        assert_eq!(rels(&l), ["", "sub"]);
        assert_eq!(l.shown, 1);
        let l = run(&d, opts(false, false, true));
        let r = l.blocks[0].rows.iter().find(|r| r.name == "loop").unwrap();
        assert!(matches!(r.kind, RowKind::Folder));
    }

    #[cfg(unix)]
    #[test]
    fn dangling_symlink_and_fifo_are_skipped_silently() {
        let d = Dir::new();
        std::os::unix::fs::symlink("nowhere", d.root.join("dangling")).unwrap();
        std::os::unix::fs::symlink("selfloop", d.root.join("selfloop")).unwrap();
        let fifo = std::ffi::CString::new(d.root.join("pipe").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let l = run(&d, opts(false, false, true));
        assert!(l.blocks[0].rows.is_empty());
        assert_eq!((l.shown, l.not_openable), (0, 0));
        assert!(l.warnings.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_into_unreadable_folder_warns_uncounted() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let d = Dir::new();
        d.file("locked/a.gz", GZ, 1);
        let locked = d.root.join("locked");
        d.restore.borrow_mut().push(locked.clone());
        std::os::unix::fs::symlink(locked.join("a.gz"), d.root.join("via.gz")).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let l = run(&d, opts(false, false, true));
        assert_eq!(l.warnings.len(), 1, "{:?}", l.warnings);
        assert!(l.warnings[0].starts_with("stuffr: cannot read via.gz: "));
        assert_eq!((l.shown, l.not_openable), (0, 0));
        assert_eq!(names(&l.blocks[0]), ["locked"]);
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_file_and_folder_warn() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let d = Dir::new();
        let x = d.file("x.gz", GZ, 1);
        d.file("locked/a.gz", GZ, 2);
        let locked = d.root.join("locked");
        d.restore.borrow_mut().push(x.clone());
        d.restore.borrow_mut().push(locked.clone());
        fs::set_permissions(&x, fs::Permissions::from_mode(0o000)).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let l = run(&d, opts(true, false, true));
        assert_eq!((l.shown, l.not_openable), (0, 1));
        assert_eq!(l.warnings.len(), 2);
        assert!(
            l.warnings
                .iter()
                .any(|w| w.starts_with("stuffr: cannot read x.gz: "))
        );
        assert!(
            l.warnings
                .iter()
                .any(|w| w.starts_with("stuffr: cannot read locked: "))
        );
        assert_eq!(rels(&l), [""]);
    }

    #[test]
    fn vanished_entry_is_a_warning() {
        let d = Dir::new();
        let p = d.file("gone.gz", GZ, 1);
        fs::remove_file(&p).unwrap();
        let mut acc = Acc::default();
        let o = opts(false, false, false);
        let e = visit_entry(
            stuffr::registry(),
            &d.root,
            &p,
            "gone.gz".into(),
            true,
            &o,
            &mut acc,
        );
        assert!(e.is_none());
        assert_eq!(acc.warnings.len(), 1);
        assert!(acc.warnings[0].starts_with("stuffr: cannot read gone.gz: "));
        assert_eq!(acc.not_openable, 1);
        // a vanished non-file is a warning only
        let mut acc = Acc::default();
        visit_entry(
            stuffr::registry(),
            &d.root,
            &p,
            "gone.gz".into(),
            false,
            &o,
            &mut acc,
        );
        assert_eq!((acc.warnings.len(), acc.not_openable), (1, 0));
    }

    #[test]
    fn warning_escapes_the_path() {
        let d = Dir::new();
        let p = d.root.join("bad\nname.gz");
        let mut acc = Acc::default();
        visit_entry(
            stuffr::registry(),
            &d.root,
            &p,
            "bad\nname.gz".into(),
            true,
            &opts(false, false, false),
            &mut acc,
        );
        assert!(acc.warnings[0].starts_with("stuffr: cannot read bad\\nname.gz: "));
    }

    #[test]
    fn reads_at_most_probe_len_per_file() {
        use std::io::Read;
        struct Counting<R>(R, std::rc::Rc<std::cell::Cell<usize>>);
        impl<R: Read> Read for Counting<R> {
            fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                let n = self.0.read(b)?;
                self.1.set(self.1.get() + n);
                Ok(n)
            }
        }
        let d = Dir::new();
        let mut big = GZ.to_vec();
        big.resize(1 << 20, 0);
        let p = d.file("big.gz", &big, 1);
        let count = std::rc::Rc::new(std::cell::Cell::new(0));
        let r = Counting(fs::File::open(&p).unwrap(), count.clone());
        let v = super::super::identify::identify_with_reader(stuffr::registry(), &p, r).unwrap();
        assert!(matches!(v, Identified::Openable(_)));
        assert!(
            count.get() <= stuffr::probe::PROBE_LEN,
            "read {}",
            count.get()
        );
        assert!(count.get() > 0);
    }
}
