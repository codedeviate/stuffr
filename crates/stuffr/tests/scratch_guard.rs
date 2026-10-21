//! The scratch guard in `common` removes its tree on drop, read-only
//! directories and panics included.

mod common;
use common::ScratchDir;

#[cfg(unix)]
fn make_read_only_tree(d: &ScratchDir) {
    use std::os::unix::fs::PermissionsExt;
    let ro = d.join("ro");
    std::fs::create_dir_all(&ro).unwrap();
    std::fs::write(ro.join("x"), b"x").unwrap();
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
}

#[cfg(unix)]
#[test]
fn scratch_guard_removes_read_only_trees_and_survives_panics() {
    let path = {
        let d = ScratchDir::create(&format!("stuffr-guard-{}-0", std::process::id()));
        make_read_only_tree(&d);
        d.to_path_buf()
    };
    assert!(!path.exists(), "dropped guard left {}", path.display());

    let path = std::env::temp_dir().join(format!("stuffr-guard-{}-1", std::process::id()));
    let p2 = path.clone();
    let r = std::panic::catch_unwind(move || {
        let d = ScratchDir::create(&format!("stuffr-guard-{}-1", std::process::id()));
        make_read_only_tree(&d);
        assert!(d.exists());
        panic!("test body panics after creating the tree");
    });
    assert!(r.is_err());
    assert!(!p2.exists(), "unwound guard left {}", p2.display());
}

#[cfg(unix)]
#[test]
fn scratch_guard_does_not_follow_symlinks_out_of_the_tree() {
    use std::os::unix::fs::PermissionsExt;
    let pid = std::process::id();
    let outside = ScratchDir::create(&format!("stuffr-guard-{pid}-outside"));
    std::fs::set_permissions(&*outside, std::fs::Permissions::from_mode(0o555)).unwrap();

    let d = ScratchDir::create(&format!("stuffr-guard-{pid}-link"));
    make_read_only_tree(&d);
    std::os::unix::fs::symlink(&*outside, d.join("link")).unwrap();
    let dp = d.to_path_buf();
    drop(d);

    assert!(!dp.exists());
    assert!(outside.exists(), "guard followed the link and removed it");
    let mode = std::fs::metadata(&*outside).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o555, "guard changed the outside directory's mode");
}
