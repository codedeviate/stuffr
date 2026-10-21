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
