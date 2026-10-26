//! The zip family's archives against this platform's reference (Tasks 6
//! and 7 of 0.19.0): every byte zip writes (local and central headers,
//! extra fields, data descriptors, Zip64 records, comments, the deflate
//! data at every level), both streams and the exit code, over
//! [`zip_bytes_matrix`] (new archives) and [`zip_update_matrix`] (archives
//! already at the path). Apple's `/usr/bin/zip` on macOS, Ubuntu's apt
//! `zip` under `make compat-ubuntu` and CI's Linux jobs.

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod unix {
    use super::compat_harness::*;
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::{Command, Stdio};

    #[test]
    fn new_archives_are_byte_identical() {
        let cases = zip_bytes_matrix(platform_zip_flavour());
        assert!(cases.len() >= 100, "{} cases", cases.len());
        run_group(
            &format!("zip bytes ({})", platform_zip_flavour()),
            &cases,
            Skipped::none(),
            &assert_same_zip,
        );
    }

    /// Task 7: updates. Ubuntu's failing `-T` runs are left out: its
    /// reference double-frees there (ruling Z3, pinned in
    /// `compat_zip_common`).
    #[test]
    fn updates_are_byte_identical() {
        let f = platform_zip_flavour();
        let cases = zip_update_matrix(f, f == "apple");
        assert!(cases.len() >= 150, "{} cases", cases.len());
        run_group(
            &format!("zip updates ({f})"),
            &cases,
            Skipped::none(),
            &assert_same_zip,
        );
    }

    /// `zip - names` with standard output a file that is not at its start:
    /// appended to (`>>`, `O_APPEND`) and positioned after other output
    /// (`{ printf pre; zip - ...; } > file`). zip rewrites a local header at
    /// the offset it counted from 0 and probes with the stream's own
    /// position: both references and stuffr write the same bytes (Task 6's
    /// carried bug: the probe used to seek to the counted offset).
    #[test]
    fn standard_output_past_its_start_is_written_as_zip_writes_it() {
        let Some(dir) = zip_dir() else {
            return;
        };
        let reference = Path::new(dir).join("zip");
        if !require_reference(&reference) {
            return;
        }
        let stuffr = std::path::PathBuf::from(env!("CARGO_BIN_EXE_stuffr"));
        let tree = zip_bytes_tree();
        let names = ["a.txt", "b.txt", "big.txt", "r.bin", "s.bin"];
        for append in [true, false] {
            let mut got = Vec::new();
            for exe in [&reference, &stuffr] {
                let s = ScratchDir::unique("zip-stdout-pos");
                std::fs::create_dir_all(&*s).unwrap();
                tree.materialise(&s);
                let out_path = s.join("out");
                std::fs::write(&out_path, b"EXISTING\n").unwrap();
                let out = if append {
                    std::fs::OpenOptions::new()
                        .append(true)
                        .open(&out_path)
                        .unwrap()
                } else {
                    let mut f = std::fs::OpenOptions::new()
                        .write(true)
                        .open(&out_path)
                        .unwrap();
                    std::io::Seek::seek(&mut f, std::io::SeekFrom::End(0)).unwrap();
                    f
                };
                let mut cmd = Command::new(exe);
                cmd.arg0("zip")
                    .arg("-")
                    .args(names)
                    .current_dir(&*s)
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .env("LANG", "C")
                    .env("TZ", "UTC")
                    .env("STUFFR_ZIP_FLAVOR", platform_zip_flavour())
                    .stdin(Stdio::null())
                    .stdout(out)
                    .stderr(Stdio::piped());
                let o = output_keep_stdout(&mut cmd);
                got.push((o.0, o.1, std::fs::read(&out_path).unwrap()));
            }
            assert_eq!(got[0].0, got[1].0, "exit, append {append}");
            assert_eq!(got[0].1, got[1].1, "stderr, append {append}");
            assert!(got[0].2 == got[1].2, "bytes differ, append {append}");
        }
    }

    /// `cmd` run with its standard output as set: (exit code, stderr).
    fn output_keep_stdout(cmd: &mut Command) -> (Option<i32>, Vec<u8>) {
        let child = spawn(cmd).unwrap();
        let o = child.wait_with_output().unwrap();
        (o.status.code(), o.stderr)
    }
}
