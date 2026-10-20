//! Tests for the Info-ZIP decoder ports, one module per C file.

mod crypt {
    use crate::infozip::crypt::{Keys, RAND_HEAD_LEN, test_key};

    // The expected values below come from crypt.c itself: `update_keys`,
    // `decrypt_byte` and `init_keys` copied from
    // $UZ_KEEP/unzip60/crypt.c (modulo the `__G` plumbing) over crc32.c's
    // `make_crc_table`, into a scratch `keys.c`, and run once:
    //
    //   cc -O0 -Wall -o keys keys.c && ./keys test && ./keys "" \
    //     && ./keys "$(printf 'p\xe4\xff')"
    //
    // (Apple clang 21.0.0.) Per password it prints the keys after
    // `init_keys`, then `zdecode` over the ciphertext 00 01 .. 0f, then the
    // keys after those sixteen bytes.

    /// `keys.c test`: the keys after `init_keys("test")`.
    const KEYS_TEST: [u32; 3] = [0x7712_f9de, 0x485a_fd7b, 0x5ded_1e32];
    /// `keys.c test`: `zdecode` over 00..0f.
    const PLAIN_TEST: [u8; 16] = [
        0xdf, 0xab, 0xa8, 0xa1, 0x13, 0x1d, 0xe5, 0x56, 0x7e, 0x6f, 0xcb, 0x72, 0xee, 0x6d, 0x98,
        0xaa,
    ];
    /// `keys.c test`: the keys after those sixteen bytes.
    const KEYS_TEST_AFTER: [u32; 3] = [0x70aa_f6a7, 0x9024_e6d8, 0x9e8b_0502];

    /// `keys.c ""`: `zdecode` over 00..0f from the bare initial keys.
    const PLAIN_EMPTY: [u8; 16] = [
        0xab, 0xda, 0x45, 0x7d, 0xb6, 0x72, 0xba, 0x2d, 0xad, 0xf6, 0xe4, 0x08, 0x28, 0xc5, 0x68,
        0xe8,
    ];
    /// `keys.c ""`: the keys after those sixteen bytes.
    const KEYS_EMPTY_AFTER: [u32; 3] = [0x455e_4b23, 0xfa42_2603, 0xabfb_9ddd];

    /// `keys.c "p\xe4\xff"`: bytes above 0x7f, which crypt.c passes through
    /// a (signed, on these hosts) `char` before `CRC32`'s `& 0xff`.
    const KEYS_HIGH: [u32; 3] = [0xd456_86a8, 0x9d35_b95c, 0xe307_dce8];
    const PLAIN_HIGH: [u8; 16] = [
        0xe2, 0xf9, 0x13, 0x1f, 0x18, 0xb0, 0x69, 0x17, 0x57, 0xfc, 0x4c, 0xbc, 0xca, 0xf4, 0x28,
        0xa8,
    ];
    const KEYS_HIGH_AFTER: [u32; 3] = [0x781c_f789, 0x1608_060b, 0xdaad_f20d];

    fn ciphertext_00_to_0f() -> [u8; 16] {
        std::array::from_fn(|i| i as u8)
    }

    /// Encrypts `plain` under `keys`, crypt.h's `zencode`, built from the
    /// decryption API: on a clone, `zdecode(0)` yields the stream byte.
    fn encrypt(keys: &mut Keys, plain: &[u8]) -> Vec<u8> {
        plain
            .iter()
            .map(|&p| {
                let stream = keys.clone().decrypt_byte(0);
                let c = stream ^ p;
                assert_eq!(keys.decrypt_byte(c), p);
                c
            })
            .collect()
    }

    #[test]
    fn keys_after_init_match_crypt_c() {
        // PKWARE APPNOTE 6.1's initial keys, which an empty password leaves
        // untouched.
        assert_eq!(
            Keys::new(b"").raw(),
            [0x1234_5678, 0x2345_6789, 0x3456_7890]
        );
        assert_eq!(Keys::new(b"test").raw(), KEYS_TEST);
        assert_eq!(Keys::new(b"p\xe4\xff").raw(), KEYS_HIGH);
        // init_keys() walks a C string: a NUL ends the password.
        assert_eq!(Keys::new(b"test\0junk").raw(), KEYS_TEST);
    }

    #[test]
    fn decrypt_round_trips_with_the_reference() {
        for (password, plain, after) in [
            (&b"test"[..], PLAIN_TEST, KEYS_TEST_AFTER),
            (&b""[..], PLAIN_EMPTY, KEYS_EMPTY_AFTER),
            (&b"p\xe4\xff"[..], PLAIN_HIGH, KEYS_HIGH_AFTER),
        ] {
            // Whole buffer, as crypt.c's NEXTBYTE path sees it.
            let mut keys = Keys::new(password);
            let mut buf = ciphertext_00_to_0f();
            keys.decrypt(&mut buf);
            assert_eq!(buf, plain, "password {password:?}");
            assert_eq!(keys.raw(), after, "password {password:?}");

            // A byte at a time agrees with the buffer.
            let mut keys = Keys::new(password);
            let bytes: Vec<u8> = ciphertext_00_to_0f()
                .iter()
                .map(|&c| keys.decrypt_byte(c))
                .collect();
            assert_eq!(bytes, plain);

            // And encrypting the reference's plain text gives back 00..0f.
            let mut keys = Keys::new(password);
            assert_eq!(encrypt(&mut keys, &plain), ciphertext_00_to_0f());
            assert_eq!(keys.raw(), after);
        }

        // A longer round trip through the header and the data after it.
        let data = b"The quick brown fox jumps over the lazy dog.\n".repeat(50);
        let mut enc = Keys::new(b"secret");
        let mut header = [0u8; RAND_HEAD_LEN];
        header[..RAND_HEAD_LEN - 1].copy_from_slice(b"random head");
        header[RAND_HEAD_LEN - 1] = 0x5a;
        let mut stream = encrypt(&mut enc, &header);
        stream.extend(encrypt(&mut enc, &data));
        let head: [u8; RAND_HEAD_LEN] = stream[..RAND_HEAD_LEN].try_into().unwrap();
        let mut keys = test_key(b"secret", &head, 0x5a).expect("right password");
        let mut body = stream[RAND_HEAD_LEN..].to_vec();
        keys.decrypt(&mut body);
        assert_eq!(body, data);
    }

    /// Twelve arbitrary ciphertext bytes; `secret` decrypts the last to
    /// `0x8f` (crypt.c, below).
    const COLLISION_HEADER: [u8; RAND_HEAD_LEN] = [
        0x3a, 0xc5, 0x17, 0x80, 0x5e, 0xf2, 0x09, 0x6b, 0xd4, 0x21, 0x9c, 0x47,
    ];

    #[test]
    fn test_key_rejects_a_wrong_password_and_reports_the_lucky_collision() {
        // Expected values from crypt.c's init_keys/zdecode run as testkey()
        // runs them over COLLISION_HEADER, for "secret" and for every
        // "pw0".."pw9999", in a scratch `coll.c`:
        //
        //   cc -O0 -Wall -o coll coll.c && ./coll
        //
        // printing `check=8f`, the first five matching passwords and
        // `count=42` (1 in 256 is ~39 expected over 10,000).
        const CHECK: u8 = 0x8f;
        const FIRST_LUCKY: [&str; 5] = ["pw0", "pw140", "pw268", "pw499", "pw994"];
        const LUCKY_COUNT: usize = 42;

        assert!(test_key(b"secret", &COLLISION_HEADER, CHECK).is_some());
        assert!(test_key(b"secret", &COLLISION_HEADER, CHECK ^ 1).is_none());

        let lucky: Vec<String> = (0..10_000)
            .map(|i| format!("pw{i}"))
            .filter(|pw| test_key(pw.as_bytes(), &COLLISION_HEADER, CHECK).is_some())
            .collect();
        assert_eq!(lucky.len(), LUCKY_COUNT, "{lucky:?}");
        assert_eq!(lucky[..FIRST_LUCKY.len()], FIRST_LUCKY);
        // A wrong password is rejected outright.
        assert!(test_key(b"pw1", &COLLISION_HEADER, CHECK).is_none());

        // The lucky one passes the check byte but decrypts to other keys
        // than the right one: only the entry's CRC can tell them apart.
        let right = test_key(b"secret", &COLLISION_HEADER, CHECK).unwrap();
        let wrong = test_key(b"pw0", &COLLISION_HEADER, CHECK).unwrap();
        assert_ne!(right.raw(), wrong.raw());
        let mut a = *b"payload bytes";
        let mut b = a;
        right.clone().decrypt(&mut a);
        wrong.clone().decrypt(&mut b);
        assert_ne!(a, b);
    }

    /// `/usr/bin/zip -P secret` over three stored files: every entry's
    /// header passes `test_key` with the right check byte and its data
    /// decrypts to the file. macOS only, where `/usr/bin/zip` is
    /// Info-ZIP's Zip 3.0.
    #[cfg(target_os = "macos")]
    #[test]
    fn test_key_accepts_zip_made_archives() {
        let dir = macos::TempDir::new("zip-made");
        let files: [(&str, Vec<u8>); 3] = [
            ("a.txt", b"alpha\n".to_vec()),
            ("b.txt", b"bravo bravo bravo\n".repeat(20)),
            (
                "c.bin",
                (0..3000u32).map(|i| (i * 7 + i / 13) as u8).collect(),
            ),
        ];
        for (name, data) in &files {
            std::fs::write(dir.0.join(name), data).unwrap();
        }
        let out = std::process::Command::new("/usr/bin/zip")
            .args([
                "-q", "-0", "-P", "secret", "out.zip", "a.txt", "b.txt", "c.bin",
            ])
            .current_dir(&dir.0)
            .output()
            .expect("run /usr/bin/zip");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );

        let entries = macos::local_entries(&std::fs::read(dir.0.join("out.zip")).unwrap());
        assert_eq!(entries.len(), files.len());
        for (entry, (name, data)) in entries.iter().zip(&files) {
            assert_eq!(entry.name, name.as_bytes());
            assert_eq!(entry.flags & 1, 1, "{name}: not encrypted");
            assert_eq!(entry.method, 0, "{name}: not stored");
            let check = if entry.flags & 8 != 0 {
                (entry.dos_time >> 8) as u8
            } else {
                (entry.crc >> 24) as u8
            };
            let head: [u8; RAND_HEAD_LEN] = entry.data[..RAND_HEAD_LEN].try_into().unwrap();
            let mut keys = test_key(b"secret", &head, check)
                .unwrap_or_else(|| panic!("{name}: the right password was refused"));
            let mut body = entry.data[RAND_HEAD_LEN..].to_vec();
            keys.decrypt(&mut body);
            assert_eq!(&body, data, "{name}");
        }
    }

    #[cfg(target_os = "macos")]
    mod macos {
        pub(super) struct TempDir(pub(super) std::path::PathBuf);

        impl TempDir {
            pub(super) fn new(tag: &str) -> TempDir {
                let dir = std::env::temp_dir().join(format!(
                    "stuffr-infozip-crypt-{tag}-{}-{:?}",
                    std::process::id(),
                    std::thread::current().id()
                ));
                let _ = std::fs::remove_dir_all(&dir);
                std::fs::create_dir_all(&dir).unwrap();
                TempDir(dir)
            }
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        pub(super) struct LocalEntry {
            pub(super) flags: u16,
            pub(super) method: u16,
            pub(super) dos_time: u16,
            pub(super) crc: u32,
            pub(super) name: Vec<u8>,
            pub(super) data: Vec<u8>,
        }

        fn u16_at(b: &[u8], at: usize) -> u16 {
            u16::from_le_bytes([b[at], b[at + 1]])
        }

        fn u32_at(b: &[u8], at: usize) -> u32 {
            u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
        }

        /// Walks the local headers from the start: each `PK\3\4` record,
        /// its data, and its data descriptor when bit 3 is set. `csize` is
        /// read from the local header, which Zip 3.0 rewrites with the real
        /// figure when its output is seekable (on a pipe it leaves the
        /// stored size there, 6 for `a.txt`, and the assertion below fires).
        pub(super) fn local_entries(zip: &[u8]) -> Vec<LocalEntry> {
            let mut at = 0;
            let mut entries = Vec::new();
            while zip.len() >= at + 30 && zip[at..at + 4] == *b"PK\x03\x04" {
                let flags = u16_at(zip, at + 6);
                let method = u16_at(zip, at + 8);
                let dos_time = u16_at(zip, at + 10);
                let csize = u32_at(zip, at + 18) as usize;
                let name_len = u16_at(zip, at + 26) as usize;
                let extra_len = u16_at(zip, at + 28) as usize;
                let name_at = at + 30;
                let data_at = name_at + name_len + extra_len;
                assert!(
                    csize >= super::RAND_HEAD_LEN,
                    "entry at {at}: csize {csize}"
                );
                let mut crc = u32_at(zip, at + 14);
                at = data_at + csize;
                if flags & 8 != 0 {
                    if zip[at..at + 4] == *b"PK\x07\x08" {
                        at += 4;
                    }
                    crc = u32_at(zip, at);
                    at += 12;
                }
                entries.push(LocalEntry {
                    flags,
                    method,
                    dos_time,
                    crc,
                    name: zip[name_at..name_at + name_len].to_vec(),
                    data: zip[data_at..data_at + csize].to_vec(),
                });
            }
            entries
        }
    }
}
