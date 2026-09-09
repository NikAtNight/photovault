use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, ErrorKind};
use std::path::Path;

/// Keep this handle alive for the process lifetime. Never unlink the lock file:
/// another process may already have opened that inode while waiting to lock it.
/// It lives outside `vault` so restore can replace that directory safely.
pub fn acquire(app_dir: &Path) -> io::Result<File> {
    std::fs::create_dir_all(app_dir)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(app_dir.join("vault.lock"))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(io::Error::new(
            ErrorKind::WouldBlock,
            "PhotoVault is already using this vault. Quit the other copy before opening this one.",
        )),
        Err(TryLockError::Error(error)) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!("photovault-lock-test-{}", crate::random_id())))
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }

    fn probe(dir: &Path, mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", "instance_lock::tests::child_probe", "--nocapture"])
            .env("PHOTOVAULT_LOCK_TEST_DIR", dir)
            .env("PHOTOVAULT_LOCK_TEST_MODE", mode)
            .stdout(Stdio::piped()).stderr(Stdio::piped());
        command
    }

    fn assert_probe(dir: &Path, mode: &str) {
        let output = probe(dir, mode).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "the subprocess must execute the probe test");
    }

    #[test]
    fn child_probe() {
        let Some(dir) = std::env::var_os("PHOTOVAULT_LOCK_TEST_DIR") else { return };
        let mode = std::env::var("PHOTOVAULT_LOCK_TEST_MODE").unwrap();
        let result = acquire(Path::new(&dir));
        if mode == "blocked" {
            assert_eq!(result.unwrap_err().kind(), ErrorKind::WouldBlock);
        } else {
            let _held = result.unwrap();
            if mode == "hold" {
                std::fs::write(Path::new(&dir).join("ready"), b"ready").unwrap();
                std::thread::sleep(Duration::from_secs(10));
            }
        }
    }

    #[test]
    fn second_process_is_blocked_then_can_open_after_release() {
        let fixture = Fixture::new();
        let held = acquire(&fixture.0).unwrap();
        assert_probe(&fixture.0, "blocked");
        drop(held);
        assert_probe(&fixture.0, "open");
        assert!(fixture.0.join("vault.lock").exists());
    }

    #[test]
    fn replacing_vault_directory_does_not_release_ownership() {
        let fixture = Fixture::new();
        let _held = acquire(&fixture.0).unwrap();
        std::fs::create_dir(fixture.0.join("vault")).unwrap();
        std::fs::rename(fixture.0.join("vault"), fixture.0.join("old-vault")).unwrap();
        std::fs::create_dir(fixture.0.join("vault")).unwrap();
        assert_probe(&fixture.0, "blocked");
    }

    #[test]
    fn process_termination_releases_ownership() {
        let fixture = Fixture::new();
        let mut child = probe(&fixture.0, "hold").spawn().unwrap();
        let ready = fixture.0.join("ready");
        for _ in 0..100 {
            if ready.exists() { break; }
            std::thread::sleep(Duration::from_millis(20));
        }
        let started = ready.exists();
        let blocked = started && acquire(&fixture.0).unwrap_err().kind() == ErrorKind::WouldBlock;
        let _ = child.kill();
        child.wait().unwrap();
        assert!(started, "lock probe did not start");
        assert!(blocked);
        assert!(acquire(&fixture.0).is_ok());
    }

    #[test]
    fn different_vault_locations_can_be_opened_independently() {
        let first = Fixture::new();
        let second = Fixture::new();
        let _first_lock = acquire(&first.0).unwrap();
        let _second_lock = acquire(&second.0).unwrap();
    }
}
