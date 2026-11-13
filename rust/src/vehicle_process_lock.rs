//! OS-released file lock shared by cooperating BimmerScope processes.
use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
};

pub(crate) struct ProcessLock {
    _file: File,
}
impl ProcessLock {
    pub(crate) fn acquire(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("Vehicle lock directory: {e}"))?;
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(0);
        }
        let file=options.open(path).map_err(|e|format!("Vehicle access is owned by another BimmerScope process, or its OS lock is unavailable: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            unsafe extern "C" {
                fn flock(fd: i32, operation: i32) -> i32;
            }
            // LOCK_EX | LOCK_NB; the OS releases this when the descriptor closes.
            if unsafe { flock(file.as_raw_fd(), 2 | 4) } != 0 {
                return Err(format!("Vehicle access is owned by another BimmerScope process, or its OS lock is unavailable: {}",std::io::Error::last_os_error()));
            }
        }
        #[cfg(not(any(windows, unix)))]
        {
            return Err("Cross-process vehicle lock unsupported on this platform".into());
        }
        Ok(Self { _file: file })
    }
}
pub(crate) fn shared_path() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        let root = std::env::var_os("LOCALAPPDATA")
            .ok_or("LOCALAPPDATA is unavailable; cannot establish shared vehicle ownership")?;
        Ok(PathBuf::from(root).join("BimmerScope/vehicle-io.lock"))
    }
    #[cfg(not(windows))]
    {
        Ok(std::env::temp_dir().join("bimmerscope-vehicle-io/vehicle-io.lock"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    fn path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "bimmerscope-lock-test-{}-{}.lock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }
    #[test]
    #[ignore = "subprocess helper"]
    fn child_lock_probe() {
        let path = std::env::var_os("BIMMERSCOPE_TEST_LOCK_PATH").unwrap();
        if std::env::var_os("BIMMERSCOPE_TEST_LOCK_HOLD").is_some() {
            let _lock = ProcessLock::acquire(Path::new(&path)).unwrap();
            use std::io::Write;
            println!("LOCKED");
            std::io::stdout().flush().unwrap();
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
        assert!(ProcessLock::acquire(Path::new(&path)).is_err());
    }
    fn child(path: &Path) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "vehicle_process_lock::tests::child_lock_probe",
                "--ignored",
                "--nocapture",
            ])
            .env("BIMMERSCOPE_TEST_LOCK_PATH", path);
        command
    }
    #[test]
    fn separate_process_cannot_acquire_owned_lock_and_normal_drop_releases_it() {
        let path = path();
        let guard = ProcessLock::acquire(&path).unwrap();
        assert!(child(&path).output().unwrap().status.success());
        drop(guard);
        drop(ProcessLock::acquire(&path).unwrap());
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn os_releases_lock_after_owner_process_is_terminated() {
        use std::io::BufRead;
        let path = path();
        let mut process = child(&path)
            .env("BIMMERSCOPE_TEST_LOCK_HOLD", "1")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut reader = std::io::BufReader::new(process.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            if line.trim() == "LOCKED" {
                break;
            }
        }
        let busy = ProcessLock::acquire(&path).is_err();
        process.kill().unwrap();
        process.wait().unwrap();
        assert!(busy);
        drop(ProcessLock::acquire(&path).unwrap());
        std::fs::remove_file(path).unwrap();
    }
}
