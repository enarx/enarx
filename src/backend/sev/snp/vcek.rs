// SPDX-License-Identifier: Apache-2.0

use crate::backend::sev::Firmware;

use std::fs::{self, remove_file};
use std::io::{self, ErrorKind, Read, Seek};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use anyhow::{anyhow, Context};

pub enum UpdateMode {
    ReadOnly,
    ReadWrite,
}

/// Return a reader, which provides the VCEK
pub fn get_vcek_reader() -> anyhow::Result<Box<dyn Read>> {
    get_vcek_reader_with_paths(paths(), UpdateMode::ReadWrite).map(|(_, r)| r)
}

/// Returns the list of search paths in order that they
/// will be searched for the VCEK.
pub fn paths() -> Vec<PathBuf> {
    vec![home(), sys()].into_iter().flatten().collect()
}

/// Returns the "user-level" search path for the SEV
/// certificate chain (`$XDG_CACHE_HOME` or `$HOME/.cache` with the `amd-sev` subdir).
fn home() -> Option<PathBuf> {
    dirs::cache_dir().map(append_rest)
}

/// Returns the "system-level" search path for the SEV
/// certificate chain (`/var/cache/amd-sev`).
fn sys() -> Option<PathBuf> {
    let sys = PathBuf::from("/var/cache");
    if sys.exists() && sys.is_dir() {
        Some(append_rest(sys))
    } else {
        None
    }
}

/// append the `amd-sev` subdir
fn append_rest(mut path: PathBuf) -> PathBuf {
    path.push("amd-sev");
    path
}

/// Returns a reader, which provides the VCEK searching the provided paths
pub fn get_vcek_reader_with_paths(
    paths: Vec<PathBuf>,
    mode: UpdateMode,
) -> anyhow::Result<(PathBuf, Box<dyn Read>)> {
    let (url, path) = get_vcek_url_path()?;

    get_or_write(
        paths,
        path,
        || {
            let call = ureq::get(&url)
                .call()
                .context(format!("Error getting vcek from URL {}", &url))?;
            let reader = call.into_reader();
            Ok(Box::new(reader))
        },
        mode,
    )
}

fn get_vcek_url_path() -> anyhow::Result<(String, String)> {
    // Get the platform information.
    let mut sev = Firmware::open().context("failed to open /dev/sev")?;
    let id = sev.identifier().context("failed to query identifier")?;
    let status = sev
        .platform_status()
        .context("failed to query platform status")?;

    // Ensure the versions match.
    if status.tcb.platform_version != status.tcb.reported_version {
        // It is not clear from the documentation what the difference between the two is,
        // therefore only proceed if they are identical to ensure correctness.
        // TODO: Figure out which one should be used and drop this check.
        return Err(anyhow!("reported TCB version mismatch"));
    }

    let url = id.vcek_url(&status.tcb.reported_version);

    let path = id.vcek_cache_name(&status.tcb.reported_version);
    Ok((url, path))
}

// get a cached file, or write the file with the reader provided by the contents function
fn get_or_write(
    paths: Vec<PathBuf>,
    name: String,
    contents: impl Fn() -> anyhow::Result<Box<dyn Read>>,
    mode: UpdateMode,
) -> anyhow::Result<(PathBuf, Box<dyn Read>)> {
    // Fast path, try to read from any location first
    for base in &paths {
        let mut path_locked = base.clone();
        path_locked.push(name.clone() + ".lck");

        let mut path = base.clone();
        path.push(&name);

        if let Ok(file) = fs::File::open(&path) {
            if !path_locked.exists() {
                // no write in progress
                return Ok((path, Box::new(file)));
            }
        }
    }

    if matches!(mode, UpdateMode::ReadWrite) {
        // Nothing found, try to create a cache file, which may collide with other instances doing so also
        for base in paths {
            // ignore error, error is handled in lock file creation
            let _ = fs::create_dir_all(&base);

            let mut path_locked = base.clone();
            path_locked.push(name.clone() + ".lck");

            let mut path = base.clone();
            path.push(&name);

            let mut retries = 100;

            while retries > 0 {
                match fs::OpenOptions::new()
                    .mode(0o644)
                    .write(true)
                    .create_new(true)
                    .open(&path_locked)
                {
                    Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                        // sleep, write may be in progress
                        std::thread::sleep(std::time::Duration::from_millis(200));
                        retries -= 1;
                        continue;
                    }
                    Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                        if let Ok(file) = fs::File::open(&path) {
                            return Ok((path, Box::new(file)));
                        }
                        break;
                    }
                    Ok(lock) => {
                        match fs::File::open(&path) {
                            Ok(file) => {
                                drop(lock);
                                let _ = remove_file(&path_locked);
                                return Ok((path, Box::new(file)));
                            }
                            Err(e) if e.kind() == ErrorKind::NotFound => {
                                // write the file ourselves
                                if let Ok(mut file) = fs::OpenOptions::new()
                                    .mode(0o644)
                                    .write(true)
                                    .read(true)
                                    .create_new(true)
                                    .open(&path)
                                {
                                    let res = contents().and_then(|mut contents| {
                                        io::copy(&mut contents, &mut file)
                                            .context(format!("Error writing {:?}", &path))
                                    });
                                    if let Err(e) = res {
                                        drop(file);
                                        let _ = remove_file(&path_locked);
                                        return Err(e);
                                    }
                                    let _ = remove_file(&path_locked);
                                    file.rewind()
                                        .context(format!("Error rewinding {:?}", &path))?;
                                    return Ok((path, Box::new(file)));
                                }
                                let _ = remove_file(&path_locked);
                                break;
                            }
                            Err(_) => {
                                let _ = remove_file(&path_locked);
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            if retries == 0 {
                return Err(io::Error::from(ErrorKind::NotFound))
                    .context(format!("Potential stale lock file {:?}", &path_locked));
            }
        }
    }

    Err(io::Error::from(ErrorKind::NotFound).into())
}

#[cfg(test)]
mod tests {
    use super::{get_or_write, UpdateMode};

    use std::io::{self, ErrorKind, Read};
    use std::path::PathBuf;
    use std::thread;
    use tempfile::tempdir;

    #[test]
    fn test_get_or_write() -> anyhow::Result<()> {
        let mut join_handles = Vec::new();
        let tmp_dir = tempdir()?;
        let tmp_dir2 = tempdir()?;

        let mut file_path = tmp_dir.path().to_path_buf();
        file_path.push("test");

        for _ in 1..10 {
            let tmp_dir_path = tmp_dir.path().to_path_buf();
            let tmp_dir_path2 = tmp_dir2.path().to_path_buf();
            let file_path = file_path.clone();
            join_handles.push(thread::spawn(move || {
                let (path, mut r) = get_or_write(
                    vec![
                        PathBuf::from(
                            "/proc/ENOENT DIRECTORY SHOULD NOT EXIST AND NOT BE ABLE TO CREATE/",
                        ),
                        tmp_dir_path,
                        tmp_dir_path2,
                    ],
                    "test".to_string(),
                    || Ok(Box::new(b"test test".as_slice())),
                    UpdateMode::ReadWrite,
                )
                .unwrap();
                let mut buffer = String::new();
                r.read_to_string(&mut buffer).unwrap();
                assert_eq!(buffer, "test test");
                assert_eq!(file_path, path);
            }));
        }

        for handle in join_handles {
            handle.join().unwrap();
        }
        Ok(())
    }

    #[test]
    fn test_empty_cache_path() -> anyhow::Result<()> {
        let res = get_or_write(
            vec![PathBuf::from(
                "/proc/ENOENT DIRECTORY SHOULD NOT EXIST AND NOT BE ABLE TO CREATE/",
            )],
            "test".to_string(),
            || Ok(Box::new(b"test test".as_slice())),
            UpdateMode::ReadOnly,
        );
        let error = res.err().unwrap();

        assert!(matches!(
            error.downcast_ref::<io::Error>().map(io::Error::kind),
            Some(ErrorKind::NotFound)
        ));

        Ok(())
    }
}
