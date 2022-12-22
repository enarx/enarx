// SPDX-License-Identifier: Apache-2.0

use crate::backend::sev::Firmware;

use std::fs::{self, remove_file};
use std::io::{self, ErrorKind, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use anyhow::Context;
use colorful::core::StrMarker;
use der::{Decode, Document, Sequence};

#[derive(Sequence)]
pub struct SnpEvidence {
    pub vcek: Document,
    pub crl: Document,
}

impl SnpEvidence {
    pub fn read() -> anyhow::Result<Self> {
        let mut vcek = Vec::new();
        let mut vcek_reader = get_vcek_reader()?;
        io::copy(&mut vcek_reader, &mut vcek)?;

        let mut crl = Vec::new();
        let (_, mut crl_reader) = get_crl_reader_with_path()?;
        io::copy(&mut crl_reader, &mut crl)?;

        Ok(Self {
            vcek: Document::from_der(&vcek)?,
            crl: Document::from_der(&crl)?,
        })
    }
}

/// Return a reader, which provides the VCEK certificate
pub fn get_vcek_reader() -> anyhow::Result<Box<dyn Read>> {
    get_vcek_reader_with_path(sev_cache_dir()?).map(|(_, r)| r)
}

/// Update the global VCEK cache file
pub fn vcek_write() -> anyhow::Result<()> {
    vcek_write_with_path(sev_cache_dir()?)?;
    Ok(())
}

/// Returns a reader and a path, which provides the AMD CRLs
pub fn get_crl_reader_with_path() -> anyhow::Result<(PathBuf, Box<dyn Read>)> {
    read(sev_cache_dir()?, "crls.der".to_str())
}

/// Returns the "system-level" search path for the SEV
/// certificate chain (`/var/cache/amd-sev`).
pub fn sev_cache_dir() -> anyhow::Result<PathBuf> {
    const CACHE_DIR: &str = "/var/cache";

    let mut sys = PathBuf::from(CACHE_DIR);
    if sys.exists() && sys.is_dir() {
        sys.push("amd-sev");
        Ok(sys)
    } else {
        Err(io::Error::from(ErrorKind::NotFound))
            .with_context(|| format!("Directory `{CACHE_DIR}` does not exist!"))
    }
}

/// Returns a reader and a path, which provides the VCEK certificate
pub fn get_vcek_reader_with_path(cache_dir: PathBuf) -> anyhow::Result<(PathBuf, Box<dyn Read>)> {
    let (_, path) = get_vcek_url_path()?;

    read(cache_dir, path)
}

/// Write the VCEK certificate to a cache directory
///
/// Downloads the certificate from the standard URL, and stores it in the provided directory.
/// Returns the path, where it has been stored.
pub fn vcek_write_with_path(cache_dir: PathBuf) -> anyhow::Result<PathBuf> {
    let (url, path) = get_vcek_url_path()?;

    write(cache_dir, path, || {
        let call = ureq::get(&url)
            .call()
            .with_context(|| format!("Error getting vcek from URL {}", &url))?;
        let reader = call.into_reader();
        Ok(Box::new(reader))
    })
}

fn get_vcek_url_path() -> anyhow::Result<(String, String)> {
    // Get the platform information.
    let mut sev = Firmware::open().context("failed to open /dev/sev")?;
    let id = sev.identifier().context("failed to query identifier")?;
    let status = sev
        .platform_status()
        .context("failed to query platform status")?;

    let url = id.vcek_url(&status.tcb.reported_version);

    let path = id.vcek_cache_name(&status.tcb.reported_version);
    Ok((url, path))
}

// read the cached file
fn read(cache_dir: PathBuf, name: String) -> anyhow::Result<(PathBuf, Box<dyn Read>)> {
    let mut path_locked = cache_dir.clone();
    path_locked.push(name.clone() + ".lck");

    let mut path = cache_dir;
    path.push(&name);

    let mut retries = 100;

    while retries > 0 {
        let file =
            fs::File::open(&path).with_context(|| format!("Error reading `{}`", path.display()))?;

        if !path_locked.exists() {
            // no write in progress
            return Ok((path, Box::new(file)));
        }

        // sleep, write may be in progress
        std::thread::sleep(std::time::Duration::from_millis(200));
        retries -= 1;
    }

    Err(io::Error::from(ErrorKind::InvalidData))
        .with_context(|| format!("Potential stale lock file {:?}", &path_locked))
}

// write the file with the reader provided by the contents function
fn write(
    cache_dir: PathBuf,
    name: String,
    contents: impl Fn() -> anyhow::Result<Box<dyn Read>>,
) -> anyhow::Result<PathBuf> {
    // ignore error, error is handled in lock file creation
    let _ = fs::create_dir_all(&cache_dir);

    let mut path_locked = cache_dir.clone();
    path_locked.push(name.clone() + ".lck");

    let mut path = cache_dir;
    path.push(&name);

    if path.exists() {
        return Ok(path);
    }

    let _lock = fs::OpenOptions::new()
        .mode(0o644)
        .write(true)
        .create_new(true)
        .open(&path_locked)
        .with_context(|| format!("Error creating lockfile {}", path_locked.display()))?;

    let mut file = fs::OpenOptions::new()
        .mode(0o644)
        .write(true)
        .read(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("Error creating {}", path.display()))
        .map_err(|err| {
            let _ = remove_file(&path_locked);
            err
        })?;

    let _ = contents()
        .and_then(|mut contents| {
            io::copy(&mut contents, &mut file).with_context(|| format!("Error writing {:?}", &path))
        })
        .map_err(|e| {
            let _ = remove_file(&path);
            let _ = remove_file(&path_locked);
            e
        })?;

    let _ = remove_file(&path_locked);

    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::{read, write};

    use std::io::{self, ErrorKind, Read};
    use std::path::PathBuf;
    use std::thread;
    use tempfile::tempdir;

    #[test]
    fn test_write() -> anyhow::Result<()> {
        let mut join_handles = Vec::new();
        let tmp_dir = tempdir()?;

        let tmp_dir_path = tmp_dir.path().to_path_buf();

        let mut file_path = tmp_dir_path.clone();
        file_path.push("test");

        let file_path_write = file_path.clone();

        join_handles.push(thread::spawn(move || {
            thread::sleep(std::time::Duration::from_millis(200));
            let path = write(tmp_dir_path.clone(), "test".to_string(), || {
                Ok(Box::new(b"test test".as_slice()))
            })
            .unwrap();
            assert_eq!(file_path_write, path);
        }));

        for _ in 1..10 {
            let tmp_dir_path = tmp_dir.path().to_path_buf();
            let file_path = file_path.clone();
            join_handles.push(thread::spawn(move || {
                let mut retries = 100;

                while retries > 0 {
                    match read(tmp_dir_path.clone(), "test".to_string()) {
                        Err(e)
                            if matches!(
                                e.downcast_ref::<io::Error>().map(io::Error::kind),
                                Some(io::ErrorKind::NotFound)
                            ) =>
                        {
                            // sleep, write is in progress
                            thread::sleep(std::time::Duration::from_millis(100));
                            retries -= 1;
                            continue;
                        }
                        Ok((path, mut r)) => {
                            assert_eq!(file_path, path);
                            let mut buffer = String::new();
                            r.read_to_string(&mut buffer).unwrap();
                            assert_eq!(buffer, "test test");
                            break;
                        }
                        Err(e) => panic!("{e}"),
                    }
                }

                assert!(retries > 0);
            }));
        }

        for handle in join_handles {
            handle.join().unwrap();
        }
        Ok(())
    }

    #[test]
    fn test_invalid_cache_path() -> anyhow::Result<()> {
        let res = write(
            PathBuf::from("/proc/ENOENT DIRECTORY SHOULD NOT EXIST AND NOT BE ABLE TO CREATE/"),
            "test".to_string(),
            || Ok(Box::new(b"test test".as_slice())),
        );
        let error = res.err().unwrap();

        dbg!(&error);

        assert!(matches!(
            error.downcast_ref::<io::Error>().map(io::Error::kind),
            Some(ErrorKind::NotFound)
        ));

        Ok(())
    }
}
