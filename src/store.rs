//! Where the flows keep their credentials: the [`TokenStore`] trait, an
//! in-memory store, and an owner-only file store.
//!
//! The trait and both stores follow rig-core 0.45.0's
//! (`providers::internal::auth::store`, MIT), so a [`FileTokenStore`] and
//! rig's over one directory read and lock the same files. The `rig` feature
//! connects the two traits ([`crate::rig`]).
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// A store's error.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// A store's boxed future.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Keeps the credentials a sign-in writes and refreshes, each a JSON text
/// under a key the provider names (`openai`, `openrouter`).
///
/// A flow reads its record before it hands out a token, and saves it after a
/// sign-in or a refresh. A store shared with other processes holds the
/// record against them while a refresh or sign-in reads and saves it
/// ([`lock`](Self::lock)), so one refresh runs at a time. Implement it over
/// a keychain, a database or anything else that keeps a string per key.
pub trait TokenStore: Send + Sync {
    /// The record kept under `key`, or `None` when there is none. An error
    /// means the store could not answer.
    fn load<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<String>, BoxError>>;

    /// Keep `record` under `key`, replacing any record there.
    fn save<'a>(&'a self, key: &'a str, record: &'a str) -> BoxFuture<'a, Result<(), BoxError>>;

    /// Forget the record under `key`; forgetting a missing record succeeds.
    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), BoxError>>;

    /// Hold the record under `key` until the returned [`StoreLock`] is
    /// dropped, against every other holder of it, in this process or
    /// another. The default holds nothing: a store no other process reads
    /// needs no lock beyond the flow's own.
    fn lock<'a>(&'a self, _key: &'a str) -> BoxFuture<'a, Result<StoreLock, BoxError>> {
        Box::pin(async { Ok(StoreLock::new(())) })
    }
}

/// A record held by [`TokenStore::lock`], let go when dropped.
pub struct StoreLock {
    // Nothing reads the guard; the mutex only makes the lock `Sync`.
    _guard: Mutex<Box<dyn Send>>,
}

impl StoreLock {
    /// Holds `guard`, any value whose drop releases the store's lock, such
    /// as a locked file or an open transaction, until this lock is dropped.
    /// A store with nothing to release passes `()`. The guard's `Drop` may
    /// run inside an async task, so it must not block.
    pub fn new(guard: impl Send + 'static) -> Self {
        Self {
            _guard: Mutex::new(Box::new(guard)),
        }
    }
}

impl std::fmt::Debug for StoreLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreLock").finish_non_exhaustive()
    }
}

impl<T: TokenStore + ?Sized> TokenStore for Arc<T> {
    fn load<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<String>, BoxError>> {
        (**self).load(key)
    }

    fn save<'a>(&'a self, key: &'a str, record: &'a str) -> BoxFuture<'a, Result<(), BoxError>> {
        (**self).save(key, record)
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), BoxError>> {
        (**self).delete(key)
    }

    fn lock<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<StoreLock, BoxError>> {
        (**self).lock(key)
    }
}

/// A [`TokenStore`] in this process's memory, gone when it is dropped.
#[derive(Default)]
pub struct MemoryTokenStore(Mutex<HashMap<String, String>>);

impl std::fmt::Debug for MemoryTokenStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryTokenStore").finish_non_exhaustive()
    }
}

impl MemoryTokenStore {
    fn records(&self) -> std::sync::MutexGuard<'_, HashMap<String, String>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl TokenStore for MemoryTokenStore {
    fn load<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<String>, BoxError>> {
        Box::pin(async move { Ok(self.records().get(key).cloned()) })
    }

    fn save<'a>(&'a self, key: &'a str, record: &'a str) -> BoxFuture<'a, Result<(), BoxError>> {
        Box::pin(async move {
            self.records().insert(key.to_owned(), record.to_owned());
            Ok(())
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), BoxError>> {
        Box::pin(async move {
            self.records().remove(key);
            Ok(())
        })
    }
}

/// A [`TokenStore`] keeping each record in `<dir>/<key>.json`, written whole
/// or not at all (a temporary file renamed over it), and held across
/// processes with a file lock on `<dir>/<key>.lock`. On Unix the files, and
/// the directories it creates for them, are readable by the owner alone.
#[derive(Debug, Clone)]
pub struct FileTokenStore {
    dir: PathBuf,
}

impl FileTokenStore {
    /// A store over the files in `dir`, created when first written.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The file the record under `key` is kept in.
    pub fn path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.json"))
    }
}

impl TokenStore for FileTokenStore {
    fn load<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<String>, BoxError>> {
        Box::pin(async move {
            match std::fs::read_to_string(self.path(key)) {
                Ok(record) => Ok(Some(record)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error.into()),
            }
        })
    }

    fn save<'a>(&'a self, key: &'a str, record: &'a str) -> BoxFuture<'a, Result<(), BoxError>> {
        Box::pin(async move { Ok(write_private(&self.path(key), record.as_bytes())?) })
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), BoxError>> {
        Box::pin(async move {
            match std::fs::remove_file(self.path(key)) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
                _ => Ok(()),
            }
        })
    }

    /// Takes the file lock on `<dir>/<key>.lock`, waiting while another
    /// holder has it, for at most two minutes. A process that dies lets go
    /// of it.
    fn lock<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<StoreLock, BoxError>> {
        Box::pin(async move {
            let path = self.dir.join(format!("{key}.lock"));
            create_private_dir(&path)?;
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true).create(true).truncate(false);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            let file = options.open(&path)?;
            let started = std::time::Instant::now();
            loop {
                match file.try_lock() {
                    Ok(()) => return Ok(StoreLock::new(file)),
                    Err(std::fs::TryLockError::WouldBlock) if started.elapsed() < LOCK_WAIT => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    Err(std::fs::TryLockError::WouldBlock) => {
                        return Err(format!(
                            "another process has held {} for {} seconds",
                            path.display(),
                            LOCK_WAIT.as_secs()
                        )
                        .into());
                    }
                    Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
                }
            }
        })
    }
}

/// How long [`FileTokenStore::lock`] waits for another holder: far longer
/// than a refresh's one request takes.
const LOCK_WAIT: Duration = Duration::from_secs(120);

/// Creates the directories above `path`, 0700 on Unix.
fn create_private_dir(path: &Path) -> Result<(), std::io::Error> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(parent)
}

/// Writes a credential file whole or not at all, creating the directories
/// above it: the bytes go to a fresh temporary file beside it, which is
/// synced and renamed over it, so a crash or a reader at the same moment
/// never sees half a credential. On Unix the file is 0600 before anything
/// is written to it.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    static WRITES: AtomicU64 = AtomicU64::new(0);
    create_private_dir(path)?;
    let mut temp = path.as_os_str().to_owned();
    temp.push(format!(
        ".tmp-{}-{}",
        std::process::id(),
        WRITES.fetch_add(1, Ordering::Relaxed)
    ));
    let temp = PathBuf::from(temp);
    let write = || {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&temp)?;
        #[cfg(unix)]
        file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)
    };
    let written = write();
    if written.is_err() {
        std::fs::remove_file(&temp).ok();
    }
    written
}
