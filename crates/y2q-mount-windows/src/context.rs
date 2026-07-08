//! WinFsp filesystem context for y2q. Mirrors `y2q-fuse`'s `fs.rs` at the
//! semantic level (same bucket/key resolution, same "buffer writes to a
//! tempfile and PUT once on close" strategy — an object store can't support
//! WinFsp's incremental in-place-write protocol any more than FUSE's), but
//! the shape is necessarily different: WinFsp callbacks are path-keyed (the
//! full path arrives on every call) rather than inode-keyed, so there is no
//! `InodeTable` equivalent here — see `y2q-mount-core` for the rationale.
//!
//! Built against the `winfsp_wrs` 0.4 API as read from its published source
//! (github.com/Scille/winfsp_wrs) — this crate has not been compiled or
//! tested against a real Windows + WinFsp environment (no Windows toolchain
//! was available while writing it). Validate on Windows CI/hardware before
//! relying on it.

use std::collections::HashMap;
use std::io::{Seek, SeekFrom, Write as IoWrite};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use tempfile::NamedTempFile;
use winfsp_wrs::{
    CleanupFlags, CreateFileInfo, CreateOptions, DirInfo, FileAccessRights, FileAttributes,
    FileInfo, FileSystemInterface, NTSTATUS, PSecurityDescriptor, STATUS_ACCESS_DENIED,
    STATUS_DIRECTORY_NOT_EMPTY, STATUS_END_OF_FILE, STATUS_IO_DEVICE_ERROR,
    STATUS_MEDIA_WRITE_PROTECTED, STATUS_NOT_A_DIRECTORY, STATUS_OBJECT_NAME_COLLISION,
    STATUS_OBJECT_NAME_NOT_FOUND, SecurityDescriptor, U16CStr, VolumeInfo, WriteMode, filetime_now,
    u16cstr, u16str,
};
use y2q_client::{ClientError, ListOptions, MetadataView, Y2qClient};
use y2q_mount_core::dir::{ChildEntry, list_children};
use y2q_mount_core::path::{CachedMeta, InodePath, MountMode};

use crate::error::{WinMountError, to_ntstatus};

const ATTR_TTL: Duration = Duration::from_secs(5);

/// Windows FILETIME (100ns intervals since 1601-01-01) for a y2q timestamp
/// (nanoseconds since the Unix epoch). Same formula `winfsp_wrs::filetime_now`
/// uses internally, inlined here to avoid pulling in `chrono` just for this.
const EPOCH_AS_FILETIME: u64 = 116_444_736_000_000_000;
fn ns_to_filetime(ns: u64) -> u64 {
    ns / 100 + EPOCH_AS_FILETIME
}

fn cached_meta_from_head(head: &MetadataView) -> CachedMeta {
    CachedMeta {
        size: head.size,
        created: head.created,
        modified: head.modified,
        checksum_gxhash: head.checksum_gxhash.clone(),
        labels: head.labels.clone(),
        cipher_size: head.cipher_size,
        cipher_sha256: head.cipher_sha256.clone(),
        kem_alg: head.kem_alg.clone(),
        aead_alg: head.aead_alg.clone(),
        envelope_version: head.envelope_version,
    }
}

/// A path resolved into what would need to be created/looked up, before we
/// know whether it already exists.
enum Target {
    Root,
    Bucket(String),
    KeyIsh { bucket: String, key: String },
}

/// Per-open-file state. Reads always hit the server directly (matching
/// `y2q-fuse`'s `read()`, which has the same limitation); writes buffer to a
/// local tempfile and are PUT to the server once in `close()`.
pub struct OpenFile {
    path: InodePath,
    is_dir: bool,
    /// True if this handle was opened against something that already existed
    /// on the server — governs whether the first `write()` must seed the
    /// buffer with current content before applying the write.
    existed: bool,
    write_buf: Mutex<Option<NamedTempFile>>,
    deleted: AtomicBool,
}

impl OpenFile {
    fn new_dir(path: InodePath) -> Self {
        Self {
            path,
            is_dir: true,
            existed: true,
            write_buf: Mutex::new(None),
            deleted: AtomicBool::new(false),
        }
    }

    fn new_file(path: InodePath, existed: bool) -> Self {
        Self {
            path,
            is_dir: false,
            existed,
            write_buf: Mutex::new(None),
            deleted: AtomicBool::new(false),
        }
    }
}

struct MetaCache {
    entries: Mutex<HashMap<InodePath, (CachedMeta, Instant)>>,
}

impl MetaCache {
    fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn get_fresh(&self, path: &InodePath) -> Option<CachedMeta> {
        let g = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        g.get(path)
            .filter(|(_, at)| at.elapsed() < ATTR_TTL)
            .map(|(m, _)| m.clone())
    }

    fn set(&self, path: InodePath, meta: CachedMeta) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(path, (meta, Instant::now()));
    }

    fn invalidate(&self, path: &InodePath) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(path);
    }
}

pub struct Y2qWinFs {
    client: Arc<RwLock<Y2qClient>>,
    rt: tokio::runtime::Handle,
    read_only: bool,
    mode: MountMode,
    meta: MetaCache,
    security_descriptor: SecurityDescriptor,
}

impl Y2qWinFs {
    pub fn new(
        client: Arc<RwLock<Y2qClient>>,
        rt: tokio::runtime::Handle,
        read_only: bool,
        mode: MountMode,
    ) -> Result<Self, WinMountError> {
        // Full access to SYSTEM, built-in Admins, and Everyone — y2q has no
        // concept of Windows ACLs to project, so this is the same permissive
        // static descriptor the winfsp_wrs `memfs` example uses.
        let security_descriptor = SecurityDescriptor::from_wstr(u16cstr!(
            "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)"
        ))
        .map_err(WinMountError::Other)?;
        Ok(Self {
            client,
            rt,
            read_only,
            mode,
            meta: MetaCache::new(),
            security_descriptor,
        })
    }

    fn client_clone(&self) -> Y2qClient {
        self.client
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn dir_file_info(&self) -> FileInfo {
        let now = filetime_now();
        let mut info = FileInfo::default();
        info.set_file_attributes(FileAttributes::DIRECTORY)
            .set_time(now);
        info
    }

    fn new_file_info(&self) -> FileInfo {
        let now = filetime_now();
        let mut info = FileInfo::default();
        info.set_file_attributes(FileAttributes::ARCHIVE)
            .set_time(now);
        info
    }

    fn object_file_info(meta: &CachedMeta) -> FileInfo {
        let mut info = FileInfo::default();
        info.set_file_attributes(FileAttributes::ARCHIVE)
            .set_file_size(meta.size)
            .set_allocation_size(meta.size)
            .set_creation_time(ns_to_filetime(meta.created))
            .set_last_write_time(ns_to_filetime(meta.modified))
            .set_last_access_time(ns_to_filetime(meta.modified))
            .set_change_time(ns_to_filetime(meta.modified));
        info
    }

    fn file_info_from_tmp(tmp: &NamedTempFile) -> FileInfo {
        let size = tmp.as_file().metadata().map(|m| m.len()).unwrap_or(0);
        let now = filetime_now();
        let mut info = FileInfo::default();
        info.set_file_attributes(FileAttributes::ARCHIVE)
            .set_file_size(size)
            .set_allocation_size(size)
            .set_time(now);
        info
    }

    /// Split a WinFsp path (`\`-separated, rooted at `\`) into a target,
    /// according to the mount's single-bucket-vs-multi-bucket mode.
    fn split_target(&self, file_name: &U16CStr) -> Target {
        let os = file_name.to_os_string();
        let s = os.to_string_lossy();
        let components: Vec<&str> = s.split('\\').filter(|c| !c.is_empty()).collect();

        match &self.mode {
            MountMode::Single(bucket) => {
                if components.is_empty() {
                    Target::Bucket(bucket.clone())
                } else {
                    Target::KeyIsh {
                        bucket: bucket.clone(),
                        key: components.join("/"),
                    }
                }
            }
            MountMode::Multi => {
                if components.is_empty() {
                    Target::Root
                } else if components.len() == 1 {
                    Target::Bucket(components[0].to_owned())
                } else {
                    Target::KeyIsh {
                        bucket: components[0].to_owned(),
                        key: components[1..].join("/"),
                    }
                }
            }
        }
    }

    /// Resolve a path to an existing filesystem entry. `None` inside the
    /// `KeyIsh` branch (neither an object nor anything with children under
    /// it as a prefix) means "not found".
    fn resolve(
        &self,
        file_name: &U16CStr,
    ) -> Result<(InodePath, bool, Option<CachedMeta>), NTSTATUS> {
        match self.split_target(file_name) {
            Target::Root => Ok((InodePath::Root, true, None)),
            Target::Bucket(name) => match &self.mode {
                MountMode::Single(_) => Ok((InodePath::Bucket(name), true, None)),
                MountMode::Multi => {
                    let client = self.client_clone();
                    let n = name.clone();
                    let exists = self
                        .rt
                        .block_on(async move { client.list_buckets().await })
                        .map(|bs| bs.iter().any(|b| b == &n))
                        .map_err(|e| to_ntstatus(&e))?;
                    if exists {
                        Ok((InodePath::Bucket(name), true, None))
                    } else {
                        Err(STATUS_OBJECT_NAME_NOT_FOUND)
                    }
                }
            },
            Target::KeyIsh { bucket, key } => {
                let object_path = InodePath::Object {
                    bucket: bucket.clone(),
                    key: key.clone(),
                };
                if let Some(cached) = self.meta.get_fresh(&object_path) {
                    return Ok((object_path, false, Some(cached)));
                }

                let client = self.client_clone();
                let b = bucket.clone();
                let k = key.clone();
                let head_result = self.rt.block_on(async move { client.head(&b, &k).await });

                match head_result {
                    Ok(head) => {
                        let meta = cached_meta_from_head(&head);
                        self.meta.set(object_path.clone(), meta.clone());
                        Ok((object_path, false, Some(meta)))
                    }
                    Err(ClientError::NotFound { .. }) => {
                        let client = self.client_clone();
                        let b = bucket.clone();
                        let dir_prefix = format!("{key}/");
                        let has_children = self
                            .rt
                            .block_on(async move {
                                client
                                    .list_objects(
                                        &b,
                                        &ListOptions {
                                            prefix: Some(dir_prefix),
                                            after: None,
                                            limit: Some(1),
                                        },
                                    )
                                    .await
                            })
                            .map(|page| !page.items.is_empty())
                            .map_err(|e| to_ntstatus(&e))?;
                        if has_children {
                            Ok((
                                InodePath::VirtualDir {
                                    bucket,
                                    prefix: key,
                                },
                                true,
                                None,
                            ))
                        } else {
                            Err(STATUS_OBJECT_NAME_NOT_FOUND)
                        }
                    }
                    Err(e) => Err(to_ntstatus(&e)),
                }
            }
        }
    }

    /// Lazily materialize `fc`'s write buffer, seeding it with the object's
    /// current server content on first touch if `fc.existed`.
    fn ensure_write_buf(&self, fc: &OpenFile) -> Result<(), NTSTATUS> {
        let mut guard = fc.write_buf.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_some() {
            return Ok(());
        }
        let tmp = NamedTempFile::new().map_err(|_| STATUS_IO_DEVICE_ERROR)?;
        if fc.existed
            && let InodePath::Object { bucket, key } = &fc.path
        {
            let write_copy = tmp.reopen().map_err(|_| STATUS_IO_DEVICE_ERROR)?;
            let client = self.client_clone();
            let b = bucket.clone();
            let k = key.clone();
            let result = self.rt.block_on(async move {
                let mut writer = tokio::fs::File::from_std(write_copy);
                client.get_to_writer(&b, &k, &mut writer).await
            });
            match result {
                Ok(_) | Err(ClientError::NotFound { .. }) => {}
                Err(e) => return Err(to_ntstatus(&e)),
            }
        }
        *guard = Some(tmp);
        Ok(())
    }
}

impl FileSystemInterface for Y2qWinFs {
    type FileContext = Arc<OpenFile>;

    const GET_VOLUME_INFO_DEFINED: bool = true;
    fn get_volume_info(&self) -> Result<VolumeInfo, NTSTATUS> {
        // Object store capacity is unknown; report a large fixed size,
        // matching y2q-fuse's `statfs` (1 PiB).
        const ONE_PIB: u64 = 1u64 << 50;
        VolumeInfo::new(ONE_PIB, ONE_PIB, u16str!("y2q")).map_err(|_| STATUS_IO_DEVICE_ERROR)
    }

    const GET_SECURITY_BY_NAME_DEFINED: bool = true;
    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        _find_reparse_point: impl Fn() -> Option<FileAttributes>,
    ) -> Result<(FileAttributes, PSecurityDescriptor, bool), NTSTATUS> {
        let (_, is_dir, _) = self.resolve(file_name)?;
        let attrs = if is_dir {
            FileAttributes::DIRECTORY
        } else {
            FileAttributes::ARCHIVE
        };
        Ok((attrs, self.security_descriptor.as_ptr(), false))
    }

    const CREATE_EX_DEFINED: bool = true;
    fn create_ex(
        &self,
        file_name: &U16CStr,
        create_file_info: CreateFileInfo,
        _security_descriptor: SecurityDescriptor,
        _buffer: &[u8],
        _extra_buffer_is_reparse_point: bool,
    ) -> Result<(Self::FileContext, FileInfo), NTSTATUS> {
        if self.read_only {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }

        let is_dir_request = create_file_info
            .create_options
            .is(CreateOptions::FILE_DIRECTORY_FILE);

        match (self.split_target(file_name), is_dir_request) {
            (Target::Root, _) => Err(STATUS_ACCESS_DENIED),

            (Target::Bucket(name), true) => {
                let client = self.client_clone();
                let n = name.clone();
                match self
                    .rt
                    .block_on(async move { client.create_bucket(&n).await })
                {
                    Ok(_) => {
                        let fc = Arc::new(OpenFile::new_dir(InodePath::Bucket(name)));
                        Ok((fc, self.dir_file_info()))
                    }
                    Err(ClientError::Conflict { .. }) => Err(STATUS_OBJECT_NAME_COLLISION),
                    Err(e) => Err(to_ntstatus(&e)),
                }
            }

            (Target::Bucket(_), false) => Err(STATUS_ACCESS_DENIED),

            (Target::KeyIsh { bucket, key }, true) => {
                let fc = Arc::new(OpenFile::new_dir(InodePath::VirtualDir {
                    bucket,
                    prefix: key,
                }));
                Ok((fc, self.dir_file_info()))
            }

            (Target::KeyIsh { bucket, key }, false) => {
                let path = InodePath::Object { bucket, key };
                let fc = OpenFile::new_file(path, false);
                let tmp = NamedTempFile::new().map_err(|_| STATUS_IO_DEVICE_ERROR)?;
                *fc.write_buf.lock().unwrap_or_else(|e| e.into_inner()) = Some(tmp);
                Ok((Arc::new(fc), self.new_file_info()))
            }
        }
    }

    const OPEN_DEFINED: bool = true;
    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: CreateOptions,
        _granted_access: FileAccessRights,
    ) -> Result<(Self::FileContext, FileInfo), NTSTATUS> {
        let (path, is_dir, meta) = self.resolve(file_name)?;
        let info = if is_dir {
            self.dir_file_info()
        } else {
            Self::object_file_info(&meta.unwrap_or(CachedMeta {
                size: 0,
                created: 0,
                modified: 0,
                checksum_gxhash: String::new(),
                labels: Default::default(),
                cipher_size: None,
                cipher_sha256: None,
                kem_alg: None,
                aead_alg: None,
                envelope_version: None,
            }))
        };
        let fc = if is_dir {
            OpenFile::new_dir(path)
        } else {
            OpenFile::new_file(path, true)
        };
        Ok((Arc::new(fc), info))
    }

    const OVERWRITE_EX_DEFINED: bool = true;
    fn overwrite_ex(
        &self,
        file_context: Self::FileContext,
        _file_attributes: FileAttributes,
        _replace_file_attributes: bool,
        _allocation_size: u64,
        _buffer: &[u8],
    ) -> Result<FileInfo, NTSTATUS> {
        if self.read_only {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }
        let tmp = NamedTempFile::new().map_err(|_| STATUS_IO_DEVICE_ERROR)?;
        *file_context
            .write_buf
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(tmp);
        Ok(self.new_file_info())
    }

    const CLEANUP_DEFINED: bool = true;
    fn cleanup(
        &self,
        file_context: Self::FileContext,
        file_name: Option<&U16CStr>,
        flags: CleanupFlags,
    ) {
        if file_name.is_none() || !flags.is(CleanupFlags::DELETE) || self.read_only {
            return;
        }
        file_context.deleted.store(true, Ordering::SeqCst);
        let client = self.client_clone();
        match &file_context.path {
            InodePath::Object { bucket, key } => {
                let b = bucket.clone();
                let k = key.clone();
                let _ = self.rt.block_on(async move { client.delete(&b, &k).await });
                self.meta.invalidate(&file_context.path);
            }
            InodePath::Bucket(name) => {
                let n = name.clone();
                let _ = self
                    .rt
                    .block_on(async move { client.delete_bucket(&n).await });
            }
            InodePath::VirtualDir { .. } | InodePath::Root => {}
        }
    }

    const CLOSE_DEFINED: bool = true;
    fn close(&self, file_context: Self::FileContext) {
        if file_context.deleted.load(Ordering::SeqCst) || self.read_only {
            return;
        }
        let tmp = {
            let mut guard = file_context
                .write_buf
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            guard.take()
        };
        let Some(mut tmp) = tmp else { return };
        let InodePath::Object { bucket, key } = &file_context.path else {
            return;
        };
        let size = match tmp.as_file().metadata() {
            Ok(m) => m.len(),
            Err(e) => {
                tracing::error!("close stat {bucket}/{key}: {e}");
                return;
            }
        };
        if let Err(e) = tmp.seek(SeekFrom::Start(0)) {
            tracing::error!("close seek {bucket}/{key}: {e}");
            return;
        }
        let std_file = match tmp.reopen() {
            Ok(f) => f,
            Err(e) => {
                tracing::error!("close reopen {bucket}/{key}: {e}");
                return;
            }
        };
        let client = self.client_clone();
        let b = bucket.clone();
        let k = key.clone();
        let result = self.rt.block_on(async move {
            let async_file = tokio::fs::File::from_std(std_file);
            client
                .put_from_reader(&b, &k, async_file, Some(size), &Default::default(), None)
                .await
        });
        match result {
            Ok(_) => self.meta.invalidate(&file_context.path),
            Err(e) => tracing::error!("close PUT {bucket}/{key}: {e}"),
        }
    }

    const READ_DEFINED: bool = true;
    fn read(
        &self,
        file_context: Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> Result<usize, NTSTATUS> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let InodePath::Object { bucket, key } = &file_context.path else {
            return Err(STATUS_NOT_A_DIRECTORY);
        };

        // y2qd returns 416 when end >= file_size; clamp using cached size so
        // the last chunk never overruns EOF (mirrors y2q-fuse::fs::read).
        let cached_size = self.meta.get_fresh(&file_context.path).map(|m| m.size);
        if let Some(size) = cached_size
            && offset >= size
        {
            return Err(STATUS_END_OF_FILE);
        }
        let end = match cached_size {
            Some(size) => (offset + buffer.len() as u64 - 1).min(size.saturating_sub(1)),
            None => offset + buffer.len() as u64 - 1,
        };

        let client = self.client_clone();
        let b = bucket.clone();
        let k = key.clone();
        let result = self.rt.block_on(async move {
            let mut buf = Vec::with_capacity((end - offset + 1) as usize);
            client
                .get_range_to_writer(&b, &k, offset, end, &mut buf)
                .await?;
            Ok::<Vec<u8>, ClientError>(buf)
        });
        match result {
            Ok(data) => {
                let n = data.len().min(buffer.len());
                buffer[..n].copy_from_slice(&data[..n]);
                Ok(n)
            }
            Err(ClientError::ServerError { status: 416, .. }) => Ok(0),
            Err(e) => Err(to_ntstatus(&e)),
        }
    }

    const WRITE_DEFINED: bool = true;
    fn write(
        &self,
        file_context: Self::FileContext,
        buffer: &[u8],
        mode: WriteMode,
    ) -> Result<(usize, FileInfo), NTSTATUS> {
        if self.read_only {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }
        self.ensure_write_buf(&file_context)?;

        let mut guard = file_context
            .write_buf
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = guard
            .as_mut()
            .expect("ensure_write_buf just populated this");

        let current_len = tmp
            .as_file()
            .metadata()
            .map_err(|_| STATUS_IO_DEVICE_ERROR)?
            .len();

        let (offset, to_write) = match mode {
            WriteMode::Normal { offset } => (offset, buffer),
            WriteMode::WriteToEOF => (current_len, buffer),
            WriteMode::ConstrainedIO { offset } => {
                if offset >= current_len {
                    return Ok((0, Self::file_info_from_tmp(tmp)));
                }
                let end = current_len.min(offset + buffer.len() as u64);
                (offset, &buffer[..(end - offset) as usize])
            }
        };

        tmp.seek(SeekFrom::Start(offset))
            .map_err(|_| STATUS_IO_DEVICE_ERROR)?;
        tmp.write_all(to_write)
            .map_err(|_| STATUS_IO_DEVICE_ERROR)?;

        Ok((to_write.len(), Self::file_info_from_tmp(tmp)))
    }

    const FLUSH_DEFINED: bool = true;
    fn flush(&self, file_context: Self::FileContext) -> Result<FileInfo, NTSTATUS> {
        self.get_file_info(file_context)
    }

    const GET_FILE_INFO_DEFINED: bool = true;
    fn get_file_info(&self, file_context: Self::FileContext) -> Result<FileInfo, NTSTATUS> {
        if file_context.is_dir {
            return Ok(self.dir_file_info());
        }
        if let Some(tmp) = file_context
            .write_buf
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            return Ok(Self::file_info_from_tmp(tmp));
        }
        let InodePath::Object { bucket, key } = &file_context.path else {
            return Ok(self.dir_file_info());
        };
        if let Some(meta) = self.meta.get_fresh(&file_context.path) {
            return Ok(Self::object_file_info(&meta));
        }
        let client = self.client_clone();
        let b = bucket.clone();
        let k = key.clone();
        match self.rt.block_on(async move { client.head(&b, &k).await }) {
            Ok(head) => {
                let meta = cached_meta_from_head(&head);
                self.meta.set(file_context.path.clone(), meta.clone());
                Ok(Self::object_file_info(&meta))
            }
            Err(e) => Err(to_ntstatus(&e)),
        }
    }

    const SET_BASIC_INFO_DEFINED: bool = true;
    fn set_basic_info(
        &self,
        file_context: Self::FileContext,
        _file_attributes: FileAttributes,
        _creation_time: u64,
        _last_access_time: u64,
        _last_write_time: u64,
        _change_time: u64,
    ) -> Result<FileInfo, NTSTATUS> {
        // y2q objects don't have independently settable creation/mtimes;
        // accept the call (Explorer/apps expect it not to fail) but only
        // report current synthetic attrs, matching y2q-fuse::fs::setattr.
        self.get_file_info(file_context)
    }

    const SET_FILE_SIZE_DEFINED: bool = true;
    fn set_file_size(
        &self,
        file_context: Self::FileContext,
        new_size: u64,
        _set_allocation_size: bool,
    ) -> Result<FileInfo, NTSTATUS> {
        if self.read_only {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }
        self.ensure_write_buf(&file_context)?;
        let mut guard = file_context
            .write_buf
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = guard
            .as_mut()
            .expect("ensure_write_buf just populated this");
        tmp.as_file()
            .set_len(new_size)
            .map_err(|_| STATUS_IO_DEVICE_ERROR)?;
        Ok(Self::file_info_from_tmp(tmp))
    }

    const RENAME_DEFINED: bool = true;
    fn rename(
        &self,
        file_context: Self::FileContext,
        _file_name: &U16CStr,
        new_file_name: &U16CStr,
        _replace_if_exists: bool,
    ) -> Result<(), NTSTATUS> {
        if self.read_only {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }
        let InodePath::Object {
            bucket: src_bucket,
            key: src_key,
        } = &file_context.path
        else {
            // Directory/bucket rename isn't supported — same restriction as
            // y2q-fuse (virtual dirs exist only by key-prefix convention).
            return Err(STATUS_ACCESS_DENIED);
        };

        let dst = match self.split_target(new_file_name) {
            Target::KeyIsh { bucket, key } => (bucket, key),
            _ => return Err(STATUS_ACCESS_DENIED),
        };
        if &dst.0 != src_bucket {
            // Cross-bucket rename is technically possible but complex; reject
            // (same call y2q-fuse makes for cross-bucket rename).
            return Err(STATUS_ACCESS_DENIED);
        }
        if &dst.1 == src_key {
            return Ok(());
        }

        let client = self.client_clone();
        let (sb, sk, db, dk) = (src_bucket.clone(), src_key.clone(), dst.0, dst.1);
        let result = self.rt.block_on(async move {
            let tmp = tempfile::NamedTempFile::new().map_err(ClientError::Io)?;
            let write_copy = tmp.reopen().map_err(ClientError::Io)?;
            let mut writer = tokio::fs::File::from_std(write_copy);
            client.get_to_writer(&sb, &sk, &mut writer).await?;
            let size = writer.metadata().await.map_err(ClientError::Io)?.len();
            let read_copy = tmp.reopen().map_err(ClientError::Io)?;
            let reader = tokio::fs::File::from_std(read_copy);
            client
                .put_from_reader(&db, &dk, reader, Some(size), &Default::default(), None)
                .await?;
            client.delete(&sb, &sk).await?;
            drop(tmp);
            Ok::<(), ClientError>(())
        });
        result.map_err(|e| to_ntstatus(&e))?;
        self.meta.invalidate(&file_context.path);
        Ok(())
    }

    const GET_SECURITY_DEFINED: bool = true;
    fn get_security(
        &self,
        _file_context: Self::FileContext,
    ) -> Result<PSecurityDescriptor, NTSTATUS> {
        Ok(self.security_descriptor.as_ptr())
    }

    const SET_DELETE_DEFINED: bool = true;
    fn set_delete(
        &self,
        file_context: Self::FileContext,
        _file_name: &U16CStr,
        delete_file: bool,
    ) -> Result<(), NTSTATUS> {
        if !delete_file {
            return Ok(());
        }
        if self.read_only {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }
        let client = self.client_clone();
        let is_empty = match &file_context.path {
            InodePath::Bucket(b) => {
                let b = b.clone();
                self.rt
                    .block_on(async move { list_children(&client, &b, "").await })
                    .map(|c| c.is_empty())
                    .unwrap_or(true)
            }
            InodePath::VirtualDir { bucket, prefix } => {
                let b = bucket.clone();
                let p = format!("{prefix}/");
                self.rt
                    .block_on(async move { list_children(&client, &b, &p).await })
                    .map(|c| c.is_empty())
                    .unwrap_or(true)
            }
            InodePath::Object { .. } | InodePath::Root => true,
        };
        if is_empty {
            Ok(())
        } else {
            Err(STATUS_DIRECTORY_NOT_EMPTY)
        }
    }

    const READ_DIRECTORY_DEFINED: bool = true;
    fn read_directory(
        &self,
        file_context: Self::FileContext,
        marker: Option<&U16CStr>,
        mut add_dir_info: impl FnMut(DirInfo) -> bool,
    ) -> Result<(), NTSTATUS> {
        if !file_context.is_dir {
            return Err(STATUS_NOT_A_DIRECTORY);
        }

        let mut entries: Vec<(String, FileInfo)> = Vec::new();

        match &file_context.path {
            InodePath::Root => {
                let client = self.client_clone();
                let buckets = self
                    .rt
                    .block_on(async move { client.list_buckets().await })
                    .map_err(|e| to_ntstatus(&e))?;
                for b in buckets {
                    entries.push((b, self.dir_file_info()));
                }
            }
            InodePath::Bucket(_) | InodePath::VirtualDir { .. } => {
                let (bucket, prefix) = match &file_context.path {
                    InodePath::Bucket(b) => (b.clone(), String::new()),
                    InodePath::VirtualDir { bucket, prefix } => {
                        (bucket.clone(), format!("{prefix}/"))
                    }
                    _ => unreachable!(),
                };
                let client = self.client_clone();
                let children = match self
                    .rt
                    .block_on(async move { list_children(&client, &bucket, &prefix).await })
                {
                    Ok(c) => c,
                    Err(ClientError::NotFound { .. }) => vec![],
                    Err(e) => return Err(to_ntstatus(&e)),
                };
                for child in children {
                    match child {
                        ChildEntry::Dir { name } => entries.push((name, self.dir_file_info())),
                        ChildEntry::File { name, meta } => {
                            let cm = cached_meta_from_head(&meta);
                            entries.push((name, Self::object_file_info(&cm)));
                        }
                    }
                }
            }
            InodePath::Object { .. } => return Err(STATUS_NOT_A_DIRECTORY),
        }

        entries.sort_by(|a, b| a.0.cmp(&b.0));

        let mut out: Vec<(String, FileInfo)> = Vec::new();
        if marker.is_none() {
            out.push((".".to_owned(), self.dir_file_info()));
            out.push(("..".to_owned(), self.dir_file_info()));
        }
        out.extend(entries);

        if let Some(marker) = marker {
            let marker_str = marker.to_string_lossy();
            if let Some(pos) = out.iter().position(|(n, _)| n == &marker_str) {
                out.drain(..=pos);
            }
        }

        for (name, info) in out {
            let dir_info = DirInfo::from_str(info, &name);
            if !add_dir_info(dir_info) {
                break;
            }
        }

        Ok(())
    }
}
