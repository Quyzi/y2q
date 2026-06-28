use std::collections::{BTreeSet, HashMap};
use std::io::{Seek, SeekFrom, Write as IoWrite};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr, Request,
};
use tempfile::NamedTempFile;
use y2q_client::{ClientError, ListOptions, Y2qClient};

use crate::dir::{ChildEntry, list_children};
use crate::error::to_errno;
use crate::inode::{CachedMeta, InodePath, InodeTable, ROOT_INO};

const ATTR_TTL: Duration = Duration::from_secs(5);
const ENTRY_TTL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub enum MountMode {
    /// All buckets appear as top-level directories.
    Multi,
    /// A single bucket is the filesystem root.
    Single(String),
}

struct OpenFile {
    bucket: String,
    key: String,
    /// Present for writable opens; absent for read-only opens.
    write_buf: Option<NamedTempFile>,
    dirty: bool,
    /// Set after flush() attempts the PUT so release() knows not to retry.
    flushed: bool,
}

pub struct Y2qFuse {
    client: Arc<RwLock<Y2qClient>>,
    rt: tokio::runtime::Handle,
    inodes: Mutex<InodeTable>,
    open_files: Mutex<HashMap<u64, OpenFile>>,
    next_fh: AtomicU64,
    read_only: bool,
    mode: MountMode,
    uid: u32,
    gid: u32,
}

impl Y2qFuse {
    pub fn new(
        client: Arc<RwLock<Y2qClient>>,
        rt: tokio::runtime::Handle,
        read_only: bool,
        mode: MountMode,
        uid: u32,
        gid: u32,
    ) -> Self {
        Self {
            client,
            rt,
            inodes: Mutex::new(InodeTable::new()),
            open_files: Mutex::new(HashMap::new()),
            next_fh: AtomicU64::new(1),
            read_only,
            mode,
            uid,
            gid,
        }
    }

    fn client_clone(&self) -> Y2qClient {
        self.client
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn alloc_fh(&self) -> u64 {
        self.next_fh.fetch_add(1, Ordering::Relaxed)
    }

    fn file_attr(&self, ino: u64, size: u64, created_ns: u64, modified_ns: u64) -> FileAttr {
        let created = UNIX_EPOCH + Duration::from_nanos(created_ns);
        let modified = UNIX_EPOCH + Duration::from_nanos(modified_ns);
        FileAttr {
            ino,
            size,
            blocks: size.div_ceil(512),
            atime: modified,
            mtime: modified,
            ctime: created,
            crtime: created,
            kind: FileType::RegularFile,
            perm: 0o644,
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }

    fn dir_attr(&self, ino: u64) -> FileAttr {
        let now = SystemTime::now();
        FileAttr {
            ino,
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: FileType::Directory,
            perm: 0o755,
            nlink: 2,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }

    /// Resolve an inode to (bucket, key_prefix) where prefix ends with "/" or
    /// is empty for bucket root. Returns None for root in multi mode, or for
    /// object inodes.
    fn inode_to_bucket_prefix(&self, ino: u64) -> Option<(String, String)> {
        let inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
        let entry = inodes.get(ino)?;
        match &entry.path {
            InodePath::Root => match &self.mode {
                // In single-bucket mode the root IS the bucket.
                MountMode::Single(b) => Some((b.clone(), String::new())),
                MountMode::Multi => None,
            },
            InodePath::Bucket(b) => Some((b.clone(), String::new())),
            InodePath::VirtualDir { bucket, prefix } => {
                Some((bucket.clone(), format!("{prefix}/")))
            }
            InodePath::Object { .. } => None,
        }
    }
}

impl Filesystem for Y2qFuse {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &std::ffi::OsStr, reply: ReplyEntry) {
        let name = name.to_string_lossy().into_owned();

        let parent_path = {
            let inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
            inodes.get(parent).map(|e| e.path.clone())
        };

        // In single-bucket mode the root IS the bucket; remap so the Bucket
        // branch below handles object/vdir lookups without duplicating logic.
        let parent_path =
            if let (Some(InodePath::Root), MountMode::Single(b)) = (&parent_path, &self.mode) {
                Some(InodePath::Bucket(b.clone()))
            } else {
                parent_path
            };

        match parent_path {
            Some(InodePath::Root) => {
                // Multi mode only after the remap above.
                let bucket = name.clone();
                let client = self.client_clone();
                let result = self.rt.block_on(async move {
                    let buckets = client.list_buckets().await?;
                    Ok::<bool, ClientError>(buckets.iter().any(|b| b == &bucket))
                });
                match result {
                    Ok(true) => {
                        let ino = self
                            .inodes
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .get_or_assign(InodePath::Bucket(name));
                        reply.entry(&ENTRY_TTL, &self.dir_attr(ino), 0);
                    }
                    Ok(false) => reply.error(libc::ENOENT),
                    Err(e) => reply.error(to_errno(&e)),
                }
            }

            Some(InodePath::Bucket(bucket)) => {
                let key = name.clone();
                let dir_prefix = format!("{key}/");
                let client = self.client_clone();
                let bucket2 = bucket.clone();
                let key2 = key.clone();
                let result = self.rt.block_on(async move {
                    let list_opts = ListOptions {
                        prefix: Some(dir_prefix),
                        after: None,
                        limit: Some(1),
                    };
                    let (head_res, list_res) = tokio::join!(
                        client.head(&bucket2, &key2),
                        client.list_objects(&bucket2, &list_opts)
                    );
                    Ok::<_, ClientError>((head_res, list_res))
                });
                match result {
                    Ok((Ok(head), _)) => {
                        let ino = {
                            let mut inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
                            let ino = inodes.get_or_assign(InodePath::Object {
                                bucket: bucket.clone(),
                                key,
                            });
                            inodes.update_meta(
                                ino,
                                CachedMeta {
                                    size: head.size,
                                    created: head.created,
                                    modified: head.modified,
                                    checksum_gxhash: head.checksum_gxhash.clone(),
                                    labels: head.labels.clone(),
                                },
                            );
                            ino
                        };
                        reply.entry(
                            &ENTRY_TTL,
                            &self.file_attr(ino, head.size, head.created, head.modified),
                            0,
                        );
                    }
                    Ok((Err(ClientError::NotFound { .. }), Ok(page))) if !page.items.is_empty() => {
                        let ino = self
                            .inodes
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .get_or_assign(InodePath::VirtualDir {
                                bucket,
                                prefix: key,
                            });
                        reply.entry(&ENTRY_TTL, &self.dir_attr(ino), 0);
                    }
                    Ok((Err(e), _)) => reply.error(to_errno(&e)),
                    _ => reply.error(libc::ENOENT),
                }
            }

            Some(InodePath::VirtualDir { bucket, prefix }) => {
                let key = format!("{prefix}/{name}");
                let dir_prefix = format!("{key}/");
                let client = self.client_clone();
                let bucket2 = bucket.clone();
                let key2 = key.clone();
                let result = self.rt.block_on(async move {
                    let list_opts = ListOptions {
                        prefix: Some(dir_prefix),
                        after: None,
                        limit: Some(1),
                    };
                    let (head_res, list_res) = tokio::join!(
                        client.head(&bucket2, &key2),
                        client.list_objects(&bucket2, &list_opts)
                    );
                    Ok::<_, ClientError>((head_res, list_res))
                });
                match result {
                    Ok((Ok(head), _)) => {
                        let ino = {
                            let mut inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
                            let ino = inodes.get_or_assign(InodePath::Object {
                                bucket: bucket.clone(),
                                key: key.clone(),
                            });
                            inodes.update_meta(
                                ino,
                                CachedMeta {
                                    size: head.size,
                                    created: head.created,
                                    modified: head.modified,
                                    checksum_gxhash: head.checksum_gxhash.clone(),
                                    labels: head.labels.clone(),
                                },
                            );
                            ino
                        };
                        reply.entry(
                            &ENTRY_TTL,
                            &self.file_attr(ino, head.size, head.created, head.modified),
                            0,
                        );
                    }
                    Ok((Err(ClientError::NotFound { .. }), Ok(page))) if !page.items.is_empty() => {
                        let ino = self
                            .inodes
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .get_or_assign(InodePath::VirtualDir {
                                bucket,
                                prefix: key,
                            });
                        reply.entry(&ENTRY_TTL, &self.dir_attr(ino), 0);
                    }
                    Ok((Err(e), _)) => reply.error(to_errno(&e)),
                    _ => reply.error(libc::ENOENT),
                }
            }

            _ => reply.error(libc::ENOENT),
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let path = {
            let inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
            let e = match inodes.get(ino) {
                Some(e) => e,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };
            // Return from cache if fresh.
            if let (true, Some(meta)) = (e.meta_fresh(), &e.cached_meta) {
                let attr = self.file_attr(ino, meta.size, meta.created, meta.modified);
                reply.attr(&ATTR_TTL, &attr);
                return;
            }
            e.path.clone()
        };

        match path {
            InodePath::Root | InodePath::Bucket(_) | InodePath::VirtualDir { .. } => {
                reply.attr(&ATTR_TTL, &self.dir_attr(ino));
            }
            InodePath::Object { bucket, key } => {
                let client = self.client_clone();
                match self
                    .rt
                    .block_on(async move { client.head(&bucket, &key).await })
                {
                    Ok(head) => {
                        self.inodes
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .update_meta(
                                ino,
                                CachedMeta {
                                    size: head.size,
                                    created: head.created,
                                    modified: head.modified,
                                    checksum_gxhash: head.checksum_gxhash.clone(),
                                    labels: head.labels.clone(),
                                },
                            );
                        reply.attr(
                            &ATTR_TTL,
                            &self.file_attr(ino, head.size, head.created, head.modified),
                        );
                    }
                    Err(e) => reply.error(to_errno(&e)),
                }
            }
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let path = {
            let inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
            match inodes.get(ino) {
                Some(e) => e.path.clone(),
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // In single-bucket mode the root IS the bucket; remap so the Bucket
        // branch below handles listing without duplicating logic.
        let path = if let (InodePath::Root, MountMode::Single(b)) = (&path, &self.mode) {
            InodePath::Bucket(b.clone())
        } else {
            path
        };

        match path {
            InodePath::Root => {
                // Multi mode only after the remap above.
                let client = self.client_clone();
                let buckets = match self.rt.block_on(async move { client.list_buckets().await }) {
                    Ok(b) => b,
                    Err(e) => {
                        reply.error(to_errno(&e));
                        return;
                    }
                };

                let mut entries: Vec<(u64, FileType, String)> = Vec::new();
                entries.push((ROOT_INO, FileType::Directory, ".".into()));
                entries.push((ROOT_INO, FileType::Directory, "..".into()));
                for bucket in buckets {
                    let bino = self
                        .inodes
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .get_or_assign(InodePath::Bucket(bucket.clone()));
                    entries.push((bino, FileType::Directory, bucket));
                }

                for (i, (ino, kind, name)) in
                    entries.into_iter().enumerate().skip(offset.max(0) as usize)
                {
                    if reply.add(ino, (i + 1) as i64, kind, &name) {
                        break;
                    }
                }
                reply.ok();
            }

            InodePath::Bucket(ref bucket) | InodePath::VirtualDir { ref bucket, .. } => {
                let prefix = match &path {
                    InodePath::Bucket(_) => String::new(),
                    InodePath::VirtualDir { prefix, .. } => format!("{prefix}/"),
                    _ => unreachable!(),
                };
                let client = self.client_clone();
                let bucket = bucket.clone();
                let pfx = prefix.clone();
                let children = match self
                    .rt
                    .block_on(async move { list_children(&client, &bucket, &pfx).await })
                {
                    Ok(c) => c,
                    Err(e) => {
                        reply.error(to_errno(&e));
                        return;
                    }
                };

                let parent_ino = match &path {
                    InodePath::Bucket(_) => ROOT_INO,
                    InodePath::VirtualDir { bucket, prefix } => {
                        let parent_path = match prefix.rfind('/') {
                            Some(pos) => InodePath::VirtualDir {
                                bucket: bucket.clone(),
                                prefix: prefix[..pos].to_owned(),
                            },
                            None => InodePath::Bucket(bucket.clone()),
                        };
                        self.inodes
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .get_or_assign(parent_path)
                    }
                    _ => unreachable!(),
                };

                let mut entries: Vec<(u64, FileType, String)> = Vec::new();
                entries.push((ino, FileType::Directory, ".".into()));
                entries.push((parent_ino, FileType::Directory, "..".into()));

                let (bucket_name, prefix_str) = match &path {
                    InodePath::Bucket(b) => (b.clone(), String::new()),
                    InodePath::VirtualDir {
                        bucket: b,
                        prefix: p,
                    } => (b.clone(), p.clone()),
                    _ => unreachable!(),
                };

                for child in children {
                    match child {
                        ChildEntry::Dir { name } => {
                            let child_prefix = if prefix_str.is_empty() {
                                name.clone()
                            } else {
                                format!("{prefix_str}/{name}")
                            };
                            let cino = self
                                .inodes
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .get_or_assign(InodePath::VirtualDir {
                                    bucket: bucket_name.clone(),
                                    prefix: child_prefix,
                                });
                            entries.push((cino, FileType::Directory, name));
                        }
                        ChildEntry::File { name, meta } => {
                            let key = if prefix_str.is_empty() {
                                name.clone()
                            } else {
                                format!("{prefix_str}/{name}")
                            };
                            let cino = {
                                let mut inodes =
                                    self.inodes.lock().unwrap_or_else(|e| e.into_inner());
                                let cino = inodes.get_or_assign(InodePath::Object {
                                    bucket: bucket_name.clone(),
                                    key,
                                });
                                inodes.update_meta(
                                    cino,
                                    CachedMeta {
                                        size: meta.size,
                                        created: meta.created,
                                        modified: meta.modified,
                                        checksum_gxhash: meta.checksum_gxhash.clone(),
                                        labels: meta.labels.clone(),
                                    },
                                );
                                cino
                            };
                            // `meta` is boxed; dereference silently via field access above.
                            entries.push((cino, FileType::RegularFile, name));
                        }
                    }
                }

                for (i, (ino, kind, name)) in
                    entries.into_iter().enumerate().skip(offset.max(0) as usize)
                {
                    if reply.add(ino, (i + 1) as i64, kind, &name) {
                        break;
                    }
                }
                reply.ok();
            }

            InodePath::Object { .. } => {
                reply.error(libc::ENOTDIR);
            }
        }
    }

    fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        let path = {
            let inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
            match inodes.get(ino) {
                Some(e) => e.path.clone(),
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        let (bucket, key) = match path {
            InodePath::Object { bucket, key } => (bucket, key),
            _ => {
                reply.error(libc::EISDIR);
                return;
            }
        };

        let write_requested = flags & libc::O_WRONLY != 0 || flags & libc::O_RDWR != 0;
        if write_requested && self.read_only {
            reply.error(libc::EROFS);
            return;
        }

        let (write_buf, dirty) = if write_requested {
            let trunc = flags & libc::O_TRUNC != 0;
            let mut tmp = match NamedTempFile::new() {
                Ok(f) => f,
                Err(e) => {
                    tracing::error!("tempfile: {e}");
                    reply.error(libc::EIO);
                    return;
                }
            };
            if !trunc {
                // Without O_TRUNC, seed the write buffer with the current
                // object so partial writes don't silently truncate the tail.
                let write_copy = match tmp.reopen() {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::error!("tempfile reopen: {e}");
                        reply.error(libc::EIO);
                        return;
                    }
                };
                let client = self.client_clone();
                let b = bucket.clone();
                let k = key.clone();
                let result = self.rt.block_on(async move {
                    let mut writer = tokio::fs::File::from_std(write_copy);
                    client.get_to_writer(&b, &k, &mut writer).await
                });
                match result {
                    Ok(_) | Err(ClientError::NotFound { .. }) => {}
                    Err(e) => {
                        reply.error(to_errno(&e));
                        return;
                    }
                }
                if let Err(e) = tmp.seek(SeekFrom::Start(0)) {
                    tracing::error!("tempfile seek: {e}");
                    reply.error(libc::EIO);
                    return;
                }
                (Some(tmp), false)
            } else {
                (Some(tmp), true)
            }
        } else {
            (None, false)
        };

        let fh = self.alloc_fh();
        self.open_files
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                fh,
                OpenFile {
                    bucket,
                    key,
                    write_buf,
                    dirty,
                    flushed: false,
                },
            );
        reply.opened(fh, 0);
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let (bucket, key) = {
            let guard = self.open_files.lock().unwrap_or_else(|e| e.into_inner());
            match guard.get(&fh) {
                Some(of) => (of.bucket.clone(), of.key.clone()),
                None => {
                    // Fall back to inode path.
                    let inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
                    match inodes.get(ino).map(|e| &e.path) {
                        Some(InodePath::Object { bucket, key }) => (bucket.clone(), key.clone()),
                        _ => {
                            reply.error(libc::EBADF);
                            return;
                        }
                    }
                }
            }
        };

        // y2qd returns 416 when end >= file_size (strict bound check). Clamp
        // the range using the cached inode size so the last chunk never exceeds
        // EOF. If the offset is already past EOF, signal EOF with 0 bytes.
        let cached_size = self
            .inodes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(ino)
            .and_then(|e| e.cached_meta.as_ref())
            .map(|m| m.size);

        let start = offset as u64;
        if let Some(file_size) = cached_size
            && start >= file_size
        {
            reply.data(&[]);
            return;
        }
        let end = {
            let raw_end = start + size as u64 - 1;
            match cached_size {
                Some(file_size) => raw_end.min(file_size - 1),
                None => raw_end,
            }
        };

        let client = self.client_clone();
        let result = self.rt.block_on(async move {
            let mut buf = Vec::with_capacity((end - start + 1) as usize);
            client
                .get_range_to_writer(&bucket, &key, start, end, &mut buf)
                .await?;
            Ok::<Vec<u8>, ClientError>(buf)
        });
        match result {
            Ok(data) => reply.data(&data),
            // 416: server says range not satisfiable — treat as EOF.
            Err(ClientError::ServerError { status: 416, .. }) => reply.data(&[]),
            Err(e) => reply.error(to_errno(&e)),
        }
    }

    fn create(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &std::ffi::OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        if self.read_only {
            reply.error(libc::EROFS);
            return;
        }

        let name = name.to_string_lossy().into_owned();

        let (bucket, prefix) = match self.inode_to_bucket_prefix(parent) {
            Some(bp) => bp,
            None => {
                // Parent is root in multi mode — creating files at root is not valid.
                reply.error(libc::EPERM);
                return;
            }
        };

        let key = format!("{prefix}{name}");
        let buf = match NamedTempFile::new() {
            Ok(f) => f,
            Err(e) => {
                tracing::error!("tempfile: {e}");
                reply.error(libc::EIO);
                return;
            }
        };

        let ino = self
            .inodes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_or_assign(InodePath::Object {
                bucket: bucket.clone(),
                key: key.clone(),
            });
        let fh = self.alloc_fh();
        self.open_files
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                fh,
                OpenFile {
                    bucket,
                    key,
                    write_buf: Some(buf),
                    dirty: true,
                    flushed: false,
                },
            );

        let attr = self.file_attr(ino, 0, 0, 0);
        reply.created(&ENTRY_TTL, &attr, 0, fh, 0);
    }

    fn write(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        if self.read_only {
            reply.error(libc::EROFS);
            return;
        }

        let mut guard = self.open_files.lock().unwrap_or_else(|e| e.into_inner());
        let of = match guard.get_mut(&fh) {
            Some(of) => of,
            None => {
                reply.error(libc::EBADF);
                return;
            }
        };
        let buf = match of.write_buf.as_mut() {
            Some(b) => b,
            None => {
                reply.error(libc::EBADF);
                return;
            }
        };

        if let Err(e) = buf.seek(SeekFrom::Start(offset as u64)) {
            tracing::error!("seek: {e}");
            reply.error(libc::EIO);
            return;
        }
        match buf.write_all(data) {
            Ok(()) => {
                of.dirty = true;
                of.flushed = false; // a new write invalidates any prior flush
                reply.written(data.len() as u32);
            }
            Err(e) => {
                tracing::error!("write: {e}");
                reply.error(libc::EIO);
            }
        }
    }

    fn release(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        // flush() already did the PUT and reported the result to close().
        // If for any reason flush() was skipped (flushed=false), do a
        // best-effort PUT here — errors are logged but can't reach the caller.
        let of = self
            .open_files
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&fh);
        if let Some(mut of) = of
            && of.dirty
            && !of.flushed
            && let Some(mut tmp) = of.write_buf.take()
        {
            let size = match tmp.as_file().metadata() {
                Ok(m) => m.len(),
                Err(e) => {
                    tracing::error!("release stat: {e}");
                    reply.ok();
                    return;
                }
            };
            if let Err(e) = tmp.seek(SeekFrom::Start(0)) {
                tracing::error!("release seek: {e}");
                reply.ok();
                return;
            }
            let std_file = match tmp.reopen() {
                Ok(f) => f,
                Err(e) => {
                    tracing::error!("release reopen: {e}");
                    reply.ok();
                    return;
                }
            };
            let bucket = of.bucket.clone();
            let key = of.key.clone();
            let client = self.client_clone();
            let result = self.rt.block_on(async move {
                let async_file = tokio::fs::File::from_std(std_file);
                client
                    .put_from_reader(
                        &bucket,
                        &key,
                        async_file,
                        Some(size),
                        &Default::default(),
                        None,
                    )
                    .await
            });
            if let Err(e) = result {
                tracing::error!("release PUT {}/{}: {e}", of.bucket, of.key);
            }
            drop(tmp);
        }
        reply.ok();
    }

    fn setattr(
        &mut self,
        _req: &Request,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<std::time::SystemTime>,
        fh: Option<u64>,
        _crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        if let Some(0) = size {
            // O_TRUNC: replace write buffer with a fresh empty file.
            if let Some(fh) = fh {
                let mut guard = self.open_files.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(of) = guard.get_mut(&fh) {
                    match NamedTempFile::new() {
                        Ok(fresh) => {
                            of.write_buf = Some(fresh);
                            of.dirty = true;
                            of.flushed = false; // truncate after flush must re-PUT
                        }
                        Err(e) => {
                            tracing::error!("tempfile truncate: {e}");
                            reply.error(libc::EIO);
                            return;
                        }
                    }
                }
            }
        }
        // Return current attrs (synthetic).
        let attr = {
            let inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
            match inodes.get(ino) {
                Some(e) => match &e.path {
                    InodePath::Object { .. } => {
                        if let Some(meta) = &e.cached_meta {
                            self.file_attr(ino, meta.size, meta.created, meta.modified)
                        } else {
                            self.file_attr(ino, 0, 0, 0)
                        }
                    }
                    _ => self.dir_attr(ino),
                },
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };
        reply.attr(&ATTR_TTL, &attr);
    }

    fn unlink(&mut self, _req: &Request, parent: u64, name: &std::ffi::OsStr, reply: ReplyEmpty) {
        if self.read_only {
            reply.error(libc::EROFS);
            return;
        }

        let name = name.to_string_lossy().into_owned();
        let (bucket, prefix) = match self.inode_to_bucket_prefix(parent) {
            Some(bp) => bp,
            None => {
                reply.error(libc::EPERM);
                return;
            }
        };
        let key = format!("{prefix}{name}");

        let client = self.client_clone();
        let bucket2 = bucket.clone();
        let key2 = key.clone();
        match self
            .rt
            .block_on(async move { client.delete(&bucket2, &key2).await })
        {
            Ok(()) => {
                let path = InodePath::Object { bucket, key };
                let mut inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
                // get_or_assign is idempotent; if the path was already assigned,
                // this returns the existing ino so we can evict it.
                let ino = inodes.get_or_assign(path);
                inodes.remove(ino);
                reply.ok();
            }
            Err(e) => reply.error(to_errno(&e)),
        }
    }

    fn mkdir(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &std::ffi::OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        if self.read_only {
            reply.error(libc::EROFS);
            return;
        }

        let name = name.to_string_lossy().into_owned();

        // Only allow bucket creation at the root in multi mode.
        let parent_path = {
            let inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
            inodes.get(parent).map(|e| e.path.clone())
        };

        match parent_path {
            Some(InodePath::Root) => {
                if matches!(self.mode, MountMode::Single(_)) {
                    reply.error(libc::EPERM);
                    return;
                }
                let bucket = name.clone();
                let client = self.client_clone();
                match self
                    .rt
                    .block_on(async move { client.create_bucket(&bucket).await })
                {
                    Ok(_) => {
                        let ino = self
                            .inodes
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .get_or_assign(InodePath::Bucket(name));
                        reply.entry(&ENTRY_TTL, &self.dir_attr(ino), 0);
                    }
                    Err(e) => reply.error(to_errno(&e)),
                }
            }
            _ => reply.error(libc::EPERM),
        }
    }

    fn rmdir(&mut self, _req: &Request, parent: u64, name: &std::ffi::OsStr, reply: ReplyEmpty) {
        if self.read_only {
            reply.error(libc::EROFS);
            return;
        }

        let name = name.to_string_lossy().into_owned();

        let parent_path = {
            let inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
            inodes.get(parent).map(|e| e.path.clone())
        };

        match parent_path {
            Some(InodePath::Root) => {
                if matches!(self.mode, MountMode::Single(_)) {
                    reply.error(libc::EPERM);
                    return;
                }
                let bucket = name.clone();
                let client = self.client_clone();
                match self
                    .rt
                    .block_on(async move { client.delete_bucket(&bucket).await })
                {
                    Ok(_) => {
                        let mut inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
                        let ino = inodes.get_or_assign(InodePath::Bucket(name));
                        inodes.remove(ino);
                        reply.ok();
                    }
                    Err(e) => reply.error(to_errno(&e)),
                }
            }
            _ => reply.error(libc::EPERM),
        }
    }

    fn rename(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &std::ffi::OsStr,
        newparent: u64,
        newname: &std::ffi::OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        if self.read_only {
            reply.error(libc::EROFS);
            return;
        }

        let name = name.to_string_lossy().into_owned();
        let newname = newname.to_string_lossy().into_owned();

        let src_bkt_pfx = match self.inode_to_bucket_prefix(parent) {
            Some(bp) => bp,
            None => {
                reply.error(libc::EPERM);
                return;
            }
        };
        let dst_bkt_pfx = match self.inode_to_bucket_prefix(newparent) {
            Some(bp) => bp,
            None => {
                reply.error(libc::EPERM);
                return;
            }
        };

        let src_bucket = src_bkt_pfx.0;
        let src_key = format!("{}{}", src_bkt_pfx.1, name);
        let dst_bucket = dst_bkt_pfx.0;
        let dst_key = format!("{}{}", dst_bkt_pfx.1, newname);

        if src_bucket != dst_bucket {
            // Cross-bucket rename is technically possible but complex; reject.
            reply.error(libc::EXDEV);
            return;
        }

        if src_key == dst_key {
            reply.ok();
            return;
        }

        let tmp = match tempfile::NamedTempFile::new() {
            Ok(f) => f,
            Err(e) => {
                tracing::error!("rename tempfile: {e}");
                reply.error(libc::EIO);
                return;
            }
        };
        let write_copy = match tmp.reopen() {
            Ok(f) => f,
            Err(e) => {
                tracing::error!("rename tempfile reopen: {e}");
                reply.error(libc::EIO);
                return;
            }
        };
        let client = self.client_clone();
        let result = self.rt.block_on(async move {
            // Stream source to tempfile (bounded by disk, not RAM).
            let mut writer = tokio::fs::File::from_std(write_copy);
            client
                .get_to_writer(&src_bucket, &src_key, &mut writer)
                .await?;
            let size = writer.metadata().await.map_err(ClientError::Io)?.len();
            // Reopen tempfile for reading and PUT to destination.
            let read_copy = tmp.reopen().map_err(ClientError::Io)?;
            let reader = tokio::fs::File::from_std(read_copy);
            client
                .put_from_reader(
                    &dst_bucket,
                    &dst_key,
                    reader,
                    Some(size),
                    &Default::default(),
                    None,
                )
                .await?;
            client.delete(&src_bucket, &src_key).await?;
            drop(tmp);
            Ok::<(), ClientError>(())
        });
        match result {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(to_errno(&e)),
        }
    }

    fn statfs(&mut self, _req: &Request, _ino: u64, reply: ReplyStatfs) {
        // Object store capacity is unknown; report 1 PiB total/free so tools
        // that check available space before writing don't refuse prematurely.
        const BSIZE: u32 = 4096;
        const BLOCKS: u64 = (1u64 << 50) / BSIZE as u64; // 1 PiB in 4KiB blocks
        reply.statfs(
            BLOCKS,       // total blocks
            BLOCKS,       // bfree
            BLOCKS,       // bavail
            u64::MAX / 2, // files (inodes)
            u64::MAX / 2, // ffree
            BSIZE,
            255, // namelen
            BSIZE,
        );
    }

    fn access(&mut self, _req: &Request, _ino: u64, _mask: i32, reply: ReplyEmpty) {
        reply.ok();
    }

    fn flush(&mut self, _req: &Request, _ino: u64, fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
        // Extract PUT parameters while holding the lock, then release before
        // blocking on the async PUT so the lock is not held across await points.
        let work = {
            let mut guard = self.open_files.lock().unwrap_or_else(|e| e.into_inner());
            let of = match guard.get_mut(&fh) {
                Some(of) => of,
                None => {
                    return reply.ok();
                }
            };
            if !of.dirty || of.flushed {
                return reply.ok();
            }
            let tmp = match of.write_buf.as_mut() {
                Some(t) => t,
                None => {
                    return reply.ok();
                }
            };
            let size = match tmp.as_file().metadata() {
                Ok(m) => m.len(),
                Err(e) => {
                    tracing::error!("flush stat: {e}");
                    reply.error(libc::EIO);
                    return;
                }
            };
            let read_copy = match tmp.reopen() {
                Ok(f) => f,
                Err(e) => {
                    tracing::error!("flush reopen: {e}");
                    reply.error(libc::EIO);
                    return;
                }
            };
            // Mark flushed before releasing the lock so a concurrent flush()
            // (from a dup'd fd) doesn't race in and issue a second PUT.
            of.flushed = true;
            (of.bucket.clone(), of.key.clone(), size, read_copy)
        };

        let (bucket, key, size, read_copy) = work;
        let client = self.client_clone();
        let b2 = bucket.clone();
        let k2 = key.clone();
        let result = self.rt.block_on(async move {
            let reader = tokio::fs::File::from_std(read_copy);
            client
                .put_from_reader(&b2, &k2, reader, Some(size), &Default::default(), None)
                .await
        });
        match result {
            Ok(_) => reply.ok(),
            Err(e) => {
                tracing::error!("flush PUT {bucket}/{key}: {e}");
                reply.error(to_errno(&e));
            }
        }
    }

    fn getxattr(
        &mut self,
        _req: &Request,
        ino: u64,
        name: &std::ffi::OsStr,
        size: u32,
        reply: ReplyXattr,
    ) {
        let xname = match name.to_str() {
            Some(n) => n.to_owned(),
            None => {
                reply.error(libc::ENODATA);
                return;
            }
        };

        let (bucket, key, cached) = {
            let inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
            let entry = match inodes.get(ino) {
                Some(e) => e,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };
            let (bucket, key) = match &entry.path {
                InodePath::Object { bucket, key } => (bucket.clone(), key.clone()),
                _ => {
                    reply.error(libc::ENODATA);
                    return;
                }
            };
            let cached = if entry.meta_fresh() {
                entry.cached_meta.clone()
            } else {
                None
            };
            (bucket, key, cached)
        };

        let meta = match cached {
            Some(m) => m,
            None => {
                let client = self.client_clone();
                let b = bucket.clone();
                let k = key.clone();
                match self.rt.block_on(async move { client.head(&b, &k).await }) {
                    Ok(head) => {
                        let m = CachedMeta {
                            size: head.size,
                            created: head.created,
                            modified: head.modified,
                            checksum_gxhash: head.checksum_gxhash,
                            labels: head.labels,
                        };
                        self.inodes
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .update_meta(ino, m.clone());
                        m
                    }
                    Err(e) => {
                        reply.error(to_errno(&e));
                        return;
                    }
                }
            }
        };

        let value = match xattr_get(&meta.checksum_gxhash, &meta.labels, &xname) {
            Some(v) => v,
            None => {
                reply.error(libc::ENODATA);
                return;
            }
        };

        if size == 0 {
            reply.size(value.len() as u32);
        } else if value.len() > size as usize {
            reply.error(libc::ERANGE);
        } else {
            reply.data(&value);
        }
    }

    fn listxattr(&mut self, _req: &Request, ino: u64, size: u32, reply: ReplyXattr) {
        let (bucket, key, cached) = {
            let inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
            let entry = match inodes.get(ino) {
                Some(e) => e,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };
            let (bucket, key) = match &entry.path {
                InodePath::Object { bucket, key } => (bucket.clone(), key.clone()),
                _ => {
                    // Dirs have no xattrs.
                    if size == 0 {
                        reply.size(0);
                    } else {
                        reply.data(&[]);
                    }
                    return;
                }
            };
            let cached = if entry.meta_fresh() {
                entry.cached_meta.clone()
            } else {
                None
            };
            (bucket, key, cached)
        };

        let meta = match cached {
            Some(m) => m,
            None => {
                let client = self.client_clone();
                let b = bucket.clone();
                let k = key.clone();
                match self.rt.block_on(async move { client.head(&b, &k).await }) {
                    Ok(head) => {
                        let m = CachedMeta {
                            size: head.size,
                            created: head.created,
                            modified: head.modified,
                            checksum_gxhash: head.checksum_gxhash,
                            labels: head.labels,
                        };
                        self.inodes
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .update_meta(ino, m.clone());
                        m
                    }
                    Err(e) => {
                        reply.error(to_errno(&e));
                        return;
                    }
                }
            }
        };

        let buf = xattr_list(&meta.labels);
        if size == 0 {
            reply.size(buf.len() as u32);
        } else if buf.len() > size as usize {
            reply.error(libc::ERANGE);
        } else {
            reply.data(&buf);
        }
    }
}

/// Build the null-terminated xattr name list for an object.
fn xattr_list(labels: &BTreeSet<(String, String)>) -> Vec<u8> {
    let mut buf: Vec<u8> = b"user.y2q.checksum.gxhash\0".to_vec();
    let mut seen = BTreeSet::<&str>::new();
    for (name, _) in labels {
        if seen.insert(name.as_str()) {
            buf.extend_from_slice(format!("user.y2q.label.{name}\0").as_bytes());
        }
    }
    buf
}

/// Return the byte value for xattr `name`, or `None` if not found.
fn xattr_get(
    checksum_gxhash: &str,
    labels: &BTreeSet<(String, String)>,
    name: &str,
) -> Option<Vec<u8>> {
    if name == "user.y2q.checksum.gxhash" {
        return Some(checksum_gxhash.as_bytes().to_vec());
    }
    if let Some(label_name) = name.strip_prefix("user.y2q.label.") {
        let vals: Vec<&str> = labels
            .iter()
            .filter(|(n, _)| n == label_name)
            .map(|(_, v)| v.as_str())
            .collect();
        if !vals.is_empty() {
            return Some(vals.join(",").into_bytes());
        }
    }
    None
}
