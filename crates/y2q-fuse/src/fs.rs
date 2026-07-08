use std::collections::{BTreeSet, HashMap};
use std::io::{Seek, SeekFrom, Write as IoWrite};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    AccessFlags, BsdFileFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags,
    Generation, INodeNo, LockOwner, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr,
    Request, WriteFlags,
};
use tempfile::NamedTempFile;
use y2q_client::{AclBody, BucketConfig, ClientError, ListOptions, Y2qClient};
use y2q_mount_core::dir::{ChildEntry, list_children};
use y2q_mount_core::path::{CachedMeta, InodePath, MountMode};

use crate::error::to_errno;
use crate::inode::{InodeTable, ROOT_INO};

const ATTR_TTL: Duration = Duration::from_secs(5);
const ENTRY_TTL: Duration = Duration::from_secs(5);

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
            ino: INodeNo(ino),
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
            ino: INodeNo(ino),
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
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &std::ffi::OsStr, reply: ReplyEntry) {
        let parent = parent.0;
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
                        reply.entry(&ENTRY_TTL, &self.dir_attr(ino), Generation(0));
                    }
                    Ok(false) => reply.error(Errno::ENOENT),
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
                                    cipher_size: head.cipher_size,
                                    cipher_sha256: head.cipher_sha256.clone(),
                                    kem_alg: head.kem_alg.clone(),
                                    aead_alg: head.aead_alg.clone(),
                                    envelope_version: head.envelope_version,
                                },
                            );
                            ino
                        };
                        reply.entry(
                            &ENTRY_TTL,
                            &self.file_attr(ino, head.size, head.created, head.modified),
                            Generation(0),
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
                        reply.entry(&ENTRY_TTL, &self.dir_attr(ino), Generation(0));
                    }
                    Ok((Err(e), _)) => reply.error(to_errno(&e)),
                    _ => reply.error(Errno::ENOENT),
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
                                    cipher_size: head.cipher_size,
                                    cipher_sha256: head.cipher_sha256.clone(),
                                    kem_alg: head.kem_alg.clone(),
                                    aead_alg: head.aead_alg.clone(),
                                    envelope_version: head.envelope_version,
                                },
                            );
                            ino
                        };
                        reply.entry(
                            &ENTRY_TTL,
                            &self.file_attr(ino, head.size, head.created, head.modified),
                            Generation(0),
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
                        reply.entry(&ENTRY_TTL, &self.dir_attr(ino), Generation(0));
                    }
                    Ok((Err(e), _)) => reply.error(to_errno(&e)),
                    _ => reply.error(Errno::ENOENT),
                }
            }

            _ => reply.error(Errno::ENOENT),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let ino = ino.0;
        let path = {
            let inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
            let e = match inodes.get(ino) {
                Some(e) => e,
                None => {
                    reply.error(Errno::ENOENT);
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
                                    cipher_size: head.cipher_size,
                                    cipher_sha256: head.cipher_sha256.clone(),
                                    kem_alg: head.kem_alg.clone(),
                                    aead_alg: head.aead_alg.clone(),
                                    envelope_version: head.envelope_version,
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
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let ino = ino.0;
        let path = {
            let inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
            match inodes.get(ino) {
                Some(e) => e.path.clone(),
                None => {
                    reply.error(Errno::ENOENT);
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

                for (i, (ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize)
                {
                    if reply.add(INodeNo(ino), (i + 1) as u64, kind, &name) {
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
                    // Bucket doesn't exist yet: treat as empty so the mount is
                    // usable before any objects are written.
                    Err(ClientError::NotFound { .. }) => vec![],
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
                                        cipher_size: meta.cipher_size,
                                        cipher_sha256: meta.cipher_sha256.clone(),
                                        kem_alg: meta.kem_alg.clone(),
                                        aead_alg: meta.aead_alg.clone(),
                                        envelope_version: meta.envelope_version,
                                    },
                                );
                                cino
                            };
                            // `meta` is boxed; dereference silently via field access above.
                            entries.push((cino, FileType::RegularFile, name));
                        }
                    }
                }

                for (i, (ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize)
                {
                    if reply.add(INodeNo(ino), (i + 1) as u64, kind, &name) {
                        break;
                    }
                }
                reply.ok();
            }

            InodePath::Object { .. } => {
                reply.error(Errno::ENOTDIR);
            }
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let ino = ino.0;
        let flags = flags.0;
        let path = {
            let inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
            match inodes.get(ino) {
                Some(e) => e.path.clone(),
                None => {
                    reply.error(Errno::ENOENT);
                    return;
                }
            }
        };

        let (bucket, key) = match path {
            InodePath::Object { bucket, key } => (bucket, key),
            _ => {
                reply.error(Errno::EISDIR);
                return;
            }
        };

        let write_requested = flags & libc::O_WRONLY != 0 || flags & libc::O_RDWR != 0;
        if write_requested && self.read_only {
            reply.error(Errno::EROFS);
            return;
        }

        let (write_buf, dirty) = if write_requested {
            let trunc = flags & libc::O_TRUNC != 0;
            let mut tmp = match NamedTempFile::new() {
                Ok(f) => f,
                Err(e) => {
                    tracing::error!("tempfile: {e}");
                    reply.error(Errno::EIO);
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
                        reply.error(Errno::EIO);
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
                    reply.error(Errno::EIO);
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
        reply.opened(FileHandle(fh), FopenFlags::empty());
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let ino = ino.0;
        let fh = fh.0;
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
                            reply.error(Errno::EBADF);
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

        let start = offset;
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
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &std::ffi::OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let parent = parent.0;
        if self.read_only {
            reply.error(Errno::EROFS);
            return;
        }

        let name = name.to_string_lossy().into_owned();

        let (bucket, prefix) = match self.inode_to_bucket_prefix(parent) {
            Some(bp) => bp,
            None => {
                // Parent is root in multi mode — creating files at root is not valid.
                reply.error(Errno::EPERM);
                return;
            }
        };

        let key = format!("{prefix}{name}");
        let buf = match NamedTempFile::new() {
            Ok(f) => f,
            Err(e) => {
                tracing::error!("tempfile: {e}");
                reply.error(Errno::EIO);
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
        reply.created(
            &ENTRY_TTL,
            &attr,
            Generation(0),
            FileHandle(fh),
            FopenFlags::empty(),
        );
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let fh = fh.0;
        if self.read_only {
            reply.error(Errno::EROFS);
            return;
        }

        let mut guard = self.open_files.lock().unwrap_or_else(|e| e.into_inner());
        let of = match guard.get_mut(&fh) {
            Some(of) => of,
            None => {
                reply.error(Errno::EBADF);
                return;
            }
        };
        let buf = match of.write_buf.as_mut() {
            Some(b) => b,
            None => {
                reply.error(Errno::EBADF);
                return;
            }
        };

        if let Err(e) = buf.seek(SeekFrom::Start(offset)) {
            tracing::error!("seek: {e}");
            reply.error(Errno::EIO);
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
                reply.error(Errno::EIO);
            }
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let fh = fh.0;
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
        &self,
        _req: &Request,
        ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<std::time::SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let ino = ino.0;
        if let Some(0) = size {
            // O_TRUNC: replace write buffer with a fresh empty file.
            if let Some(fh) = fh {
                let fh = fh.0;
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
                            reply.error(Errno::EIO);
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
                    reply.error(Errno::ENOENT);
                    return;
                }
            }
        };
        reply.attr(&ATTR_TTL, &attr);
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &std::ffi::OsStr, reply: ReplyEmpty) {
        let parent = parent.0;
        if self.read_only {
            reply.error(Errno::EROFS);
            return;
        }

        let name = name.to_string_lossy().into_owned();
        let (bucket, prefix) = match self.inode_to_bucket_prefix(parent) {
            Some(bp) => bp,
            None => {
                reply.error(Errno::EPERM);
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
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &std::ffi::OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let parent = parent.0;
        if self.read_only {
            reply.error(Errno::EROFS);
            return;
        }

        let name = name.to_string_lossy().into_owned();

        let parent_path = {
            let inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
            inodes.get(parent).map(|e| e.path.clone())
        };

        // In single-bucket mode the root IS the bucket; remap so virtual-dir
        // creation falls through to the Bucket arm below.
        let parent_path =
            if let (Some(InodePath::Root), MountMode::Single(b)) = (&parent_path, &self.mode) {
                Some(InodePath::Bucket(b.clone()))
            } else {
                parent_path
            };

        match parent_path {
            Some(InodePath::Root) => {
                // Multi mode: create a real bucket on the server.
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
                        reply.entry(&ENTRY_TTL, &self.dir_attr(ino), Generation(0));
                    }
                    Err(e) => reply.error(to_errno(&e)),
                }
            }
            Some(InodePath::Bucket(bucket)) => {
                // Virtual dir: exists by convention (key prefix). No server call.
                let ino = self
                    .inodes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get_or_assign(InodePath::VirtualDir {
                        bucket,
                        prefix: name,
                    });
                reply.entry(&ENTRY_TTL, &self.dir_attr(ino), Generation(0));
            }
            Some(InodePath::VirtualDir { bucket, prefix }) => {
                let child_prefix = format!("{prefix}/{name}");
                let ino = self
                    .inodes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get_or_assign(InodePath::VirtualDir {
                        bucket,
                        prefix: child_prefix,
                    });
                reply.entry(&ENTRY_TTL, &self.dir_attr(ino), Generation(0));
            }
            _ => reply.error(Errno::EPERM),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &std::ffi::OsStr, reply: ReplyEmpty) {
        let parent = parent.0;
        if self.read_only {
            reply.error(Errno::EROFS);
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
                    reply.error(Errno::EPERM);
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
            _ => reply.error(Errno::EPERM),
        }
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &std::ffi::OsStr,
        newparent: INodeNo,
        newname: &std::ffi::OsStr,
        _flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        let parent = parent.0;
        let newparent = newparent.0;
        if self.read_only {
            reply.error(Errno::EROFS);
            return;
        }

        let name = name.to_string_lossy().into_owned();
        let newname = newname.to_string_lossy().into_owned();

        let src_bkt_pfx = match self.inode_to_bucket_prefix(parent) {
            Some(bp) => bp,
            None => {
                reply.error(Errno::EPERM);
                return;
            }
        };
        let dst_bkt_pfx = match self.inode_to_bucket_prefix(newparent) {
            Some(bp) => bp,
            None => {
                reply.error(Errno::EPERM);
                return;
            }
        };

        let src_bucket = src_bkt_pfx.0;
        let src_key = format!("{}{}", src_bkt_pfx.1, name);
        let dst_bucket = dst_bkt_pfx.0;
        let dst_key = format!("{}{}", dst_bkt_pfx.1, newname);

        if src_bucket != dst_bucket {
            // Cross-bucket rename is technically possible but complex; reject.
            reply.error(Errno::EXDEV);
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
                reply.error(Errno::EIO);
                return;
            }
        };
        let write_copy = match tmp.reopen() {
            Ok(f) => f,
            Err(e) => {
                tracing::error!("rename tempfile reopen: {e}");
                reply.error(Errno::EIO);
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

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
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

    fn access(&self, _req: &Request, _ino: INodeNo, _mask: AccessFlags, reply: ReplyEmpty) {
        reply.ok();
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        let fh = fh.0;
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
                    reply.error(Errno::EIO);
                    return;
                }
            };
            let read_copy = match tmp.reopen() {
                Ok(f) => f,
                Err(e) => {
                    tracing::error!("flush reopen: {e}");
                    reply.error(Errno::EIO);
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

    fn setxattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        name: &std::ffi::OsStr,
        value: &[u8],
        _flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        let ino = ino.0;
        if self.read_only {
            reply.error(Errno::EROFS);
            return;
        }

        let xname = match name.to_str() {
            Some(n) => n.to_owned(),
            None => {
                reply.error(Errno::ENOTSUP);
                return;
            }
        };

        let inode_path = {
            let inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
            inodes.get(ino).map(|e| e.path.clone())
        };

        match inode_path {
            Some(InodePath::Object { bucket, key }) => {
                // Read-only object xattrs.
                const RO: &[&str] = &[
                    "user.y2q.checksum.gxhash",
                    "user.y2q.size",
                    "user.y2q.created",
                    "user.y2q.modified",
                    "user.y2q.cipher.size",
                    "user.y2q.cipher.sha256",
                    "user.y2q.kem.alg",
                    "user.y2q.aead.alg",
                    "user.y2q.envelope.version",
                ];
                if RO.contains(&xname.as_str()) {
                    reply.error(Errno::EPERM);
                    return;
                }

                let label_name = match xname.strip_prefix("user.y2q.label.") {
                    Some(n) if !n.is_empty() => n.to_owned(),
                    _ => {
                        reply.error(Errno::ENOTSUP);
                        return;
                    }
                };

                let label_value = match std::str::from_utf8(value) {
                    Ok(v) => v.to_owned(),
                    Err(_) => {
                        reply.error(Errno::EINVAL);
                        return;
                    }
                };

                // Fetch current labels so we can do a full replace (removes
                // any existing values for this label name, then adds the new one).
                let (cached_meta, fresh) = {
                    let inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
                    match inodes.get(ino) {
                        Some(e) => (e.cached_meta.clone(), e.meta_fresh()),
                        None => (None, false),
                    }
                };
                let current_labels: BTreeSet<(String, String)> = if fresh {
                    cached_meta.map(|m| m.labels).unwrap_or_default()
                } else {
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
                                labels: head.labels.clone(),
                                cipher_size: head.cipher_size,
                                cipher_sha256: head.cipher_sha256,
                                kem_alg: head.kem_alg,
                                aead_alg: head.aead_alg,
                                envelope_version: head.envelope_version,
                            };
                            self.inodes
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .update_meta(ino, m);
                            head.labels
                        }
                        Err(e) => {
                            reply.error(to_errno(&e));
                            return;
                        }
                    }
                };

                // Replace this label name's values with the single new value.
                let mut new_labels: BTreeSet<(String, String)> = current_labels
                    .into_iter()
                    .filter(|(n, _)| n != &label_name)
                    .collect();
                new_labels.insert((label_name, label_value));

                let client = self.client_clone();
                let b = bucket.clone();
                let k = key.clone();
                match self.rt.block_on(async move {
                    client.set_labels(&b, &k, "replace", &new_labels).await
                }) {
                    Ok(_) => {
                        self.inodes
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .invalidate_meta(ino);
                        reply.ok();
                    }
                    Err(e) => reply.error(to_errno(&e)),
                }
            }

            Some(InodePath::Bucket(_)) | Some(InodePath::Root)
                if matches!(&self.mode, MountMode::Single(_))
                    || matches!(&inode_path, Some(InodePath::Bucket(_))) =>
            {
                let bucket = match &inode_path {
                    Some(InodePath::Bucket(b)) => b.clone(),
                    _ => match &self.mode {
                        MountMode::Single(b) => b.clone(),
                        _ => {
                            reply.error(Errno::ENOTSUP);
                            return;
                        }
                    },
                };

                let str_val = match std::str::from_utf8(value) {
                    Ok(v) => v.to_owned(),
                    Err(_) => {
                        reply.error(Errno::EINVAL);
                        return;
                    }
                };

                match xname.as_str() {
                    "user.y2q.quota.bytes" => {
                        let quota: u64 = match str_val.trim().parse() {
                            Ok(n) => n,
                            Err(_) => {
                                reply.error(Errno::EINVAL);
                                return;
                            }
                        };
                        let client = self.client_clone();
                        let b = bucket.clone();
                        match self.rt.block_on(async move {
                            let mut cfg = client.get_bucket_config(&b).await?;
                            cfg.quota_bytes = Some(quota);
                            client.set_bucket_config(&b, &cfg).await
                        }) {
                            Ok(_) => reply.ok(),
                            Err(e) => reply.error(to_errno(&e)),
                        }
                    }
                    "user.y2q.default.sse" => {
                        let client = self.client_clone();
                        let b = bucket.clone();
                        match self.rt.block_on(async move {
                            let mut cfg = client.get_bucket_config(&b).await?;
                            cfg.default_sse = if str_val.is_empty() {
                                None
                            } else {
                                Some(str_val)
                            };
                            client.set_bucket_config(&b, &cfg).await
                        }) {
                            Ok(_) => reply.ok(),
                            Err(e) => reply.error(to_errno(&e)),
                        }
                    }
                    _ => reply.error(Errno::ENOTSUP),
                }
            }

            _ => reply.error(Errno::ENOTSUP),
        }
    }

    fn removexattr(&self, _req: &Request, ino: INodeNo, name: &std::ffi::OsStr, reply: ReplyEmpty) {
        let ino = ino.0;
        if self.read_only {
            reply.error(Errno::EROFS);
            return;
        }

        let xname = match name.to_str() {
            Some(n) => n.to_owned(),
            None => {
                reply.error(Errno::ENOTSUP);
                return;
            }
        };

        let (bucket, key, cached_meta, fresh) = {
            let inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
            match inodes.get(ino).map(|e| &e.path) {
                Some(InodePath::Object { bucket, key }) => {
                    let entry = inodes.get(ino).unwrap();
                    (
                        bucket.clone(),
                        key.clone(),
                        entry.cached_meta.clone(),
                        entry.meta_fresh(),
                    )
                }
                Some(InodePath::Bucket(b)) => {
                    // Bucket config xattrs: removing sets the field to None.
                    let bucket = b.clone();
                    drop(inodes);
                    match xname.as_str() {
                        "user.y2q.quota.bytes" => {
                            let client = self.client_clone();
                            let bk = bucket.clone();
                            match self.rt.block_on(async move {
                                let mut cfg = client.get_bucket_config(&bk).await?;
                                cfg.quota_bytes = None;
                                client.set_bucket_config(&bk, &cfg).await
                            }) {
                                Ok(_) => reply.ok(),
                                Err(e) => reply.error(to_errno(&e)),
                            }
                        }
                        "user.y2q.default.sse" => {
                            let client = self.client_clone();
                            let bk = bucket.clone();
                            match self.rt.block_on(async move {
                                let mut cfg = client.get_bucket_config(&bk).await?;
                                cfg.default_sse = None;
                                client.set_bucket_config(&bk, &cfg).await
                            }) {
                                Ok(_) => reply.ok(),
                                Err(e) => reply.error(to_errno(&e)),
                            }
                        }
                        _ => reply.error(Errno::NO_XATTR),
                    }
                    return;
                }
                _ => {
                    reply.error(Errno::ENOTSUP);
                    return;
                }
            }
        };

        let label_name = match xname.strip_prefix("user.y2q.label.") {
            Some(n) if !n.is_empty() => n.to_owned(),
            _ => {
                reply.error(Errno::ENOTSUP);
                return;
            }
        };

        let current_labels: BTreeSet<(String, String)> = if fresh {
            cached_meta.map(|m| m.labels).unwrap_or_default()
        } else {
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
                        labels: head.labels.clone(),
                        cipher_size: head.cipher_size,
                        cipher_sha256: head.cipher_sha256,
                        kem_alg: head.kem_alg,
                        aead_alg: head.aead_alg,
                        envelope_version: head.envelope_version,
                    };
                    self.inodes
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .update_meta(ino, m);
                    head.labels
                }
                Err(e) => {
                    reply.error(to_errno(&e));
                    return;
                }
            }
        };

        let to_remove: BTreeSet<(String, String)> = current_labels
            .into_iter()
            .filter(|(n, _)| n == &label_name)
            .collect();

        if to_remove.is_empty() {
            reply.error(Errno::NO_XATTR);
            return;
        }

        let client = self.client_clone();
        let b = bucket.clone();
        let k = key.clone();
        match self
            .rt
            .block_on(async move { client.set_labels(&b, &k, "remove", &to_remove).await })
        {
            Ok(_) => {
                self.inodes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .invalidate_meta(ino);
                reply.ok();
            }
            Err(e) => reply.error(to_errno(&e)),
        }
    }

    fn getxattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        name: &std::ffi::OsStr,
        size: u32,
        reply: ReplyXattr,
    ) {
        let ino = ino.0;
        let xname = match name.to_str() {
            Some(n) => n.to_owned(),
            None => {
                reply.error(Errno::NO_XATTR);
                return;
            }
        };

        let (path, cached) = {
            let inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
            let entry = match inodes.get(ino) {
                Some(e) => e,
                None => {
                    reply.error(Errno::ENOENT);
                    return;
                }
            };
            let cached = if entry.meta_fresh() {
                entry.cached_meta.clone()
            } else {
                None
            };
            (entry.path.clone(), cached)
        };

        match path {
            InodePath::Object { bucket, key } => {
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
                                    cipher_size: head.cipher_size,
                                    cipher_sha256: head.cipher_sha256,
                                    kem_alg: head.kem_alg,
                                    aead_alg: head.aead_alg,
                                    envelope_version: head.envelope_version,
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
                let value = match xattr_get(&meta, &xname) {
                    Some(v) => v,
                    None => {
                        reply.error(Errno::NO_XATTR);
                        return;
                    }
                };
                xattr_reply(reply, size, &value);
            }
            InodePath::Bucket(b) => {
                self.reply_bucket_xattr(ino, &b, &xname, size, reply);
            }
            InodePath::Root => {
                if let MountMode::Single(b) = self.mode.clone() {
                    self.reply_bucket_xattr(ino, &b, &xname, size, reply);
                } else {
                    reply.error(Errno::NO_XATTR);
                }
            }
            _ => reply.error(Errno::NO_XATTR),
        }
    }

    fn listxattr(&self, _req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        let ino = ino.0;
        let path = {
            let inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
            match inodes.get(ino) {
                Some(e) => e.path.clone(),
                None => {
                    reply.error(Errno::ENOENT);
                    return;
                }
            }
        };

        match path {
            InodePath::Object { bucket, key } => {
                let cached = {
                    let inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
                    inodes
                        .get(ino)
                        .filter(|e| e.meta_fresh())
                        .and_then(|e| e.cached_meta.clone())
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
                                    cipher_size: head.cipher_size,
                                    cipher_sha256: head.cipher_sha256,
                                    kem_alg: head.kem_alg,
                                    aead_alg: head.aead_alg,
                                    envelope_version: head.envelope_version,
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
                let buf = xattr_list(&meta);
                if size == 0 {
                    reply.size(buf.len() as u32);
                } else if buf.len() > size as usize {
                    reply.error(Errno::ERANGE);
                } else {
                    reply.data(&buf);
                }
            }
            InodePath::Bucket(b) => {
                self.reply_bucket_xattr_list(&b, size, reply);
            }
            InodePath::Root => {
                if let MountMode::Single(b) = self.mode.clone() {
                    self.reply_bucket_xattr_list(&b, size, reply);
                } else {
                    if size == 0 {
                        reply.size(0);
                    } else {
                        reply.data(&[]);
                    }
                }
            }
            _ => {
                if size == 0 {
                    reply.size(0);
                } else {
                    reply.data(&[]);
                }
            }
        }
    }
}

impl Y2qFuse {
    fn reply_bucket_xattr(
        &self,
        _ino: u64,
        bucket: &str,
        xname: &str,
        size: u32,
        reply: ReplyXattr,
    ) {
        let client = self.client_clone();
        let b = bucket.to_owned();
        match self.rt.block_on(async move {
            let cfg = client.get_bucket_config(&b).await?;
            let acl = client.get_bucket_acl(&b).await?;
            Ok::<_, ClientError>((cfg, acl))
        }) {
            Ok((cfg, acl)) => match bucket_xattr_get(&cfg, &acl, xname) {
                Some(v) => xattr_reply(reply, size, &v),
                None => reply.error(Errno::NO_XATTR),
            },
            Err(e) => reply.error(to_errno(&e)),
        }
    }

    fn reply_bucket_xattr_list(&self, bucket: &str, size: u32, reply: ReplyXattr) {
        let client = self.client_clone();
        let b = bucket.to_owned();
        match self.rt.block_on(async move {
            let cfg = client.get_bucket_config(&b).await?;
            let acl = client.get_bucket_acl(&b).await?;
            Ok::<_, ClientError>((cfg, acl))
        }) {
            Ok((cfg, acl)) => {
                let buf = bucket_xattr_list(&cfg, &acl);
                if size == 0 {
                    reply.size(buf.len() as u32);
                } else if buf.len() > size as usize {
                    reply.error(Errno::ERANGE);
                } else {
                    reply.data(&buf);
                }
            }
            Err(e) => reply.error(to_errno(&e)),
        }
    }
}

fn xattr_reply(reply: ReplyXattr, size: u32, value: &[u8]) {
    if size == 0 {
        reply.size(value.len() as u32);
    } else if value.len() > size as usize {
        reply.error(Errno::ERANGE);
    } else {
        reply.data(value);
    }
}

/// Build the null-terminated xattr name list for an object.
fn xattr_list(meta: &CachedMeta) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    for name in &[
        "user.y2q.checksum.gxhash\0",
        "user.y2q.size\0",
        "user.y2q.created\0",
        "user.y2q.modified\0",
    ] {
        buf.extend_from_slice(name.as_bytes());
    }
    if meta.cipher_size.is_some() {
        buf.extend_from_slice(b"user.y2q.cipher.size\0");
    }
    if meta.cipher_sha256.is_some() {
        buf.extend_from_slice(b"user.y2q.cipher.sha256\0");
    }
    if meta.kem_alg.is_some() {
        buf.extend_from_slice(b"user.y2q.kem.alg\0");
    }
    if meta.aead_alg.is_some() {
        buf.extend_from_slice(b"user.y2q.aead.alg\0");
    }
    if meta.envelope_version.is_some() {
        buf.extend_from_slice(b"user.y2q.envelope.version\0");
    }
    let mut seen = BTreeSet::<&str>::new();
    for (name, _) in &meta.labels {
        if seen.insert(name.as_str()) {
            buf.extend_from_slice(format!("user.y2q.label.{name}\0").as_bytes());
        }
    }
    buf
}

/// Return the byte value for object xattr `name`, or `None` if not found.
fn xattr_get(meta: &CachedMeta, name: &str) -> Option<Vec<u8>> {
    match name {
        "user.y2q.checksum.gxhash" => Some(meta.checksum_gxhash.as_bytes().to_vec()),
        "user.y2q.size" => Some(meta.size.to_string().into_bytes()),
        "user.y2q.created" => Some(meta.created.to_string().into_bytes()),
        "user.y2q.modified" => Some(meta.modified.to_string().into_bytes()),
        "user.y2q.cipher.size" => meta.cipher_size.map(|v| v.to_string().into_bytes()),
        "user.y2q.cipher.sha256" => meta.cipher_sha256.as_deref().map(|v| v.as_bytes().to_vec()),
        "user.y2q.kem.alg" => meta.kem_alg.as_deref().map(|v| v.as_bytes().to_vec()),
        "user.y2q.aead.alg" => meta.aead_alg.as_deref().map(|v| v.as_bytes().to_vec()),
        "user.y2q.envelope.version" => meta.envelope_version.map(|v| v.to_string().into_bytes()),
        _ => {
            if let Some(label_name) = name.strip_prefix("user.y2q.label.") {
                let vals: Vec<&str> = meta
                    .labels
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
    }
}

/// Build the null-terminated xattr name list for a bucket.
fn bucket_xattr_list(cfg: &BucketConfig, acl: &AclBody) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    if cfg.quota_bytes.is_some() {
        buf.extend_from_slice(b"user.y2q.quota.bytes\0");
    }
    if cfg.default_sse.is_some() {
        buf.extend_from_slice(b"user.y2q.default.sse\0");
    }
    if cfg.cors_allow_origin.is_some() {
        buf.extend_from_slice(b"user.y2q.cors.allow_origin\0");
    }
    if acl.owner.is_some() {
        buf.extend_from_slice(b"user.y2q.acl.owner\0");
    }
    for username in acl.grants.keys() {
        buf.extend_from_slice(format!("user.y2q.acl.grant.{username}\0").as_bytes());
    }
    buf
}

/// Return the byte value for bucket xattr `name`, or `None` if not found.
fn bucket_xattr_get(cfg: &BucketConfig, acl: &AclBody, name: &str) -> Option<Vec<u8>> {
    match name {
        "user.y2q.quota.bytes" => cfg.quota_bytes.map(|v| v.to_string().into_bytes()),
        "user.y2q.default.sse" => cfg.default_sse.as_deref().map(|v| v.as_bytes().to_vec()),
        "user.y2q.cors.allow_origin" => cfg
            .cors_allow_origin
            .as_deref()
            .map(|v| v.as_bytes().to_vec()),
        "user.y2q.acl.owner" => acl.owner.as_deref().map(|v| v.as_bytes().to_vec()),
        _ => {
            if let Some(username) = name.strip_prefix("user.y2q.acl.grant.") {
                return acl.grants.get(username).map(|v| v.as_bytes().to_vec());
            }
            None
        }
    }
}
