// SPDX-License-Identifier: Apache-2.0

//! A file system containing listening networking sockets.

use super::super::io::null::Null;
use super::super::io::urandom::Urandom;
use super::super::WasiResult;

use std::sync::Arc;

use anyhow::Context;
use futures::executor::block_on;
use wasi_common::file::{FdFlags, FileType};
use wasi_common::{Error, ErrorExt, WasiFile};
use wasmtime_vfs_dir::Directory;
use wasmtime_vfs_ledger::InodeId;
use wasmtime_vfs_memory::{Data, Inode, Link, Node};
use wiggle::async_trait;

// NOTE: Most of this is an awful hack to avoid reimplementing a non-extensible `Directory` type,
// but still use it with `WasiFile` implementations.
// Hopefully, a more suitable VFS API will emerge and this will be removed.

/// This wraps an arbitrary [WasiFile] and [FileType] tuple and
/// provides a [Node] implementation adaptor.
struct FileNode<T>(Link<(T, FileType)>);

impl<T: WasiFile + 'static> FileNode<T> {
    pub fn new(parent: Arc<dyn Node>, file: T, typ: FileType) -> Arc<Self> {
        let id = parent.id().device().create_inode();
        let inode = Inode {
            data: Data::from((file, typ)).into(),
            id,
        };
        Arc::new(Self(Link {
            parent: Arc::downgrade(&parent),
            inode: inode.into(),
        }))
    }
}

#[async_trait]
impl<T: Clone + WasiFile + 'static> Node for FileNode<T> {
    fn to_any(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync> {
        self
    }

    fn parent(&self) -> Option<Arc<dyn Node>> {
        self.0.parent.upgrade()
    }

    fn filetype(&self) -> FileType {
        block_on(self.0.inode.data.read()).content.1
    }

    fn id(&self) -> Arc<InodeId> {
        self.0.inode.id.clone()
    }

    async fn open_dir(self: Arc<Self>) -> WasiResult<Box<dyn wasi_common::WasiDir>> {
        Err(Error::not_dir())
    }

    async fn open_file(
        self: Arc<Self>,
        _path: &str,
        dir: bool,
        _read: bool,
        _write: bool,
        _flags: FdFlags,
    ) -> WasiResult<Box<dyn WasiFile>> {
        if dir {
            return Err(Error::not_dir());
        }
        Ok(Box::new(self.0.inode.data.write().await.content.0.clone()))
    }
}

pub async fn new(parent: Arc<dyn Node>) -> anyhow::Result<Arc<dyn Node>> {
    let dir = Directory::new(parent, None);
    dir.attach(
        "null",
        FileNode::new(dir.clone(), Null, Null.get_filetype().await?),
    )
    .await
    .context("failed to attach /dev/null")?;
    dir.attach(
        "urandom",
        FileNode::new(dir.clone(), Urandom, Urandom.get_filetype().await?),
    )
    .await
    .context("failed to attach /dev/urandom")?;
    Ok(dir)
}
