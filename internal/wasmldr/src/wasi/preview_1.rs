// SPDX-License-Identifier: Apache-2.0

use super::Ctx;

use wasi_common::snapshots::preview_1::types;
use wasi_common::snapshots::preview_1::wasi_snapshot_preview1::WasiSnapshotPreview1;
use wasi_common::Error;
use wiggle::{GuestPtr, Trap};

impl types::UserErrorConversion for Ctx {
    fn errno_from_error(&mut self, e: Error) -> Result<types::Errno, Trap> {
        self.inner.errno_from_error(e)
    }
}

#[wiggle::async_trait]
impl WasiSnapshotPreview1 for Ctx {
    async fn args_get<'a>(
        &mut self,
        argv: &GuestPtr<'a, GuestPtr<'a, u8>>,
        argv_buf: &GuestPtr<'a, u8>,
    ) -> Result<(), Error> {
        WasiSnapshotPreview1::args_get(&mut self.inner, argv, argv_buf).await
    }

    async fn args_sizes_get(&mut self) -> Result<(types::Size, types::Size), Error> {
        WasiSnapshotPreview1::args_sizes_get(&mut self.inner).await
    }

    async fn environ_get<'a>(
        &mut self,
        environ: &GuestPtr<'a, GuestPtr<'a, u8>>,
        environ_buf: &GuestPtr<'a, u8>,
    ) -> Result<(), Error> {
        WasiSnapshotPreview1::environ_get(&mut self.inner, environ, environ_buf).await
    }

    async fn environ_sizes_get(&mut self) -> Result<(types::Size, types::Size), Error> {
        WasiSnapshotPreview1::environ_sizes_get(&mut self.inner).await
    }

    async fn clock_res_get(&mut self, id: types::Clockid) -> Result<types::Timestamp, Error> {
        WasiSnapshotPreview1::clock_res_get(&mut self.inner, id).await
    }

    async fn clock_time_get(
        &mut self,
        id: types::Clockid,
        precision: types::Timestamp,
    ) -> Result<types::Timestamp, Error> {
        WasiSnapshotPreview1::clock_time_get(&mut self.inner, id, precision).await
    }

    async fn fd_advise(
        &mut self,
        fd: types::Fd,
        offset: types::Filesize,
        len: types::Filesize,
        advice: types::Advice,
    ) -> Result<(), Error> {
        WasiSnapshotPreview1::fd_advise(&mut self.inner, fd, offset, len, advice).await
    }

    async fn fd_allocate(
        &mut self,
        fd: types::Fd,
        offset: types::Filesize,
        len: types::Filesize,
    ) -> Result<(), Error> {
        WasiSnapshotPreview1::fd_allocate(&mut self.inner, fd, offset, len).await
    }

    async fn fd_close(&mut self, fd: types::Fd) -> Result<(), Error> {
        WasiSnapshotPreview1::fd_close(&mut self.inner, fd).await
    }

    async fn fd_datasync(&mut self, fd: types::Fd) -> Result<(), Error> {
        WasiSnapshotPreview1::fd_datasync(&mut self.inner, fd).await
    }

    async fn fd_fdstat_get(&mut self, fd: types::Fd) -> Result<types::Fdstat, Error> {
        WasiSnapshotPreview1::fd_fdstat_get(&mut self.inner, fd).await
    }

    async fn fd_fdstat_set_flags(
        &mut self,
        fd: types::Fd,
        flags: types::Fdflags,
    ) -> Result<(), Error> {
        WasiSnapshotPreview1::fd_fdstat_set_flags(&mut self.inner, fd, flags).await
    }

    async fn fd_fdstat_set_rights(
        &mut self,
        fd: types::Fd,
        fs_rights_base: types::Rights,
        fs_rights_inheriting: types::Rights,
    ) -> Result<(), Error> {
        WasiSnapshotPreview1::fd_fdstat_set_rights(
            &mut self.inner,
            fd,
            fs_rights_base,
            fs_rights_inheriting,
        )
        .await
    }

    async fn fd_filestat_get(&mut self, fd: types::Fd) -> Result<types::Filestat, Error> {
        WasiSnapshotPreview1::fd_filestat_get(&mut self.inner, fd).await
    }

    async fn fd_filestat_set_size(
        &mut self,
        fd: types::Fd,
        size: types::Filesize,
    ) -> Result<(), Error> {
        WasiSnapshotPreview1::fd_filestat_set_size(&mut self.inner, fd, size).await
    }

    async fn fd_filestat_set_times(
        &mut self,
        fd: types::Fd,
        atim: types::Timestamp,
        mtim: types::Timestamp,
        fst_flags: types::Fstflags,
    ) -> Result<(), Error> {
        WasiSnapshotPreview1::fd_filestat_set_times(&mut self.inner, fd, atim, mtim, fst_flags)
            .await
    }

    async fn fd_read<'a>(
        &mut self,
        fd: types::Fd,
        iovs: &types::IovecArray<'a>,
    ) -> Result<types::Size, Error> {
        WasiSnapshotPreview1::fd_read(&mut self.inner, fd, iovs).await
    }

    async fn fd_pread<'a>(
        &mut self,
        fd: types::Fd,
        iovs: &types::IovecArray<'a>,
        offset: types::Filesize,
    ) -> Result<types::Size, Error> {
        WasiSnapshotPreview1::fd_pread(&mut self.inner, fd, iovs, offset).await
    }

    async fn fd_write<'a>(
        &mut self,
        fd: types::Fd,
        ciovs: &types::CiovecArray<'a>,
    ) -> Result<types::Size, Error> {
        WasiSnapshotPreview1::fd_write(&mut self.inner, fd, ciovs).await
    }

    async fn fd_pwrite<'a>(
        &mut self,
        fd: types::Fd,
        ciovs: &types::CiovecArray<'a>,
        offset: types::Filesize,
    ) -> Result<types::Size, Error> {
        WasiSnapshotPreview1::fd_pwrite(&mut self.inner, fd, ciovs, offset).await
    }

    async fn fd_prestat_get(&mut self, fd: types::Fd) -> Result<types::Prestat, Error> {
        WasiSnapshotPreview1::fd_prestat_get(&mut self.inner, fd).await
    }

    async fn fd_prestat_dir_name<'a>(
        &mut self,
        fd: types::Fd,
        path: &GuestPtr<'a, u8>,
        path_max_len: types::Size,
    ) -> Result<(), Error> {
        WasiSnapshotPreview1::fd_prestat_dir_name(&mut self.inner, fd, path, path_max_len).await
    }

    async fn fd_renumber(&mut self, from: types::Fd, to: types::Fd) -> Result<(), Error> {
        WasiSnapshotPreview1::fd_renumber(&mut self.inner, from, to).await
    }

    async fn fd_seek(
        &mut self,
        fd: types::Fd,
        offset: types::Filedelta,
        whence: types::Whence,
    ) -> Result<types::Filesize, Error> {
        WasiSnapshotPreview1::fd_seek(&mut self.inner, fd, offset, whence).await
    }

    async fn fd_sync(&mut self, fd: types::Fd) -> Result<(), Error> {
        WasiSnapshotPreview1::fd_sync(&mut self.inner, fd).await
    }

    async fn fd_tell(&mut self, fd: types::Fd) -> Result<types::Filesize, Error> {
        WasiSnapshotPreview1::fd_tell(&mut self.inner, fd).await
    }

    async fn fd_readdir<'a>(
        &mut self,
        fd: types::Fd,
        buf: &GuestPtr<'a, u8>,
        buf_len: types::Size,
        cookie: types::Dircookie,
    ) -> Result<types::Size, Error> {
        WasiSnapshotPreview1::fd_readdir(&mut self.inner, fd, buf, buf_len, cookie).await
    }

    async fn path_create_directory<'a>(
        &mut self,
        dirfd: types::Fd,
        path: &GuestPtr<'a, str>,
    ) -> Result<(), Error> {
        WasiSnapshotPreview1::path_create_directory(&mut self.inner, dirfd, path).await
    }

    async fn path_filestat_get<'a>(
        &mut self,
        dirfd: types::Fd,
        flags: types::Lookupflags,
        path: &GuestPtr<'a, str>,
    ) -> Result<types::Filestat, Error> {
        WasiSnapshotPreview1::path_filestat_get(&mut self.inner, dirfd, flags, path).await
    }

    async fn path_filestat_set_times<'a>(
        &mut self,
        dirfd: types::Fd,
        flags: types::Lookupflags,
        path: &GuestPtr<'a, str>,
        atim: types::Timestamp,
        mtim: types::Timestamp,
        fst_flags: types::Fstflags,
    ) -> Result<(), Error> {
        WasiSnapshotPreview1::path_filestat_set_times(
            &mut self.inner,
            dirfd,
            flags,
            path,
            atim,
            mtim,
            fst_flags,
        )
        .await
    }

    async fn path_link<'a>(
        &mut self,
        src_fd: types::Fd,
        src_flags: types::Lookupflags,
        src_path: &GuestPtr<'a, str>,
        target_fd: types::Fd,
        target_path: &GuestPtr<'a, str>,
    ) -> Result<(), Error> {
        WasiSnapshotPreview1::path_link(
            &mut self.inner,
            src_fd,
            src_flags,
            src_path,
            target_fd,
            target_path,
        )
        .await
    }

    async fn path_open<'a>(
        &mut self,
        dirfd: types::Fd,
        dirflags: types::Lookupflags,
        path: &GuestPtr<'a, str>,
        oflags: types::Oflags,
        fs_rights_base: types::Rights,
        fs_rights_inheriting: types::Rights,
        fdflags: types::Fdflags,
    ) -> Result<types::Fd, Error> {
        WasiSnapshotPreview1::path_open(
            &mut self.inner,
            dirfd,
            dirflags,
            path,
            oflags,
            fs_rights_base,
            fs_rights_inheriting,
            fdflags,
        )
        .await
    }

    async fn path_readlink<'a>(
        &mut self,
        dirfd: types::Fd,
        path: &GuestPtr<'a, str>,
        buf: &GuestPtr<'a, u8>,
        buf_len: types::Size,
    ) -> Result<types::Size, Error> {
        WasiSnapshotPreview1::path_readlink(&mut self.inner, dirfd, path, buf, buf_len).await
    }

    async fn path_remove_directory<'a>(
        &mut self,
        dirfd: types::Fd,
        path: &GuestPtr<'a, str>,
    ) -> Result<(), Error> {
        WasiSnapshotPreview1::path_remove_directory(&mut self.inner, dirfd, path).await
    }

    async fn path_rename<'a>(
        &mut self,
        src_fd: types::Fd,
        src_path: &GuestPtr<'a, str>,
        dest_fd: types::Fd,
        dest_path: &GuestPtr<'a, str>,
    ) -> Result<(), Error> {
        WasiSnapshotPreview1::path_rename(&mut self.inner, src_fd, src_path, dest_fd, dest_path)
            .await
    }

    async fn path_symlink<'a>(
        &mut self,
        src_path: &GuestPtr<'a, str>,
        dirfd: types::Fd,
        dest_path: &GuestPtr<'a, str>,
    ) -> Result<(), Error> {
        WasiSnapshotPreview1::path_symlink(&mut self.inner, src_path, dirfd, dest_path).await
    }

    async fn path_unlink_file<'a>(
        &mut self,
        dirfd: types::Fd,
        path: &GuestPtr<'a, str>,
    ) -> Result<(), Error> {
        WasiSnapshotPreview1::path_unlink_file(&mut self.inner, dirfd, path).await
    }

    async fn poll_oneoff<'a>(
        &mut self,
        subs: &GuestPtr<'a, types::Subscription>,
        events: &GuestPtr<'a, types::Event>,
        nsubscriptions: types::Size,
    ) -> Result<types::Size, Error> {
        WasiSnapshotPreview1::poll_oneoff(&mut self.inner, subs, events, nsubscriptions).await
    }

    async fn proc_exit(&mut self, status: types::Exitcode) -> wiggle::Trap {
        WasiSnapshotPreview1::proc_exit(&mut self.inner, status).await
    }

    async fn proc_raise(&mut self, sig: types::Signal) -> Result<(), Error> {
        WasiSnapshotPreview1::proc_raise(&mut self.inner, sig).await
    }

    async fn sched_yield(&mut self) -> Result<(), Error> {
        WasiSnapshotPreview1::sched_yield(&mut self.inner).await
    }

    async fn random_get<'a>(
        &mut self,
        buf: &GuestPtr<'a, u8>,
        buf_len: types::Size,
    ) -> Result<(), Error> {
        WasiSnapshotPreview1::random_get(&mut self.inner, buf, buf_len).await
    }

    async fn sock_accept(
        &mut self,
        fd: types::Fd,
        flags: types::Fdflags,
    ) -> Result<types::Fd, Error> {
        WasiSnapshotPreview1::sock_accept(&mut self.inner, fd, flags).await
    }

    async fn sock_recv<'a>(
        &mut self,
        fd: types::Fd,
        ri_data: &types::IovecArray<'a>,
        ri_flags: types::Riflags,
    ) -> Result<(types::Size, types::Roflags), Error> {
        WasiSnapshotPreview1::sock_recv(&mut self.inner, fd, ri_data, ri_flags).await
    }

    async fn sock_send<'a>(
        &mut self,
        fd: types::Fd,
        si_data: &types::CiovecArray<'a>,
        si_flags: types::Siflags,
    ) -> Result<types::Size, Error> {
        WasiSnapshotPreview1::sock_send(&mut self.inner, fd, si_data, si_flags).await
    }

    async fn sock_shutdown(&mut self, fd: types::Fd, how: types::Sdflags) -> Result<(), Error> {
        WasiSnapshotPreview1::sock_shutdown(&mut self.inner, fd, how).await
    }
}
