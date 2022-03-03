// SPDX-License-Identifier: Apache-2.0

use sallyport::syscall::FileSyscallHandler;

impl<'a> FileSyscallHandler for super::Handler<'a> {}
