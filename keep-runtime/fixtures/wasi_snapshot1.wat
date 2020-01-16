;;; SPDX-License-Identifier: Apache-2.0

;;; Return the number of command-line arguments
(module
  (import "wasi_snapshot_preview1" "args_sizes_get"
    (func $__wasi_args_sizes_get (param i32 i32) (result i32)))
  (func (export "_start") (result i32)
    (i32.store (i32.const 0) (i32.const 0))
    (i32.store (i32.const 4) (i32.const 0))
    (call $__wasi_args_sizes_get (i32.const 0) (i32.const 4))
    drop
    (i32.load (i32.const 0))
  )
  (memory 1)
  (export "memory" (memory 0))
)
