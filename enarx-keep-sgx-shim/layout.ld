/*
 * The size of the enclave was chosen because it appears to be the
 * smallest maximum enclave size supported by 64-bit enclaves on
 * Intel chips in the wild. We are aiming for the largest universally
 * available enclave size.
 *
 * The location of the enclave was chosen according to the following
 * criteria.
 *
 *   1. Enclaves need to be naturally aligned. That is, their starting
 *      position needs to be a multiple of the size. We want the freedom
 *      to increase the default enclave size in the future. So that means
 *      we need to choose the highest practical location for the base of
 *      the enclave. Therefore, an enclave loaded at the 32TiB location
 *      can be a maximum of 32TiB in size.
 *
 *   2. Increasing to 64TiB would put the end of the enclave at 128TiB.
 *      However, the kernel sometimes loads data in this area. Therefore,
 *      32TiB gives us maximum possible room to grow.
 */

ENTRY(ctx)

SECTIONS {
  . = 32 * 1M * 1M;
  .enarx.ctx : { *(.enarx.ctx) }

  . = ALIGN(4K);
  .text : { *(.text*) }

  . = ALIGN(4K);
  .got.plt : { *(.got.plt) }
  .got : { *(.got) }

  . = ALIGN(2M);
  .enarx.stk : { *(.enarx.stk) }

  . = ALIGN(4K);
  .rodata : { *(.rodata*) }

  . = ALIGN(4K);
  .data : { *(.data*) }

  . = 32 * 1M * 1M + 63 * 1M * 1K;
  .enarx.shp : { *(.enarx.shp) }

  /* All other non-discarded sections implicitly go here... */

  /DISCARD/ : {
    *(.note*)
    *(.debug*)
    *(.comment*)
    *(.eh_frame*)
  }
}
