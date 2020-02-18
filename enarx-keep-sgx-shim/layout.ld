SECTIONS {
  /* Shim gets loaded to: 32TiB + 63GiB (see README.md on enarx-keep-sgx) */
  . = 32 * 1M * 1M + 63M * 1K;

  /* Order .text first to ensure entry point. */
  .text : { *(.text) }

  /* All other non-discarded sections implicitly go here... */

  /DISCARD/ : {
    *(.note*)
    *(.debug*)
    *(.comment*)
    *(.eh_frame*)
  }
}
