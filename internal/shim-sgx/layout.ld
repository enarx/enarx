ENTRY(_start)

PHDRS {
    rodata PT_LOAD FILEHDR PHDRS;
    data PT_LOAD;
    text PT_LOAD;
    dynamic PT_DYNAMIC;
    note PT_NOTE;

    stk0 PT_LOAD;
    tcs0 PT_LOAD FLAGS(1 << 20); /* sallyport::elf::pf::sgx::TCS */
    ssa0 PT_LOAD;

    exec 0x63400000 FLAGS(0); /* sallyport::elf::pt::EXEC */
    heap PT_LOAD FLAGS(7);
}

SECTIONS {
    . = SIZEOF_HEADERS;

    . = ALIGN(4K);
    .rodata       : { *(.rodata .rodata.*) }            :rodata
    .dynsym       : { *(.dynsym) }                      :rodata
    .dynstr       : { *(.dynstr) }                      :rodata
    .gnu.hash     : { *(.gnu.hash) }                    :rodata
    .hash         : { *(.hash) }                        :rodata
    .note         : { *(.note) }                        :rodata :note

    . = ALIGN(4K);
    .data.rel.ro  : { *(.data.rel.ro .data.rel.ro.*) }  :data
    .dynamic      : { *(.dynamic) }                     :data :dynamic
    .data         : { *(.data .data.*) }                :data
    .rela.dyn     : { *(.rela.*) }                      :data
    .got          : { *(.got) }                         :data
    .bss          : { *(.bss .bss.*) }                  :data

    . = ALIGN(4K);
    .text         : { *(.text .text.*) }                :text

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note.GNU-stack)
        *(.gnu_debuglink)
        *(.interp)
        *(.comment)
        *(COMMON)
        *(.note.gnu.build-id)
    }

    /* THREAD */
    . = ALIGN(2M);
    . += 4K;                /* Guard Page */
    .enarx.stk0 (NOLOAD) : { . += 2M - 4K * 5; } :stk0 =0
    .enarx.tcs0 : {
        . += 16;
        QUAD(. + 4K - 16)   /* OSSA */
        LONG(0)             /* CSSA */
        LONG(3)             /* NSSA */
        QUAD(_start)        /* OENTRY */
        . = ALIGN(4K);
    } :tcs0 =0
    .enarx.ssa0 (NOLOAD) : { . += 4K * 3; } :ssa0 =0

    /* EXEC */
    . = ALIGN(1M);
    HIDDEN(ENARX_EXEC_START = .);
    .enarx.exec (NOLOAD) : { . = ALIGN(128M); } :exec =0
    HIDDEN(ENARX_EXEC_END = .);

    /* HEAP */
    . = ALIGN(128M);
    .enarx.heap (NOLOAD) : { *(.enarx.heap) } :heap =0
}
