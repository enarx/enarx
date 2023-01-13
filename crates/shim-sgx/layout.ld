ENTRY(_start)

/* change CSSA_0_STACK_SIZE in lib.rs if you change this */
CSSA_0_STACK_SIZE = 0x800000;
CSSA_1_plus_STACK_SIZE = 0x800000;

PHDRS {
    rodata PT_LOAD FILEHDR PHDRS;
    data PT_LOAD;
    text PT_LOAD;
    dynamic PT_DYNAMIC;
    note PT_NOTE;

    stk1 PT_LOAD;
    stk0 PT_LOAD;
    tcs PT_LOAD FLAGS(1 << 20); /* sallyport::elf::pf::sgx::TCS */
    ssa PT_LOAD;

    exec 0x63400000 FLAGS(0); /* sallyport::elf::pt::EXEC */
}

SECTIONS {
    HIDDEN(ENARX_SHIM_ADDRESS = .);
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
    .enarx.stk1 (NOLOAD) : { . += CSSA_1_plus_STACK_SIZE - 4K * 5; } :stk1 =0
    . += 4K;                /* Guard Page */
    .enarx.stk0 (NOLOAD) : { . += CSSA_0_STACK_SIZE - 4K; } :stk0 =0
    .enarx.tcs : {
        . += 16;
        QUAD(ADDR(.enarx.ssa))   /* OSSA */
        LONG(0)                   /* CSSA */
        LONG(4)                   /* NSSA */
        QUAD(_start)              /* OENTRY */
        . = ALIGN(4K);
    } :tcs =0
    .enarx.ssa (NOLOAD) : { . += 4K * 4; } :ssa =0

    /* EXEC */
    . = ALIGN(2M);
    HIDDEN(ENARX_EXEC_START = .);
    .enarx.exec (NOLOAD) : { . = ALIGN(128M); } :exec =0
    . = ALIGN(4K);
    HIDDEN(ENARX_EXEC_END = .);
}
