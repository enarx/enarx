ENTRY(_start)

/* change CSSA_0_STACK_SIZE in lib.rs if you change this */
CSSA_0_STACK_SIZE = 0x200000;
CSSA_1_plus_STACK_SIZE = 0x200000;

PHDRS {
    rodata PT_LOAD FILEHDR PHDRS;
    data PT_LOAD;
    text PT_LOAD;
    dynamic PT_DYNAMIC;
    note PT_NOTE;

    stk01 PT_LOAD;
    stk00 PT_LOAD;
    tcs0 PT_LOAD FLAGS(1 << 20); /* sallyport::elf::pf::sgx::TCS */
    ssa0 PT_LOAD;

    stk11 PT_LOAD;
    stk10 PT_LOAD;
    tcs1 PT_LOAD FLAGS(1 << 20); /* sallyport::elf::pf::sgx::TCS */
    ssa1 PT_LOAD;

    stk21 PT_LOAD;
    stk20 PT_LOAD;
    tcs2 PT_LOAD FLAGS(1 << 20); /* sallyport::elf::pf::sgx::TCS */
    ssa2 PT_LOAD;

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
    .enarx.stk01 (NOLOAD) : { . += CSSA_1_plus_STACK_SIZE - 4K * 5; } :stk01 =0
    . += 4K;                /* Guard Page */
    .enarx.stk00 (NOLOAD) : { . += CSSA_0_STACK_SIZE - 4K; } :stk00 =0
    .enarx.tcs0 : {
        . += 16;
        QUAD(ADDR(.enarx.ssa0))   /* OSSA */
        LONG(0)                   /* CSSA */
        LONG(3)                   /* NSSA */
        QUAD(_start)              /* OENTRY */
        . = ALIGN(4K);
    } :tcs0 =0
    .enarx.ssa0 (NOLOAD) : { . += 4K * 3; } :ssa0 =0

    . += 4K;                /* Guard Page */
    .enarx.stk11 (NOLOAD) : { . += CSSA_1_plus_STACK_SIZE - 4K * 5; } :stk11 =0
    . += 4K;                /* Guard Page */
    .enarx.stk10 (NOLOAD) : { . += CSSA_0_STACK_SIZE - 4K; } :stk10 =0
    .enarx.tcs1 : {
        . += 16;
        QUAD(ADDR(.enarx.ssa1))   /* OSSA */
        LONG(0)                   /* CSSA */
        LONG(3)                   /* NSSA */
        QUAD(_start)              /* OENTRY */
        . = ALIGN(4K);
    } :tcs1 =0
    .enarx.ssa1 (NOLOAD) : { . += 4K * 3; } :ssa1 =0

    . += 4K;                /* Guard Page */
    .enarx.stk21 (NOLOAD) : { . += CSSA_1_plus_STACK_SIZE - 4K * 5; } :stk21 =0
    . += 4K;                /* Guard Page */
    .enarx.stk20 (NOLOAD) : { . += CSSA_0_STACK_SIZE - 4K; } :stk20 =0
    .enarx.tcs2 : {
        . += 16;
        QUAD(ADDR(.enarx.ssa2))   /* OSSA */
        LONG(0)                   /* CSSA */
        LONG(3)                   /* NSSA */
        QUAD(_start)              /* OENTRY */
        . = ALIGN(4K);
    } :tcs2 =0
    .enarx.ssa2 (NOLOAD) : { . += 4K * 3; } :ssa2 =0

    /* EXEC */
    . = ALIGN(1M);
    HIDDEN(ENARX_EXEC_START = .);
    .enarx.exec (NOLOAD) : { . = ALIGN(128M); } :exec =0
    . = ALIGN(4K);
    HIDDEN(ENARX_EXEC_END = .);
}
