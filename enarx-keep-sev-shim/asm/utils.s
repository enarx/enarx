# This function is just for testing purposes and will be removed in the future
.section .text, "ax"
.global _enarx_asm_ud2
.type _enarx_asm_ud2, @function
.p2align 4
_enarx_asm_ud2:
    ud2
    ret

# This function is just for testing purposes and will be removed in the future
.global _enarx_asm_io_hello_world
.type _enarx_asm_io_hello_world, @function
.p2align 4
_enarx_asm_io_hello_world:
    movw $0x2f8, %dx
    movb $'H', %al
    outb %al, %dx
    ret

# This function is just for testing purposes and will be removed in the future
.global _x86_64_asm_hlt
.type _x86_64_asm_hlt, @function
.p2align 4
_x86_64_asm_hlt:
    hlt
    ret
