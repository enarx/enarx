# SPDX-License-Identifier: Apache-2.0

.section .text, "ax"
.global _read_xcr0
.type _read_xcr0, @function
.p2align 4
_read_xcr0:
    xor    %ecx,%ecx
    xgetbv
    shl    $0x20,%rdx   # shift edx to upper 32bit
    mov    %eax,%eax    # clear upper 32bit of rax
    or     %rdx,%rax    # or with rdx
    retq

.section .text, "ax"
.global _write_xcr0
.type _writex_cr0, @function
.code64
.p2align 4
_write_xcr0:
    mov    %rdi,%rax
    mov    %rdi,%rdx
    shr    $0x20,%rdx
    xor    %ecx,%ecx
    xsetbv
    retq
