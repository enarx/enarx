# SPDX-License-Identifier: Apache-2.0

.section .text, "ax"
.global _context_switch
.type _context_switch, @function
.p2align 4
_context_switch:
    movq %rsi, %rsp
    callq  *%rdi
.CSWSP:
    jmp .CSWSP

.section .text, "ax"
.global _read_rsp
.type _read_rsp, @function
.p2align 4
_read_rsp:
    movq %rsp, %rax
    retq
