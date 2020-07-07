// SPDX-License-Identifier: Apache-2.0

//! Collection of useful assembler functions
//!
//! as long as stable rust has no asm!()

.section .text

/// Provoke a triple fault to shutdown the machine
///
/// An illegal IDT is loaded with limit=0 and an #UD is produced
///
/// Fun read: http://www.rcollins.org/Productivity/TripleFault.html
.global _enarx_asm_triple_fault
.type _enarx_asm_triple_fault, @function
.code64
.p2align 4
_enarx_asm_triple_fault:
    lea _enarx_asm_Hose_IDTR(%rip), %rdi
    lidt (%rdi)
    ud2
1:
    hlt
    jmp 1b
.pushsection .bss
_enarx_asm_Hose_IDTR:
.space 10
.popsection

.section .text, "ax"
.global _rdfsbase
.type _rdfsbase, @function
.code64
.p2align 4
_rdfsbase:
    rdfsbase %rax
    retq

.section .text, "ax"
.global _wrfsbase
.type _wrfsbase, @function
.code64
.p2align 4
_wrfsbase:
    wrfsbase %rdi
    retq
