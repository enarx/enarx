# SPDX-License-Identifier: Apache-2.0

.section .text, "ax"
.global _rdfsbase
.type _rdfsbase, @function
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
