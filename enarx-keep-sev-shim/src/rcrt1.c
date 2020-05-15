// SPDX-License-Identifier: MIT

// Taken from rcrt1.c musl libc and reduced to x86_64
// with custom arguments.

#include <stddef.h>

#define R_X86_64_RELATIVE   8
#define REL_RELATIVE    R_X86_64_RELATIVE


#define DT_RELA   7
#define DT_RELASZ 8
#define DT_REL    17
#define DT_RELSZ  18
#define DYN_CNT   (DT_RELSZ+1) // last DT_* + 1

#define R_TYPE(x) ((x)&0x7fffffff)

#define IS_RELATIVE(x, s) (R_TYPE(x) == REL_RELATIVE)

__attribute__((__visibility__("hidden")))
void _dyn_reloc(size_t *dynv, size_t base) {
    size_t i, dyn[DYN_CNT];
    size_t *rel;
    size_t rel_size;

    for (i = 0; i < DYN_CNT; i++)
        dyn[i] = 0;

    for (i = 0; dynv[i]; i += 2)
        if (dynv[i] < DYN_CNT)
            dyn[dynv[i]] = dynv[i + 1];

    rel = (void *) (base + dyn[DT_REL]);
    rel_size = dyn[DT_RELSZ];

    for (; rel_size; rel += 2, rel_size -= 2 * sizeof(size_t)) {
        if (!IS_RELATIVE(rel[1], 0))
            continue;
        size_t *rel_addr = (void *) (base + rel[0]);
        *rel_addr += base;
    }

    rel = (void *) (base + dyn[DT_RELA]);
    rel_size = dyn[DT_RELASZ];

    for (; rel_size; rel += 3, rel_size -= 3 * sizeof(size_t)) {
        if (!IS_RELATIVE(rel[1], 0))
            continue;
        size_t *rel_addr = (void *) (base + rel[0]);
        *rel_addr = base + rel[2];
    }
}

