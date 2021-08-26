// SPDX-License-Identifier: Apache-2.0

#include "libc.h"

int main(void) {
    struct timespec t;

    ssize_t rax = clock_gettime(CLOCK_MONOTONIC, &t);
    if (rax == 0) {
        rax = write(STDOUT_FILENO, &t, sizeof(t));
    }

    return rax != sizeof(t);
}
