// SPDX-License-Identifier: Apache-2.0

// Read and write a buffer of the size of a maximum sized UDP packet
// in one go and fail, if it was fragmented.

#include "libc.h"

int main(void) {
    char buf[65507];

    ssize_t out = read(STDIN_FILENO, buf, sizeof(buf));

    if (out != sizeof(buf))
        return -1;

    write(STDOUT_FILENO, buf, out);
}
