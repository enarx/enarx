// SPDX-License-Identifier: Apache-2.0

#include "libc.h"

int min(int a, int b) {
    return a < b ? a : b;
}

int main(void) {
    char buf[16] = {};

    for (size_t in = 1;; in = min (in * 2 , sizeof(buf))) {
        ssize_t out = read(STDIN_FILENO, buf, in);
        if (out <= 0)
            break;

        write(STDOUT_FILENO, buf, out);
    }
}
