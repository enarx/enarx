// SPDX-License-Identifier: Apache-2.0

#include "libc.h"

/* sizeof("hello, world") = 12 (note: no NUL byte) */
#define BUF (12)

int main(void) {

    /* input = "hello, worldhello, worldhello, world"
     * so we'll gather each greeting into its own array */
    char a[BUF] = {};
    char b[BUF] = {};
    char c[BUF] = {};

    struct iovec iov[] = {
        {
            .iov_base = a,
            .iov_len = BUF,
        },
        {
            .iov_base = b,
            .iov_len = BUF,
        },
        {
            .iov_base = c,
            .iov_len = BUF,
        },
    };
    int niov = (sizeof(iov)/sizeof(iov[0]));

    readv(STDIN_FILENO, iov, niov);
    write(STDOUT_FILENO, a, BUF);
    write(STDOUT_FILENO, b, BUF);
    write(STDOUT_FILENO, c, BUF);

    return 0;
}
