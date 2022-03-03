// SPDX-License-Identifier: Apache-2.0

#include "libc.h"
#include <sys/socket.h>

int main(void) {
    if (socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0) < 0)
        return 1;

    if (socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0) < 0)
        return 2;

    if (socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0) < 0)
        return 3;

    return 0;
}
