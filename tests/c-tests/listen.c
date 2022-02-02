// SPDX-License-Identifier: Apache-2.0

#include "libc.h"
#include <sys/socket.h>
#include <string.h>
#include <stddef.h>
#include <sys/un.h>
#include <stdio.h>

#define UNIX_ABSTRACT_PATH "@enarx_listen_test"

int main(void) {
    struct sockaddr_un sa = {
            .sun_family = AF_UNIX,
    };
    socklen_t sa_len = strlen(UNIX_ABSTRACT_PATH);

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

    if (fd < 0)
        return 1;

    strcpy(sa.sun_path, UNIX_ABSTRACT_PATH);
    sa.sun_path[0] = '\0';

    if (bind(fd, (struct sockaddr *)&sa, offsetof(struct sockaddr_un, sun_path) + sa_len) < 0) {
        return 2;
    }

    if (listen(fd, 0))
        return errno;

    return 0;
}
