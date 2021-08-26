// SPDX-License-Identifier: Apache-2.0

#include "libc.h"

int main(void) {
    char msg[128 * 1024];

    if (!is_enarx()) {
        return 0;
    }

    return write(STDOUT_FILENO, msg, sizeof(msg)) != -EMSGSIZE;
}
