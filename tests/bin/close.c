// SPDX-License-Identifier: Apache-2.0

#include "libc.h"

int main(void) {
    ssize_t ret = close(STDIN_FILENO);
    return ret != 0;
}
