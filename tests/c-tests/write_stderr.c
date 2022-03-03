// SPDX-License-Identifier: Apache-2.0

#include "libc.h"

int main(void) {
    const char msg[] = "hi\n";
    const int len = sizeof(msg) - 1;
    return write(STDERR_FILENO, msg, len) != len;
}
