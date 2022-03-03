// SPDX-License-Identifier: Apache-2.0

#include "libc.h"

int main(void) {
    if (!is_enarx()) {
        return 0;
    }
    return getegid() != 1000;
}
