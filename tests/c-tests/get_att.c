// SPDX-License-Identifier: Apache-2.0

#include "libc.h"
#include "enarx.h"
#include <errno.h>

int main(void) {
    unsigned char nonce[64];
    size_t technology;

    ssize_t size = get_att(nonce, sizeof(nonce), NULL, 0, &technology);

    if (size >= 0) {
	switch (technology) {
	case TEE_NONE:
	case TEE_SEV:
	case TEE_SGX:
	    return 0;
	default: return 1;
	}
    }

    else if (size == -1)
	return !(errno == ENOSYS);

    else
	return 1;
}
