// SPDX-License-Identifier: Apache-2.0

#include "libc.h"
#include "enarx.h"
#include <errno.h>

/* This test will be run only for SGX. It is designed to request a
 * Quote size from get_attestation()  */

int main(void) {
    size_t technology;

    ssize_t size = get_att(NULL, 0, NULL, 0, &technology);

    if (size <= 0)
        return 1;

    /* this test is SGX-specific, so just return success if not running on SGX */
    if (technology != TEE_SGX)
        return 0;

    return 0;
}
