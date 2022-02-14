// SPDX-License-Identifier: Apache-2.0

#include "libc.h"
#include "enarx.h"
#include <errno.h>

/* This test will be run only for SGX. It is designed to request a
 * Quote from get_attestation() and check that the first bytes of
 * the returned Quote in buf match expected values. */

int main(void) {
    unsigned char nonce[64]; /* empty pseudo-hash value to embed in SGX Quote */
    unsigned char buf[4598];
    size_t technology;
    int i;
    unsigned char expected[28] = {
            3, 0, 2, 0, 0, 0, 0, 0, 7,
            0, 12, 0, 147, 154, 114, 51, 247,
            156, 76, 169, 148, 10, 13, 179, 149,
            127, 6, 7
    };

    ssize_t size = get_att(nonce, sizeof(nonce), buf, sizeof(buf), &technology);

    if (size < 0)
        return !(errno == ENOSYS);

    /* this test is SGX-specific, so just return success if not running on SGX */
    if (technology != TEE_SGX)
        return 0;

    /* check beginning of quote matches expected value */
    for (i = 0; i < 28; i++) {
        if (buf[i] != expected[i]) {
            return 1;
        }
    }

    return 0;
}
