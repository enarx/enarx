#include "libc.h"
#include "enarx.h"
#include <errno.h>

/* This test will be run only for SGX. It is designed to request a
 * Quote from get_attestation() and check that the first bytes of
 * the returned Quote in buf match expected values. */

// TODO: Update these to match real Quote values.
// See https://github.com/enarx/enarx-keepldr/issues/92.
const unsigned char expected[512] = { 44, 44, 44 };

int main(void) {
    int* nonce = NULL;
    // TODO Update this buffer size to match real Quote.
    unsigned char buf[512];
    size_t technology;
    int i;

    ssize_t size = get_att(nonce, sizeof(nonce), buf, sizeof(buf), &technology);

    /* this test is SGX-specific, so just return success if not running on SGX */
    if (technology != TEE_SGX)
        return 0;

    if (size < 0)
        return 1;

    for (i = 0; i < 3; i++) {
        if (buf[i] != expected[i])
	    return 1;
    }

    return 0;
}
