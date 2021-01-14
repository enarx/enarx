#include "libc.h"
#include "enarx.h"
#include <errno.h>

/* This test will be run only for SGX. It is designed to request a
 * Quote from get_attestation() and check that the first bytes of
 * the returned Quote in buf match expected values. */

// TODO: Determine expected Quote value

int main(void) {
    int* nonce = NULL;
    unsigned char buf[4598];
    size_t technology;

    ssize_t size = get_att(nonce, sizeof(nonce), buf, sizeof(buf), &technology);

    /* this test is SGX-specific, so just return success if not running on SGX */
    if (technology != TEE_SGX)
        return 0;

    if (size < 0)
        return 1;

    return 0;
}
