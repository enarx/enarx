#include "libc.h"
#include "enarx.h"
#include <errno.h>

/* This test will be run only for SEV */

int main(void) {
    int* nonce = NULL;
    // TODO Update this buffer size to match real Quote.
    unsigned char buf[16*1024];
    size_t technology;

    ssize_t size = get_att(nonce, sizeof(nonce), buf, sizeof(buf), &technology);

    if (technology != TEE_SEV)
        return 0;

    if (size < 0)
        return 1;

    write(STDOUT_FILENO, buf, size);

    return 0;
}
