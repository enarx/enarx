#include "libc.h"
#include "enarx.h"
#include <errno.h>

int main(void) {
    // TODO: Good buffer length?
    unsigned char nonce[512];
    unsigned char buf[1244];
    size_t technology;

    ssize_t size = get_att(nonce, sizeof(nonce), buf, sizeof(buf), &technology);

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
