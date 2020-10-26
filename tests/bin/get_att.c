#include "libc.h"
#include <errno.h>

typedef enum {
    NO_KEEP,
    SEV,
    SGX,
} tech;

int main(void) {
    // TODO: Good buffer length?
    unsigned char nonce[512];
    unsigned char buf[512];
    size_t technology;

    ssize_t size = get_att(nonce, sizeof(nonce), buf, sizeof(buf), &technology);

    if (size >= 0) {
	switch (technology) {
	case NO_KEEP:
	case SEV:
	case SGX:
	    return 0;
	default: return 1;
	}
    }

    else if (size == -1)
	return !(errno == ENOSYS);

    else
	return 1;
}
