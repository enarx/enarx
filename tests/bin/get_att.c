#include "libc.h"
#include <errno.h>

int main(void) {
    // TODO: Good buffer length?
    unsigned char nonce[512];
    unsigned char buf[512];
    size_t technology;

    ssize_t size = get_att(nonce, sizeof(nonce), buf, sizeof(buf), &technology);

    // TODO: Currently this should return ENOSYS. However, this will change
    // as get_att() is implemented for each technology.
    return !(size == -1 && errno == ENOSYS);
}
