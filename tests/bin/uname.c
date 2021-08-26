// SPDX-License-Identifier: Apache-2.0

#include "libc.h"

int strcmp(const char* s1, const char* s2)
{
    while(*s1 && (*s1==*s2))
        s1++,s2++;
    return *(const unsigned char*)s1-*(const unsigned char*)s2;
}

int main(void) {

    int v;
    char *l = "Linux";
    struct utsname buffer;

    errno = 0;
    if (uname(&buffer) != 0) {
       return 1;
    }

    v = strcmp(buffer.sysname, l);
    if (v != 0) {
        return 1;
    }

    return 0;
}
