#include "libc.h"

int main(void) {
    const char msg[] = "hi\n";
    const int len = sizeof(msg) - 1;
    return write(STDOUT_FILENO, msg, len) != len;
}
