#include <sys/syscall.h>

#define STATUS 1

void _start(void) {
    asm(
        "syscall; ud2"
        : // no ouputs
        : "a" (SYS_exit), "D" (STATUS)
        : // no clobbers
    );
}
