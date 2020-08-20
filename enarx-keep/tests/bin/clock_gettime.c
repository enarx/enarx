#include <sys/syscall.h>
#include <time.h>


void _start(void) {
    struct timespec t;
    asm(
        "syscall"
        : // no ouputs
        : "a" (SYS_clock_gettime), "D" (CLOCK_MONOTONIC), "S" (&t)
        : // no clobbers
    );

    asm(
        "syscall; ud2"
        : // no outputs
        : "a" (SYS_exit), "D" (0)
        : // no clobbers
    );
}
