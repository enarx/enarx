#include <sys/syscall.h>
#include <unistd.h>

void _start(void) {
    char s[3] = "hi\n";
    int len = 3;

    asm(
        "syscall"
        : // no ouputs
        : "a" (SYS_write), "D" (STDOUT_FILENO), "S" (&s), "d" (len)
        : // no clobbers
    );

    asm(
        "syscall; ud2"
        : // no outputs
        : "a" (SYS_exit), "D" (0)
        : // no clobbers
    );
}
