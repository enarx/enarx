#include <sys/syscall.h>

void _exit(int status) {
    asm("syscall; ud2" :: "a" (SYS_exit), "D" (status));
    while (1) {}
}

int main(void);
void _start(void) {
    _exit(main());
}
