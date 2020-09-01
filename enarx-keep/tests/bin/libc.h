#include <sys/syscall.h>
#include <unistd.h>

void _exit(int status) {
    asm("syscall; ud2" :: "a" (SYS_exit), "D" (status));
    while (1) {}
}

int main(void);
void _start(void) {
    _exit(main());
}

ssize_t write(int fd, const void *buf, size_t count) {
    ssize_t rax;

    asm(
        "syscall"
        : "=a" (rax)
        : "a" (SYS_write), "D" (fd), "S" (buf), "d" (count)
    );

    return rax;
}
