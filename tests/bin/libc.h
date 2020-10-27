#include <sys/syscall.h>
#include <sys/uio.h> /* struct iovec */
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>

int *__errno_location(void) {
    static int errnum = 0;
    return &errnum;
}

void _exit(int status) {
    asm(
        "syscall; ud2"
        :
        : "a" (SYS_exit), "D" (status)
        : "%rcx", "%r11"
    );

    while (1) {}
}

int main(void);
void _start(void) {
    _exit(main());
}

ssize_t read(int fd, void *buf, size_t count) {
    ssize_t rax;

    asm(
        "syscall"
        : "=a" (rax)
        : "a" (SYS_read), "D" (fd), "S" (buf), "d" (count)
        : "%rcx", "%r11"
    );

    if (rax < 0) {
        errno = -rax;
        return -1;
    }

    return rax;
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt) {
    ssize_t rax;

    asm(
        "syscall"
        : "=a" (rax)
        : "a" (SYS_readv), "D" (fd), "S" (iov), "d" (iovcnt)
        : "%rcx", "%r11"
    );

    if (rax < 0) {
        errno = -rax;
        return -1;
    }

    return rax;
}

ssize_t write(int fd, const void *buf, size_t count) {
    ssize_t rax;

    asm(
        "syscall"
        : "=a" (rax)
        : "a" (SYS_write), "D" (fd), "S" (buf), "d" (count)
        : "%rcx", "%r11"
    );

    if (rax < 0) {
        errno = -rax;
        return -1;
    }

    return rax;
}

int clock_gettime(clockid_t clk_id, struct timespec *tp) {
    int rax;

    asm(
        "syscall"
        : "=a" (rax)
        : "a" (SYS_clock_gettime), "D" (clk_id), "S" (tp)
        : "%rcx", "%r11"
    );

    if (rax < 0) {
        errno = -rax;
        return -1;
    }

    return rax;
}

int is_enarx() {
    ssize_t rax;

    asm(
        "syscall"
        : "=a" (rax)
        : "a" (SYS_fork)
        : "%rcx", "%r11"
    );

    switch (rax) {
        case 0: _exit(0);
        case -ENOSYS: return 1;
        default: return 0;
    }
}

ssize_t get_att(void *nonce, size_t nonce_len, void *buf, size_t buf_len, size_t *technology) {
    ssize_t rax;
    ssize_t tech;
    register size_t r10 __asm__("r10") = buf_len;

    asm(
        "syscall"
        : "=a" (rax), "=d" (tech)
        : "a" (0xEA01), "D" (nonce), "S" (nonce_len), "d" (buf), "r" (r10)
        : "%rcx", "%r11"
    );

    if (rax < 0) {
        errno = -rax;
        return -1;
    }

    *technology = tech;
    return rax;
}

uid_t getuid() {
    uid_t rax;
    asm(
        "syscall"
        : "=a" (rax)
        : "a" (SYS_getuid)
        : "%rcx", "%r11"
    );
    return rax;
}


uid_t geteuid() {
    uid_t rax;
    asm(
        "syscall" 
        : "=a" (rax)
        : "a" (SYS_geteuid)
        : "%rcx", "%r11"
    );
    return rax;
}

gid_t getgid() {
    gid_t rax;
    asm(
        "syscall" 
        : "=a" (rax)
        : "a" (SYS_getgid)
        : "%rcx", "%r11"
    );
    return rax;
}


gid_t getegid() {
    gid_t rax;
    asm(
        "syscall" 
        : "=a" (rax)
        : "a" (SYS_getegid)
        : "%rcx", "%r11"
    );
    return rax;
}
