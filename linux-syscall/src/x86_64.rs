// Copyright 2020 Red Hat, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! syscall type and constants

/// SyscallNR as a transparent type
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Num(u64);

impl From<u64> for Num {
    #[inline(always)]
    fn from(val: u64) -> Self {
        Self(val)
    }
}

impl From<Num> for u64 {
    #[inline(always)]
    fn from(val: Num) -> Self {
        val.0
    }
}

// generated with
// ```bash
// $ while read a b c; do \
//    [ "${b#__NR_*}" != "$b" ] || continue; \
//    b="${b#__NR_*}"; \
//    echo "/// $b()"; \
//    b=$(echo "$b" | tr '[:lower:]' '[:upper:]'); \
//    echo "pub const SYSCALL_$b: SyscallNR = SyscallNR::new($c);"; \
//    echo ; \
//  done < ./arch/x86/include/generated/uapi/asm/unistd_64.h
// ```

/// read()
pub const SYSCALL_READ: Num = Num(0);

/// write()
pub const SYSCALL_WRITE: Num = Num(1);

/// open()
pub const SYSCALL_OPEN: Num = Num(2);

/// close()
pub const SYSCALL_CLOSE: Num = Num(3);

/// stat()
pub const SYSCALL_STAT: Num = Num(4);

/// fstat()
pub const SYSCALL_FSTAT: Num = Num(5);

/// lstat()
pub const SYSCALL_LSTAT: Num = Num(6);

/// poll()
pub const SYSCALL_POLL: Num = Num(7);

/// lseek()
pub const SYSCALL_LSEEK: Num = Num(8);

/// mmap()
pub const SYSCALL_MMAP: Num = Num(9);

/// mprotect()
pub const SYSCALL_MPROTECT: Num = Num(10);

/// munmap()
pub const SYSCALL_MUNMAP: Num = Num(11);

/// brk()
pub const SYSCALL_BRK: Num = Num(12);

/// rt_sigaction()
pub const SYSCALL_RT_SIGACTION: Num = Num(13);

/// rt_sigprocmask()
pub const SYSCALL_RT_SIGPROCMASK: Num = Num(14);

/// rt_sigreturn()
pub const SYSCALL_RT_SIGRETURN: Num = Num(15);

/// ioctl()
pub const SYSCALL_IOCTL: Num = Num(16);

/// pread64()
pub const SYSCALL_PREAD64: Num = Num(17);

/// pwrite64()
pub const SYSCALL_PWRITE64: Num = Num(18);

/// readv()
pub const SYSCALL_READV: Num = Num(19);

/// writev()
pub const SYSCALL_WRITEV: Num = Num(20);

/// access()
pub const SYSCALL_ACCESS: Num = Num(21);

/// pipe()
pub const SYSCALL_PIPE: Num = Num(22);

/// select()
pub const SYSCALL_SELECT: Num = Num(23);

/// sched_yield()
pub const SYSCALL_SCHED_YIELD: Num = Num(24);

/// mremap()
pub const SYSCALL_MREMAP: Num = Num(25);

/// msync()
pub const SYSCALL_MSYNC: Num = Num(26);

/// mincore()
pub const SYSCALL_MINCORE: Num = Num(27);

/// madvise()
pub const SYSCALL_MADVISE: Num = Num(28);

/// shmget()
pub const SYSCALL_SHMGET: Num = Num(29);

/// shmat()
pub const SYSCALL_SHMAT: Num = Num(30);

/// shmctl()
pub const SYSCALL_SHMCTL: Num = Num(31);

/// dup()
pub const SYSCALL_DUP: Num = Num(32);

/// dup2()
pub const SYSCALL_DUP2: Num = Num(33);

/// pause()
pub const SYSCALL_PAUSE: Num = Num(34);

/// nanosleep()
pub const SYSCALL_NANOSLEEP: Num = Num(35);

/// getitimer()
pub const SYSCALL_GETITIMER: Num = Num(36);

/// alarm()
pub const SYSCALL_ALARM: Num = Num(37);

/// setitimer()
pub const SYSCALL_SETITIMER: Num = Num(38);

/// getpid()
pub const SYSCALL_GETPID: Num = Num(39);

/// sendfile()
pub const SYSCALL_SENDFILE: Num = Num(40);

/// socket()
pub const SYSCALL_SOCKET: Num = Num(41);

/// connect()
pub const SYSCALL_CONNECT: Num = Num(42);

/// accept()
pub const SYSCALL_ACCEPT: Num = Num(43);

/// sendto()
pub const SYSCALL_SENDTO: Num = Num(44);

/// recvfrom()
pub const SYSCALL_RECVFROM: Num = Num(45);

/// sendmsg()
pub const SYSCALL_SENDMSG: Num = Num(46);

/// recvmsg()
pub const SYSCALL_RECVMSG: Num = Num(47);

/// shutdown()
pub const SYSCALL_SHUTDOWN: Num = Num(48);

/// bind()
pub const SYSCALL_BIND: Num = Num(49);

/// listen()
pub const SYSCALL_LISTEN: Num = Num(50);

/// getsockname()
pub const SYSCALL_GETSOCKNAME: Num = Num(51);

/// getpeername()
pub const SYSCALL_GETPEERNAME: Num = Num(52);

/// socketpair()
pub const SYSCALL_SOCKETPAIR: Num = Num(53);

/// setsockopt()
pub const SYSCALL_SETSOCKOPT: Num = Num(54);

/// getsockopt()
pub const SYSCALL_GETSOCKOPT: Num = Num(55);

/// clone()
pub const SYSCALL_CLONE: Num = Num(56);

/// fork()
pub const SYSCALL_FORK: Num = Num(57);

/// vfork()
pub const SYSCALL_VFORK: Num = Num(58);

/// execve()
pub const SYSCALL_EXECVE: Num = Num(59);

/// exit()
pub const SYSCALL_EXIT: Num = Num(60);

/// wait4()
pub const SYSCALL_WAIT4: Num = Num(61);

/// kill()
pub const SYSCALL_KILL: Num = Num(62);

/// uname()
pub const SYSCALL_UNAME: Num = Num(63);

/// semget()
pub const SYSCALL_SEMGET: Num = Num(64);

/// semop()
pub const SYSCALL_SEMOP: Num = Num(65);

/// semctl()
pub const SYSCALL_SEMCTL: Num = Num(66);

/// shmdt()
pub const SYSCALL_SHMDT: Num = Num(67);

/// msgget()
pub const SYSCALL_MSGGET: Num = Num(68);

/// msgsnd()
pub const SYSCALL_MSGSND: Num = Num(69);

/// msgrcv()
pub const SYSCALL_MSGRCV: Num = Num(70);

/// msgctl()
pub const SYSCALL_MSGCTL: Num = Num(71);

/// fcntl()
pub const SYSCALL_FCNTL: Num = Num(72);

/// flock()
pub const SYSCALL_FLOCK: Num = Num(73);

/// fsync()
pub const SYSCALL_FSYNC: Num = Num(74);

/// fdatasync()
pub const SYSCALL_FDATASYNC: Num = Num(75);

/// truncate()
pub const SYSCALL_TRUNCATE: Num = Num(76);

/// ftruncate()
pub const SYSCALL_FTRUNCATE: Num = Num(77);

/// getdents()
pub const SYSCALL_GETDENTS: Num = Num(78);

/// getcwd()
pub const SYSCALL_GETCWD: Num = Num(79);

/// chdir()
pub const SYSCALL_CHDIR: Num = Num(80);

/// fchdir()
pub const SYSCALL_FCHDIR: Num = Num(81);

/// rename()
pub const SYSCALL_RENAME: Num = Num(82);

/// mkdir()
pub const SYSCALL_MKDIR: Num = Num(83);

/// rmdir()
pub const SYSCALL_RMDIR: Num = Num(84);

/// creat()
pub const SYSCALL_CREAT: Num = Num(85);

/// link()
pub const SYSCALL_LINK: Num = Num(86);

/// unlink()
pub const SYSCALL_UNLINK: Num = Num(87);

/// symlink()
pub const SYSCALL_SYMLINK: Num = Num(88);

/// readlink()
pub const SYSCALL_READLINK: Num = Num(89);

/// chmod()
pub const SYSCALL_CHMOD: Num = Num(90);

/// fchmod()
pub const SYSCALL_FCHMOD: Num = Num(91);

/// chown()
pub const SYSCALL_CHOWN: Num = Num(92);

/// fchown()
pub const SYSCALL_FCHOWN: Num = Num(93);

/// lchown()
pub const SYSCALL_LCHOWN: Num = Num(94);

/// umask()
pub const SYSCALL_UMASK: Num = Num(95);

/// gettimeofday()
pub const SYSCALL_GETTIMEOFDAY: Num = Num(96);

/// getrlimit()
pub const SYSCALL_GETRLIMIT: Num = Num(97);

/// getrusage()
pub const SYSCALL_GETRUSAGE: Num = Num(98);

/// sysinfo()
pub const SYSCALL_SYSINFO: Num = Num(99);

/// times()
pub const SYSCALL_TIMES: Num = Num(100);

/// ptrace()
pub const SYSCALL_PTRACE: Num = Num(101);

/// getuid()
pub const SYSCALL_GETUID: Num = Num(102);

/// syslog()
pub const SYSCALL_SYSLOG: Num = Num(103);

/// getgid()
pub const SYSCALL_GETGID: Num = Num(104);

/// setuid()
pub const SYSCALL_SETUID: Num = Num(105);

/// setgid()
pub const SYSCALL_SETGID: Num = Num(106);

/// geteuid()
pub const SYSCALL_GETEUID: Num = Num(107);

/// getegid()
pub const SYSCALL_GETEGID: Num = Num(108);

/// setpgid()
pub const SYSCALL_SETPGID: Num = Num(109);

/// getppid()
pub const SYSCALL_GETPPID: Num = Num(110);

/// getpgrp()
pub const SYSCALL_GETPGRP: Num = Num(111);

/// setsid()
pub const SYSCALL_SETSID: Num = Num(112);

/// setreuid()
pub const SYSCALL_SETREUID: Num = Num(113);

/// setregid()
pub const SYSCALL_SETREGID: Num = Num(114);

/// getgroups()
pub const SYSCALL_GETGROUPS: Num = Num(115);

/// setgroups()
pub const SYSCALL_SETGROUPS: Num = Num(116);

/// setresuid()
pub const SYSCALL_SETRESUID: Num = Num(117);

/// getresuid()
pub const SYSCALL_GETRESUID: Num = Num(118);

/// setresgid()
pub const SYSCALL_SETRESGID: Num = Num(119);

/// getresgid()
pub const SYSCALL_GETRESGID: Num = Num(120);

/// getpgid()
pub const SYSCALL_GETPGID: Num = Num(121);

/// setfsuid()
pub const SYSCALL_SETFSUID: Num = Num(122);

/// setfsgid()
pub const SYSCALL_SETFSGID: Num = Num(123);

/// getsid()
pub const SYSCALL_GETSID: Num = Num(124);

/// capget()
pub const SYSCALL_CAPGET: Num = Num(125);

/// capset()
pub const SYSCALL_CAPSET: Num = Num(126);

/// rt_sigpending()
pub const SYSCALL_RT_SIGPENDING: Num = Num(127);

/// rt_sigtimedwait()
pub const SYSCALL_RT_SIGTIMEDWAIT: Num = Num(128);

/// rt_sigqueueinfo()
pub const SYSCALL_RT_SIGQUEUEINFO: Num = Num(129);

/// rt_sigsuspend()
pub const SYSCALL_RT_SIGSUSPEND: Num = Num(130);

/// sigaltstack()
pub const SYSCALL_SIGALTSTACK: Num = Num(131);

/// utime()
pub const SYSCALL_UTIME: Num = Num(132);

/// mknod()
pub const SYSCALL_MKNOD: Num = Num(133);

/// uselib()
pub const SYSCALL_USELIB: Num = Num(134);

/// personality()
pub const SYSCALL_PERSONALITY: Num = Num(135);

/// ustat()
pub const SYSCALL_USTAT: Num = Num(136);

/// statfs()
pub const SYSCALL_STATFS: Num = Num(137);

/// fstatfs()
pub const SYSCALL_FSTATFS: Num = Num(138);

/// sysfs()
pub const SYSCALL_SYSFS: Num = Num(139);

/// getpriority()
pub const SYSCALL_GETPRIORITY: Num = Num(140);

/// setpriority()
pub const SYSCALL_SETPRIORITY: Num = Num(141);

/// sched_setparam()
pub const SYSCALL_SCHED_SETPARAM: Num = Num(142);

/// sched_getparam()
pub const SYSCALL_SCHED_GETPARAM: Num = Num(143);

/// sched_setscheduler()
pub const SYSCALL_SCHED_SETSCHEDULER: Num = Num(144);

/// sched_getscheduler()
pub const SYSCALL_SCHED_GETSCHEDULER: Num = Num(145);

/// sched_get_priority_max()
pub const SYSCALL_SCHED_GET_PRIORITY_MAX: Num = Num(146);

/// sched_get_priority_min()
pub const SYSCALL_SCHED_GET_PRIORITY_MIN: Num = Num(147);

/// sched_rr_get_interval()
pub const SYSCALL_SCHED_RR_GET_INTERVAL: Num = Num(148);

/// mlock()
pub const SYSCALL_MLOCK: Num = Num(149);

/// munlock()
pub const SYSCALL_MUNLOCK: Num = Num(150);

/// mlockall()
pub const SYSCALL_MLOCKALL: Num = Num(151);

/// munlockall()
pub const SYSCALL_MUNLOCKALL: Num = Num(152);

/// vhangup()
pub const SYSCALL_VHANGUP: Num = Num(153);

/// modify_ldt()
pub const SYSCALL_MODIFY_LDT: Num = Num(154);

/// pivot_root()
pub const SYSCALL_PIVOT_ROOT: Num = Num(155);

/// _sysctl()
pub const SYSCALL__SYSCTL: Num = Num(156);

/// prctl()
pub const SYSCALL_PRCTL: Num = Num(157);

/// arch_prctl()
pub const SYSCALL_ARCH_PRCTL: Num = Num(158);

/// adjtimex()
pub const SYSCALL_ADJTIMEX: Num = Num(159);

/// setrlimit()
pub const SYSCALL_SETRLIMIT: Num = Num(160);

/// chroot()
pub const SYSCALL_CHROOT: Num = Num(161);

/// sync()
pub const SYSCALL_SYNC: Num = Num(162);

/// acct()
pub const SYSCALL_ACCT: Num = Num(163);

/// settimeofday()
pub const SYSCALL_SETTIMEOFDAY: Num = Num(164);

/// mount()
pub const SYSCALL_MOUNT: Num = Num(165);

/// umount2()
pub const SYSCALL_UMOUNT2: Num = Num(166);

/// swapon()
pub const SYSCALL_SWAPON: Num = Num(167);

/// swapoff()
pub const SYSCALL_SWAPOFF: Num = Num(168);

/// reboot()
pub const SYSCALL_REBOOT: Num = Num(169);

/// sethostname()
pub const SYSCALL_SETHOSTNAME: Num = Num(170);

/// setdomainname()
pub const SYSCALL_SETDOMAINNAME: Num = Num(171);

/// iopl()
pub const SYSCALL_IOPL: Num = Num(172);

/// ioperm()
pub const SYSCALL_IOPERM: Num = Num(173);

/// create_module()
pub const SYSCALL_CREATE_MODULE: Num = Num(174);

/// init_module()
pub const SYSCALL_INIT_MODULE: Num = Num(175);

/// delete_module()
pub const SYSCALL_DELETE_MODULE: Num = Num(176);

/// get_kernel_syms()
pub const SYSCALL_GET_KERNEL_SYMS: Num = Num(177);

/// query_module()
pub const SYSCALL_QUERY_MODULE: Num = Num(178);

/// quotactl()
pub const SYSCALL_QUOTACTL: Num = Num(179);

/// nfsservctl()
pub const SYSCALL_NFSSERVCTL: Num = Num(180);

/// getpmsg()
pub const SYSCALL_GETPMSG: Num = Num(181);

/// putpmsg()
pub const SYSCALL_PUTPMSG: Num = Num(182);

/// afs_syscall()
pub const SYSCALL_AFS_SYSCALL: Num = Num(183);

/// tuxcall()
pub const SYSCALL_TUXCALL: Num = Num(184);

/// security()
pub const SYSCALL_SECURITY: Num = Num(185);

/// gettid()
pub const SYSCALL_GETTID: Num = Num(186);

/// readahead()
pub const SYSCALL_READAHEAD: Num = Num(187);

/// setxattr()
pub const SYSCALL_SETXATTR: Num = Num(188);

/// lsetxattr()
pub const SYSCALL_LSETXATTR: Num = Num(189);

/// fsetxattr()
pub const SYSCALL_FSETXATTR: Num = Num(190);

/// getxattr()
pub const SYSCALL_GETXATTR: Num = Num(191);

/// lgetxattr()
pub const SYSCALL_LGETXATTR: Num = Num(192);

/// fgetxattr()
pub const SYSCALL_FGETXATTR: Num = Num(193);

/// listxattr()
pub const SYSCALL_LISTXATTR: Num = Num(194);

/// llistxattr()
pub const SYSCALL_LLISTXATTR: Num = Num(195);

/// flistxattr()
pub const SYSCALL_FLISTXATTR: Num = Num(196);

/// removexattr()
pub const SYSCALL_REMOVEXATTR: Num = Num(197);

/// lremovexattr()
pub const SYSCALL_LREMOVEXATTR: Num = Num(198);

/// fremovexattr()
pub const SYSCALL_FREMOVEXATTR: Num = Num(199);

/// tkill()
pub const SYSCALL_TKILL: Num = Num(200);

/// time()
pub const SYSCALL_TIME: Num = Num(201);

/// futex()
pub const SYSCALL_FUTEX: Num = Num(202);

/// sched_setaffinity()
pub const SYSCALL_SCHED_SETAFFINITY: Num = Num(203);

/// sched_getaffinity()
pub const SYSCALL_SCHED_GETAFFINITY: Num = Num(204);

/// set_thread_area()
pub const SYSCALL_SET_THREAD_AREA: Num = Num(205);

/// io_setup()
pub const SYSCALL_IO_SETUP: Num = Num(206);

/// io_destroy()
pub const SYSCALL_IO_DESTROY: Num = Num(207);

/// io_getevents()
pub const SYSCALL_IO_GETEVENTS: Num = Num(208);

/// io_submit()
pub const SYSCALL_IO_SUBMIT: Num = Num(209);

/// io_cancel()
pub const SYSCALL_IO_CANCEL: Num = Num(210);

/// get_thread_area()
pub const SYSCALL_GET_THREAD_AREA: Num = Num(211);

/// lookup_dcookie()
pub const SYSCALL_LOOKUP_DCOOKIE: Num = Num(212);

/// epoll_create()
pub const SYSCALL_EPOLL_CREATE: Num = Num(213);

/// epoll_ctl_old()
pub const SYSCALL_EPOLL_CTL_OLD: Num = Num(214);

/// epoll_wait_old()
pub const SYSCALL_EPOLL_WAIT_OLD: Num = Num(215);

/// remap_file_pages()
pub const SYSCALL_REMAP_FILE_PAGES: Num = Num(216);

/// getdents64()
pub const SYSCALL_GETDENTS64: Num = Num(217);

/// set_tid_address()
pub const SYSCALL_SET_TID_ADDRESS: Num = Num(218);

/// restart_syscall()
pub const SYSCALL_RESTART_SYSCALL: Num = Num(219);

/// semtimedop()
pub const SYSCALL_SEMTIMEDOP: Num = Num(220);

/// fadvise64()
pub const SYSCALL_FADVISE64: Num = Num(221);

/// timer_create()
pub const SYSCALL_TIMER_CREATE: Num = Num(222);

/// timer_settime()
pub const SYSCALL_TIMER_SETTIME: Num = Num(223);

/// timer_gettime()
pub const SYSCALL_TIMER_GETTIME: Num = Num(224);

/// timer_getoverrun()
pub const SYSCALL_TIMER_GETOVERRUN: Num = Num(225);

/// timer_delete()
pub const SYSCALL_TIMER_DELETE: Num = Num(226);

/// clock_settime()
pub const SYSCALL_CLOCK_SETTIME: Num = Num(227);

/// clock_gettime()
pub const SYSCALL_CLOCK_GETTIME: Num = Num(228);

/// clock_getres()
pub const SYSCALL_CLOCK_GETRES: Num = Num(229);

/// clock_nanosleep()
pub const SYSCALL_CLOCK_NANOSLEEP: Num = Num(230);

/// exit_group()
pub const SYSCALL_EXIT_GROUP: Num = Num(231);

/// epoll_wait()
pub const SYSCALL_EPOLL_WAIT: Num = Num(232);

/// epoll_ctl()
pub const SYSCALL_EPOLL_CTL: Num = Num(233);

/// tgkill()
pub const SYSCALL_TGKILL: Num = Num(234);

/// utimes()
pub const SYSCALL_UTIMES: Num = Num(235);

/// vserver()
pub const SYSCALL_VSERVER: Num = Num(236);

/// mbind()
pub const SYSCALL_MBIND: Num = Num(237);

/// set_mempolicy()
pub const SYSCALL_SET_MEMPOLICY: Num = Num(238);

/// get_mempolicy()
pub const SYSCALL_GET_MEMPOLICY: Num = Num(239);

/// mq_open()
pub const SYSCALL_MQ_OPEN: Num = Num(240);

/// mq_unlink()
pub const SYSCALL_MQ_UNLINK: Num = Num(241);

/// mq_timedsend()
pub const SYSCALL_MQ_TIMEDSEND: Num = Num(242);

/// mq_timedreceive()
pub const SYSCALL_MQ_TIMEDRECEIVE: Num = Num(243);

/// mq_notify()
pub const SYSCALL_MQ_NOTIFY: Num = Num(244);

/// mq_getsetattr()
pub const SYSCALL_MQ_GETSETATTR: Num = Num(245);

/// kexec_load()
pub const SYSCALL_KEXEC_LOAD: Num = Num(246);

/// waitid()
pub const SYSCALL_WAITID: Num = Num(247);

/// add_key()
pub const SYSCALL_ADD_KEY: Num = Num(248);

/// request_key()
pub const SYSCALL_REQUEST_KEY: Num = Num(249);

/// keyctl()
pub const SYSCALL_KEYCTL: Num = Num(250);

/// ioprio_set()
pub const SYSCALL_IOPRIO_SET: Num = Num(251);

/// ioprio_get()
pub const SYSCALL_IOPRIO_GET: Num = Num(252);

/// inotify_init()
pub const SYSCALL_INOTIFY_INIT: Num = Num(253);

/// inotify_add_watch()
pub const SYSCALL_INOTIFY_ADD_WATCH: Num = Num(254);

/// inotify_rm_watch()
pub const SYSCALL_INOTIFY_RM_WATCH: Num = Num(255);

/// migrate_pages()
pub const SYSCALL_MIGRATE_PAGES: Num = Num(256);

/// openat()
pub const SYSCALL_OPENAT: Num = Num(257);

/// mkdirat()
pub const SYSCALL_MKDIRAT: Num = Num(258);

/// mknodat()
pub const SYSCALL_MKNODAT: Num = Num(259);

/// fchownat()
pub const SYSCALL_FCHOWNAT: Num = Num(260);

/// futimesat()
pub const SYSCALL_FUTIMESAT: Num = Num(261);

/// newfstatat()
pub const SYSCALL_NEWFSTATAT: Num = Num(262);

/// unlinkat()
pub const SYSCALL_UNLINKAT: Num = Num(263);

/// renameat()
pub const SYSCALL_RENAMEAT: Num = Num(264);

/// linkat()
pub const SYSCALL_LINKAT: Num = Num(265);

/// symlinkat()
pub const SYSCALL_SYMLINKAT: Num = Num(266);

/// readlinkat()
pub const SYSCALL_READLINKAT: Num = Num(267);

/// fchmodat()
pub const SYSCALL_FCHMODAT: Num = Num(268);

/// faccessat()
pub const SYSCALL_FACCESSAT: Num = Num(269);

/// pselect6()
pub const SYSCALL_PSELECT6: Num = Num(270);

/// ppoll()
pub const SYSCALL_PPOLL: Num = Num(271);

/// unshare()
pub const SYSCALL_UNSHARE: Num = Num(272);

/// set_robust_list()
pub const SYSCALL_SET_ROBUST_LIST: Num = Num(273);

/// get_robust_list()
pub const SYSCALL_GET_ROBUST_LIST: Num = Num(274);

/// splice()
pub const SYSCALL_SPLICE: Num = Num(275);

/// tee()
pub const SYSCALL_TEE: Num = Num(276);

/// sync_file_range()
pub const SYSCALL_SYNC_FILE_RANGE: Num = Num(277);

/// vmsplice()
pub const SYSCALL_VMSPLICE: Num = Num(278);

/// move_pages()
pub const SYSCALL_MOVE_PAGES: Num = Num(279);

/// utimensat()
pub const SYSCALL_UTIMENSAT: Num = Num(280);

/// epoll_pwait()
pub const SYSCALL_EPOLL_PWAIT: Num = Num(281);

/// signalfd()
pub const SYSCALL_SIGNALFD: Num = Num(282);

/// timerfd_create()
pub const SYSCALL_TIMERFD_CREATE: Num = Num(283);

/// eventfd()
pub const SYSCALL_EVENTFD: Num = Num(284);

/// fallocate()
pub const SYSCALL_FALLOCATE: Num = Num(285);

/// timerfd_settime()
pub const SYSCALL_TIMERFD_SETTIME: Num = Num(286);

/// timerfd_gettime()
pub const SYSCALL_TIMERFD_GETTIME: Num = Num(287);

/// accept4()
pub const SYSCALL_ACCEPT4: Num = Num(288);

/// signalfd4()
pub const SYSCALL_SIGNALFD4: Num = Num(289);

/// eventfd2()
pub const SYSCALL_EVENTFD2: Num = Num(290);

/// epoll_create1()
pub const SYSCALL_EPOLL_CREATE1: Num = Num(291);

/// dup3()
pub const SYSCALL_DUP3: Num = Num(292);

/// pipe2()
pub const SYSCALL_PIPE2: Num = Num(293);

/// inotify_init1()
pub const SYSCALL_INOTIFY_INIT1: Num = Num(294);

/// preadv()
pub const SYSCALL_PREADV: Num = Num(295);

/// pwritev()
pub const SYSCALL_PWRITEV: Num = Num(296);

/// rt_tgsigqueueinfo()
pub const SYSCALL_RT_TGSIGQUEUEINFO: Num = Num(297);

/// perf_event_open()
pub const SYSCALL_PERF_EVENT_OPEN: Num = Num(298);

/// recvmmsg()
pub const SYSCALL_RECVMMSG: Num = Num(299);

/// fanotify_init()
pub const SYSCALL_FANOTIFY_INIT: Num = Num(300);

/// fanotify_mark()
pub const SYSCALL_FANOTIFY_MARK: Num = Num(301);

/// prlimit64()
pub const SYSCALL_PRLIMIT64: Num = Num(302);

/// name_to_handle_at()
pub const SYSCALL_NAME_TO_HANDLE_AT: Num = Num(303);

/// open_by_handle_at()
pub const SYSCALL_OPEN_BY_HANDLE_AT: Num = Num(304);

/// clock_adjtime()
pub const SYSCALL_CLOCK_ADJTIME: Num = Num(305);

/// syncfs()
pub const SYSCALL_SYNCFS: Num = Num(306);

/// sendmmsg()
pub const SYSCALL_SENDMMSG: Num = Num(307);

/// setns()
pub const SYSCALL_SETNS: Num = Num(308);

/// getcpu()
pub const SYSCALL_GETCPU: Num = Num(309);

/// process_vm_readv()
pub const SYSCALL_PROCESS_VM_READV: Num = Num(310);

/// process_vm_writev()
pub const SYSCALL_PROCESS_VM_WRITEV: Num = Num(311);

/// kcmp()
pub const SYSCALL_KCMP: Num = Num(312);

/// finit_module()
pub const SYSCALL_FINIT_MODULE: Num = Num(313);

/// sched_setattr()
pub const SYSCALL_SCHED_SETATTR: Num = Num(314);

/// sched_getattr()
pub const SYSCALL_SCHED_GETATTR: Num = Num(315);

/// renameat2()
pub const SYSCALL_RENAMEAT2: Num = Num(316);

/// seccomp()
pub const SYSCALL_SECCOMP: Num = Num(317);

/// getrandom()
pub const SYSCALL_GETRANDOM: Num = Num(318);

/// memfd_create()
pub const SYSCALL_MEMFD_CREATE: Num = Num(319);

/// kexec_file_load()
pub const SYSCALL_KEXEC_FILE_LOAD: Num = Num(320);

/// bpf()
pub const SYSCALL_BPF: Num = Num(321);

/// execveat()
pub const SYSCALL_EXECVEAT: Num = Num(322);

/// userfaultfd()
pub const SYSCALL_USERFAULTFD: Num = Num(323);

/// membarrier()
pub const SYSCALL_MEMBARRIER: Num = Num(324);

/// mlock2()
pub const SYSCALL_MLOCK2: Num = Num(325);

/// copy_file_range()
pub const SYSCALL_COPY_FILE_RANGE: Num = Num(326);

/// preadv2()
pub const SYSCALL_PREADV2: Num = Num(327);

/// pwritev2()
pub const SYSCALL_PWRITEV2: Num = Num(328);

/// pkey_mprotect()
pub const SYSCALL_PKEY_MPROTECT: Num = Num(329);

/// pkey_alloc()
pub const SYSCALL_PKEY_ALLOC: Num = Num(330);

/// pkey_free()
pub const SYSCALL_PKEY_FREE: Num = Num(331);

/// statx()
pub const SYSCALL_STATX: Num = Num(332);

/// io_pgetevents()
pub const SYSCALL_IO_PGETEVENTS: Num = Num(333);

/// rseq()
pub const SYSCALL_RSEQ: Num = Num(334);

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn basic() {
        assert_eq!(0u64, SYSCALL_READ.into());
        assert_eq!(SYSCALL_READ, 0u64.into());
    }
}
