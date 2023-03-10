/* base on the sample code of the class */
#ifndef __LIBMINI_H__
#define __LIBMINI_H__		/* avoid reentrant */

typedef long long size_t;
typedef long long ssize_t;

extern long errno;

#define	NULL		((void*) 0)

/* from /usr/include/asm-generic/fcntl.h */
#define O_ACCMODE	00000003
#define O_RDONLY	00000000
#define O_WRONLY	00000001
#define O_RDWR		00000002
#ifndef O_CREAT
#define O_CREAT		00000100	/* not fcntl */
#endif
#ifndef O_EXCL
#define O_EXCL		00000200	/* not fcntl */
#endif
#ifndef O_NOCTTY
#define O_NOCTTY	00000400	/* not fcntl */
#endif
#ifndef O_TRUNC
#define O_TRUNC		00001000	/* not fcntl */
#endif
#ifndef O_APPEND
#define O_APPEND	00002000
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK	00004000
#endif
#ifndef O_DSYNC
#define O_DSYNC		00010000	/* used to be O_SYNC, see below */
#endif
#ifndef FASYNC
#define FASYNC		00020000	/* fcntl, for BSD compatibility */
#endif
#ifndef O_DIRECT
#define O_DIRECT	00040000	/* direct disk access hint */
#endif
#ifndef O_LARGEFILE
#define O_LARGEFILE	00100000
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY	00200000	/* must be a directory */
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW	00400000	/* don't follow links */
#endif
#ifndef O_NOATIME
#define O_NOATIME	01000000
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC	02000000	/* set close_on_exec */
#endif

/* from /usr/include/asm-generic/errno-base.h */
#define	EPERM		 1	/* Operation not permitted */
#define	ENOENT		 2	/* No such file or directory */
#define	ESRCH		 3	/* No such process */
#define	EINTR		 4	/* Interrupted system call */
#define	EIO		 5	/* I/O error */
#define	ENXIO		 6	/* No such device or address */
#define	E2BIG		 7	/* Argument list too long */
#define	ENOEXEC		 8	/* Exec format error */
#define	EBADF		 9	/* Bad file number */
#define	ECHILD		10	/* No child processes */
#define	EAGAIN		11	/* Try again */
#define	ENOMEM		12	/* Out of memory */
#define	EACCES		13	/* Permission denied */
#define	EFAULT		14	/* Bad address */
#define	ENOTBLK		15	/* Block device required */
#define	EBUSY		16	/* Device or resource busy */
#define	EEXIST		17	/* File exists */
#define	EXDEV		18	/* Cross-device link */
#define	ENODEV		19	/* No such device */
#define	ENOTDIR		20	/* Not a directory */
#define	EISDIR		21	/* Is a directory */
#define	EINVAL		22	/* Invalid argument */
#define	ENFILE		23	/* File table overflow */
#define	EMFILE		24	/* Too many open files */
#define	ENOTTY		25	/* Not a typewriter */
#define	ETXTBSY		26	/* Text file busy */
#define	EFBIG		27	/* File too large */
#define	ENOSPC		28	/* No space left on device */
#define	ESPIPE		29	/* Illegal seek */
#define	EROFS		30	/* Read-only file system */
#define	EMLINK		31	/* Too many links */
#define	EPIPE		32	/* Broken pipe */
#define	EDOM		33	/* Math argument out of domain of func */
#define	ERANGE		34	/* Math result not representable */

/* from /usr/include/x86_64-linux-gnu/asm/signal.h */
#define SIGHUP		 1
#define SIGINT		 2
#define SIGQUIT		 3
#define SIGILL		 4
#define SIGTRAP		 5
#define SIGABRT		 6
#define SIGIOT		 6
#define SIGBUS		 7
#define SIGFPE		 8
#define SIGKILL		 9
#define SIGUSR1		10
#define SIGSEGV		11
#define SIGUSR2		12
#define SIGPIPE		13
#define SIGALRM		14
#define SIGTERM		15
#define SIGSTKFLT	16
#define SIGCHLD		17
#define SIGCONT		18
#define SIGSTOP		19
#define SIGTSTP		20
#define SIGTTIN		21
#define SIGTTOU		22
#define SIGURG		23
#define SIGXCPU		24
#define SIGXFSZ		25
#define SIGVTALRM	26
#define SIGPROF		27
#define SIGWINCH	28
#define SIGIO		29
#define SIGPOLL		SIGIO

#define SIGPWR		30
#define SIGSYS		31

/* from /usr/include/x86_64-linux-gnu/bits/sigaction.h */
#define	SA_NOCLDSTOP  1		 /* Don't send SIGCHLD when children stop.  */
#define SA_NOCLDWAIT  2		 /* Don't create zombie on child death.  */
#define SA_SIGINFO    4		 /* Invoke signal-catching function with three arguments instead of one.  */
# define SA_ONSTACK   0x08000000 /* Use signal stack by using `sa_restorer'. */
# define SA_RESTART   0x10000000 /* Restart syscall on signal return.  */
# define SA_INTERRUPT 0x20000000 /* Historical no-op.  */
# define SA_NODEFER   0x40000000 /* Don't automatically block the signal when its handler is being executed.  */
# define SA_RESETHAND 0x80000000 /* Reset to SIG_DFL on entry to handler.  */

#define SA_RESTORER   0x04000000

#define	SIG_BLOCK     0		 /* Block signals.  */
#define	SIG_UNBLOCK   1		 /* Unblock signals.  */
#define	SIG_SETMASK   2		 /* Set the set of blocked signals.  */

#define	SIG_DFL		(void (*)(int))0
#define	SIG_IGN		(void (*)(int))1
#define	SIG_ERR		(void (*)(int))-1

#define NSIG (64 + 1)

// Ref: https://code.woboq.org/userspace/glibc/sysdeps/unix/sysv/linux/sigsetops.h.html#_M/__sigmask
# define sigmask(sig) \
  (((unsigned long int) 1) << (((sig) - 1) % (8 * sizeof(unsigned long int))))

#define set_errno(val) (errno = (val))

struct timespec {
	long	tv_sec;		/* seconds */
	long	tv_nsec;	/* nanoseconds */
};

struct timeval {
	long	tv_sec;		/* seconds */
	long	tv_usec;	/* microseconds */
};

struct timezone {
	int	tz_minuteswest;	/* minutes west of Greenwich */
	int	tz_dsttime;	/* type of DST correction */
};

typedef void (*sighandler_t)(int);
typedef void (*sigrestore_t)(void);

typedef struct {
	unsigned long sig[1];
} sigset_t;

struct sigaction {
	sighandler_t sa_handler;
	unsigned long sa_flags;
	sigrestore_t sa_restorer;
	sigset_t sa_mask;
};

typedef struct jmp_buf_s {
	long long reg[8];
	sigset_t mask;
} jmp_buf[1];

/* system calls */
long sys_alarm(unsigned int seconds);
long sys_write(int fd, const void *buf, size_t count);
long sys_pause();
long sys_nanosleep(struct timespec *rqtp, struct timespec *rmtp);
long sys_exit(int error_code) __attribute__ ((noreturn));

long sys_rt_sigaction(int sig, struct sigaction *act, struct sigaction *oact, size_t sigsetsize);
long sys_rt_sigprocmask(int how, const sigset_t *set, sigset_t *oset, size_t sigsetsize);
long sys_rt_sigpending(sigset_t *set, size_t sigsetsize);

/* wrappers */
int setjmp(jmp_buf env);
void longjmp(jmp_buf env, int val);

sighandler_t signal(int signum, sighandler_t handler);
int sigaction(int signum, struct sigaction *act, struct sigaction *oldact);
void myrt();

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
int sigpending(sigset_t *set);
int sigemptyset(sigset_t *set);
int sigfillset(sigset_t *set);
int sigaddset (sigset_t *set, int sig);
int sigdelset (sigset_t *set, int sig);
int sigismember(const sigset_t *set, int sig);

unsigned int alarm(unsigned int sec);
ssize_t	write(int fd, const void *buf, size_t count);
int pause();
unsigned int sleep(unsigned int s);
void    exit(int error_code);
size_t strlen(const char *s);

void *memset(void *s, int val, size_t size);
void perror(const char *prefix);

#endif	/* __LIBMINI_H__ */