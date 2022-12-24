/* base on the sample code of the class */
#include "libmini.h"

long errno;

#define	WRAPPER_RETval(type)	errno = 0; if(ret < 0) { errno = -ret; return -1; } return ((type) ret);
#define	WRAPPER_RETptr(type)	errno = 0; if(ret < 0) { errno = -ret; return NULL; } return ((type) ret);

// Ref: https://code.woboq.org/userspace/glibc/sysdeps/posix/signal.c.html
sighandler_t signal(int signum, sighandler_t handler){
	struct sigaction act, oact;
	if (handler == SIG_ERR || signum < 1 || signum >= NSIG){
    	set_errno(EINVAL);
      	return SIG_ERR;
    }
	act.sa_handler = handler;
  	sigemptyset(&act.sa_mask);
  	sigaddset(&act.sa_mask, signum);
  	act.sa_flags = SA_RESTART;
  	if (sigaction (signum, &act, &oact) < 0)
    	return SIG_ERR;
  	return oact.sa_handler;
}

int sigaction(int signum, struct sigaction *act, struct sigaction *oldact){
	act->sa_flags |= SA_RESTORER;
	act->sa_restorer = myrt;
	long ret = sys_rt_sigaction(signum, act, oldact, sizeof(sigset_t));
	WRAPPER_RETval(int);
}

// Ref: https://code.woboq.org/userspace/glibc/sysdeps/unix/sysv/linux/x86_64/sigprocmask.c.html
int sigprocmask(int how, const sigset_t *set, sigset_t *oldset){
	long ret = sys_rt_sigprocmask(how, set, oldset, NSIG/8);
	WRAPPER_RETval(int);
}

// Ref: https://code.woboq.org/userspace/glibc/sysdeps/unix/sysv/linux/sigpending.c.html
int sigpending(sigset_t *set){
	long ret = sys_rt_sigpending(set, NSIG/8);
	WRAPPER_RETval(int);
}

// Ref: https://code.woboq.org/userspace/glibc/signal/sigempty.c.html
int sigemptyset(sigset_t *set){
	if(set == NULL){
		set_errno(EINVAL);
		return -1;
	}
	memset (set, 0, sizeof (sigset_t));
	return 0;
}

// Ref: https://code.woboq.org/userspace/glibc/signal/sigfillset.c.html
int sigfillset(sigset_t *set){
	if(set == NULL){
		set_errno(EINVAL);
		return -1;
	}
	memset (set, 0xff, sizeof (sigset_t));
	return 0;
}

// Ref: https://code.woboq.org/userspace/glibc/signal/sigaddset.c.html
int sigaddset (sigset_t *set, int sig){
	if (set == NULL || sig <= 0 || sig >= NSIG){
      set_errno(EINVAL);
      return -1;
    }
	set->sig[0] |= sigmask(sig);
	return 0;
}

// Ref: https://code.woboq.org/userspace/glibc/signal/sigdelset.c.html
int sigdelset (sigset_t *set, int sig){
	if (set == NULL || sig <= 0 || sig >= NSIG){
      set_errno(EINVAL);
      return -1;
    }
	set->sig[0] &= ~sigmask(sig);
	return 0;
}

// Ref: https://code.woboq.org/userspace/glibc/signal/sigismem.c.html
int sigismember(const sigset_t *set, int sig){
	if (set == NULL || sig <= 0 || sig >= NSIG){
      set_errno(EINVAL);
      return -1;
    }
	return (set->sig[0] & sigmask(sig)) ? 1 : 0;
}

unsigned int alarm(unsigned int sec) {
    long ret = sys_alarm(sec);
    WRAPPER_RETval(unsigned int);
}

ssize_t	write(int fd, const void *buf, size_t count) {
	long ret = sys_write(fd, buf, count);
	WRAPPER_RETval(ssize_t);
}

int	pause() {
	long ret = sys_pause();
	WRAPPER_RETval(int);
}

unsigned int sleep(unsigned int seconds) {
	long ret;
	struct timespec req, rem;
	req.tv_sec = seconds;
	req.tv_nsec = 0;
	ret = sys_nanosleep(&req, &rem);
	if(ret >= 0) return ret;
	if(ret == -EINTR) {
		return rem.tv_sec;
	}
	return 0;
}

void exit(int error_code) {
	sys_exit(error_code);
	/* never returns? */
}

size_t strlen(const char *s) {
	size_t count = 0;
	while(*s++) count++;
	return count;
}

void *memset(void *s, int val, size_t size) {
    char *ptr = (char *) s;
    while(size-- > 0) *ptr++ = val;
    return s;
}

#define	PERRMSG_MIN	0
#define	PERRMSG_MAX	34

static const char *errmsg[] = {
	"Success",
	"Operation not permitted",
	"No such file or directory",
	"No such process",
	"Interrupted system call",
	"I/O error",
	"No such device or address",
	"Argument list too long",
	"Exec format error",
	"Bad file number",
	"No child processes",
	"Try again",
	"Out of memory",
	"Permission denied",
	"Bad address",
	"Block device required",
	"Device or resource busy",
	"File exists",
	"Cross-device link",
	"No such device",
	"Not a directory",
	"Is a directory",
	"Invalid argument",
	"File table overflow",
	"Too many open files",
	"Not a typewriter",
	"Text file busy",
	"File too large",
	"No space left on device",
	"Illegal seek",
	"Read-only file system",
	"Too many links",
	"Broken pipe",
	"Math argument out of domain of func",
	"Math result not representable"
};

void perror(const char *prefix) {
	const char *unknown = "Unknown";
	long backup = errno;
	if(prefix) {
		write(2, prefix, strlen(prefix));
		write(2, ": ", 2);
	}
	if(errno < PERRMSG_MIN || errno > PERRMSG_MAX) write(2, unknown, strlen(unknown));
	else write(2, errmsg[backup], strlen(errmsg[backup]));
	write(2, "\n", 1);
	return;
}