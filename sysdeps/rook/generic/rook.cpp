#include <mlibc/fsfd_target.hpp>
#include <mlibc/all-sysdeps.hpp>
#include <abi-bits/errno.h>
#include <termios.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <string.h>

#include "rook/syscall.h"
#include "rook/syscalls.h"

#define STUB_BODY(msg)            \
	{                             \
		mlibc::sys_libc_log(msg); \
		*((int *)0) = 0;          \
		while (1)                 \
			;                     \
	}

#define ARCH_SET_FS 0x1000

#define TCGETS 0x5401
#define TCSETS 0x5402

namespace mlibc
{

	void sys_libc_log(const char *message)
	{
		syscall1(SYS_LOG, message);
	}

	[[noreturn]] void sys_libc_panic()
	{
		sys_libc_log("mlibc panic\n");
		*((int *)0) = 0;
		while (1)
			;
	}

	int sys_tcb_set(void *pointer)
	{
		int64_t res = (int64_t)syscall2(SYS_ARCH_CTL, ARCH_SET_FS, pointer);

		if (res < 0)
		{
			return -(int)res;
		}

		return res;
	}

	int sys_futex_wait(int *pointer, int expected, const struct timespec *time) STUB_BODY("sys_futex_wait unimplemented\n") int sys_futex_wake(int *pointer) STUB_BODY("sys_futex_wake unimplemented\n")

		int sys_anon_allocate(size_t size, void **pointer)
	{
		// TODO
		return sys_vm_map(NULL, size, 0, 0, -1, 0, pointer);
	}

	int sys_anon_free(void *pointer, size_t size) STUB_BODY("sys_anon_free unimplemented\n")

		int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf)
	{
		long long res = syscall3(SYS_FSTATAT, fd, path, statbuf);

		if (res < 0)
		{
			return -(int)res;
		}

		return res;
	}

	// mlibc assumes that anonymous memory returned by sys_vm_map() is zeroed by the kernel / whatever is behind the sysdeps
	int sys_vm_map(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window)
	{
		// TODO
		int64_t res = (int64_t)syscall6(SYS_MMAP, hint, size, prot, flags, fd, offset);

		if (res < 0)
		{
			return -(int)res;
		}

		void *ptr = (void *)res;

		// TODO: maybe no memset
		memset(ptr, 0, size);

		*window = ptr;
		return 0;
	}

	int sys_vm_unmap(void *pointer, size_t size) STUB_BODY("sys_vm_unmap unimplemented\n")
		[[gnu::weak]] int sys_vm_protect(void *pointer, size_t size, int prot) STUB_BODY("sys_vm_protect unimplemented\n")

			[[noreturn]] void sys_exit(int status) STUB_BODY("sys_exit unimplemented\n")

				int sys_clock_get(int clock, time_t *secs, long *nanos)
	{
		struct timeval tv;
		long long res = syscall2(SYS_GETTIMEOFDAY, &tv, NULL);

		*secs = tv.tv_sec;
		*nanos = tv.tv_usec * 1000;

		if (res < 0)
		{
			return -(int)res;
		}

		return 0;
	}

	int sys_open(const char *pathname, int flags, mode_t mode, int *fd)
	{
		long long res = syscall4(SYS_OPENAT, AT_FDCWD, pathname, flags, mode);

		if (res < 0)
		{
			return -(int)res;
		}

		*fd = (int)res;
		return 0;
	}

	int sys_read(int fd, void *buf, size_t count, ssize_t *bytes_read)
	{
		long long res = syscall3(SYS_READ, fd, buf, count);

		if (res < 0)
		{
			return -(int)res;
		}

		*bytes_read = (ssize_t)res;
		return 0;
	}

	int sys_write(int fd, const void *buf, size_t count, ssize_t *bytes_written)
	{
		long long res = syscall3(SYS_WRITE, fd, buf, count);

		if (res < 0)
		{
			return -(int)res;
		}

		*bytes_written = (ssize_t)res;
		return 0;
	}

	int sys_seek(int fd, off_t offset, int whence, off_t *new_offset)
	{
		long long res = syscall3(SYS_LSEEK, fd, offset, whence);

		if (res < 0)
		{
			return (int)-res;
		}

		*new_offset = (off_t)res;
		return 0;
	}

	int sys_close(int fd)
	{
		long long res = syscall1(SYS_CLOSE, fd);

		if (res < 0)
		{
			return (int)-res;
		}

		return 0;
	}

	// In contrast to the isatty() library function, the sysdep function uses return value
	// zero (and not one) to indicate that the file is a terminal.
	int sys_isatty(int fd)
	{
		// TODO: proper implementation

		if (fd < 3)
		{
			return 0;
		}
		else
		{
			return ENOTTY;
		}
	}

	int sys_ttyname(int fd, char *buf, size_t size)
	{
		// TODO: proper implementation

		if (sys_isatty(fd) < 0)
			return ENOTTY;

		strcpy(buf, "/dev/console");
		return 0;
	}

	gid_t sys_getgid()
	{
		return syscall0(SYS_GETGID);
	}

	gid_t sys_getegid()
	{
		return syscall0(SYS_GETEGID);
	}

	uid_t sys_getuid()
	{
		return syscall0(SYS_GETUID);
	}

	uid_t sys_geteuid()
	{
		return syscall0(SYS_GETEUID);
	}

	pid_t sys_getpid()
	{
		return syscall0(SYS_GETPID);
	}

	pid_t sys_getppid()
	{
		return syscall0(SYS_GETPPID);
	}

	int sys_getcwd(char *buffer, size_t size)
	{
		long long res = syscall2(SYS_GETCWD, buffer, size);

		if (res != 0)
		{
			return -(int)res;
		}

		return 0;
	}

	pid_t sys_getpgid(pid_t pid, pid_t *pgid)
	{
		long long res = syscall1(SYS_GETPGID, pid);

		if (res < 0)
		{
			return -(int)res;
		}

		*pgid = res;

		return 0;
	}

	int sys_ioctl(int fd, unsigned long request, void *arg, int *result)
	{
		long long res = syscall3(SYS_IOCTL, fd, request, arg);

		if (res < 0)
		{
			return -(int)res;
		}

		*result = res;

		return 0;
	}

	int sys_fcntl(int fd, int request, va_list args, int *result)
	{
		long long res = syscall3(SYS_FCNTL, fd, request, va_arg(args, uint64_t));

		if (res < 0)
		{
			return -(int)res;
		}

		*result = res;

		return 0;
	}

	int sys_gethostname(char *buffer, size_t bufsize)
	{
		strcpy(buffer, "test");
		return 0;
	}

	int sys_tcgetattr(int fd, struct termios *attr)
	{
		int result;
		return (int)sys_ioctl(fd, TCGETS, (void *)attr, &result);
	}

	int sys_tcsetattr(int fd, int optional_action, const struct termios *attr)
	{
		// TODO: optional action
		int result;
		return (int)sys_ioctl(fd, TCSETS, (void *)attr, &result);
	}

	int sys_pselect(int num_fds, fd_set *read_set, fd_set *write_set,
					fd_set *except_set, const struct timespec *timeout, const sigset_t *sigmask, int *num_events)
	{
		long long res = syscall6(SYS_PSELECT, num_fds, read_set, write_set, except_set, timeout, sigmask);

		if (res < 0)
		{
			return -(int)res;
		}

		*num_events = (int)res;
		return 0;
	}

	int sys_chdir(const char *path)
	{
		long long res = syscall1(SYS_CHDIR, path);
		if(res < 0) {
			return -(int)res;
		}

		return 0;
	}

}
