package gate

import (
	"errors"
	"syscall"
)

// MaxPathLen caps the length of any guest path we copy out through
// PathReader. Linux PATH_MAX is 4096 including the trailing NUL, so we
// use that as the ceiling: longer strings are refused with EFAULT
// rather than being silently truncated.
const MaxPathLen = 4096

// EncodeErrno packs err into the value the aarch64 kernel returns in
// x0 on syscall exit: 0 on success, or a small negative integer on
// failure (the kernel ABI guarantees errno fits in [1, 4095], so -errno
// never collides with a legitimate pointer return value).
//
// Handlers call this to set regs.X[0] from a Go error, e.g.
//
//	regs.X[0] = EncodeErrno(err)
//	return VerdictHandled
//
// Nil error yields 0 (success).
func EncodeErrno(err error) uint64 {
	if err == nil {
		return 0
	}
	return uint64(int64(-int(errnoFor(err))))
}

// errnoFor maps a Go error to a Linux errno. Gate-specific sentinels
// take precedence over wrapped syscall.Errno values so that e.g. an
// ErrEscape wrapping a deeper syscall error still surfaces as ENOENT
// (the guest must not learn why the escape was blocked — only that
// the path does not exist from its point of view).
func errnoFor(err error) syscall.Errno {
	if err == nil {
		return 0
	}
	switch {
	case errors.Is(err, ErrFault):
		return syscall.EFAULT
	case errors.Is(err, ErrEscape), errors.Is(err, ErrWhiteout):
		return syscall.ENOENT
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno
	}
	// Unknown Go error — surface a generic I/O error rather than a
	// plausible-but-wrong syscall result.
	return syscall.EIO
}
