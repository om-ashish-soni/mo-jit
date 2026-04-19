package gate

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestEncodeErrnoNilIsZero(t *testing.T) {
	if got := EncodeErrno(nil); got != 0 {
		t.Errorf("EncodeErrno(nil) = %#x, want 0", got)
	}
}

func TestEncodeErrnoNegativeInAArch64Wire(t *testing.T) {
	got := EncodeErrno(syscall.EFAULT)
	// Break the constant chain so the compiler does not reject
	// `-EFAULT` as an unsigned constant overflow.
	ef := syscall.EFAULT
	want := uint64(int64(-int(ef)))
	if got != want {
		t.Errorf("EncodeErrno(EFAULT) = %#x, want %#x", got, want)
	}
	// Sanity: reinterpreting the uint64 as int64 must be negative and
	// in the kernel's -errno window (-4095, 0).
	s := int64(got)
	if s >= 0 || s < -4095 {
		t.Errorf("EFAULT encoded as %d, outside kernel -errno window (-4095, 0)", s)
	}
}

func TestErrnoForGateSentinels(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want syscall.Errno
	}{
		{"ErrFault", ErrFault, syscall.EFAULT},
		{"ErrEscape", ErrEscape, syscall.ENOENT},
		{"ErrWhiteout", ErrWhiteout, syscall.ENOENT},
		{"wrapped ErrFault", fmt.Errorf("ctx: %w", ErrFault), syscall.EFAULT},
		{"wrapped ErrEscape", fmt.Errorf("ctx: %w", ErrEscape), syscall.ENOENT},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := errnoFor(tc.err); got != tc.want {
				t.Errorf("errnoFor(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestErrnoForSyscallErrno(t *testing.T) {
	if got := errnoFor(syscall.ENOTDIR); got != syscall.ENOTDIR {
		t.Errorf("errnoFor(ENOTDIR) = %v, want ENOTDIR", got)
	}
}

func TestErrnoForPathErrorUnwrapsToErrno(t *testing.T) {
	// Trigger a real path error from the OS so the wrapping matches
	// production code (os.Stat etc. wrap syscall.Errno in *fs.PathError).
	tmp := t.TempDir()
	_, err := os.Stat(filepath.Join(tmp, "does-not-exist"))
	if err == nil {
		t.Fatal("expected stat error on missing path")
	}
	var pe *fs.PathError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *fs.PathError, got %T", err)
	}
	if got := errnoFor(err); got != syscall.ENOENT {
		t.Errorf("errnoFor(os.Stat missing) = %v, want ENOENT", got)
	}
}

func TestErrnoForUnknownErrorFallsBackToEIO(t *testing.T) {
	got := errnoFor(errors.New("some random failure"))
	if got != syscall.EIO {
		t.Errorf("errnoFor(unknown) = %v, want EIO", got)
	}
}

// Gate sentinels must win over a wrapped Errno so the guest never
// learns why ErrEscape fired — only that the path does not exist.
func TestErrnoForGateSentinelBeatsWrappedErrno(t *testing.T) {
	err := fmt.Errorf("%w: blocked under %w", ErrEscape, syscall.EACCES)
	if got := errnoFor(err); got != syscall.ENOENT {
		t.Errorf("ErrEscape wrapping EACCES: got %v, want ENOENT", got)
	}
}
