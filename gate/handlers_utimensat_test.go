package gate

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// packTimespecPair encodes two timespecs as the kernel wants them in
// the times pointer: atime tv_sec, tv_nsec, mtime tv_sec, tv_nsec.
func packTimespecPair(aSec, aNsec, mSec, mNsec int64) []byte {
	buf := make([]byte, 32)
	binary.LittleEndian.PutUint64(buf[0:8], uint64(aSec))
	binary.LittleEndian.PutUint64(buf[8:16], uint64(aNsec))
	binary.LittleEndian.PutUint64(buf[16:24], uint64(mSec))
	binary.LittleEndian.PutUint64(buf[24:32], uint64(mNsec))
	return buf
}

func newUtimensatHarness(t *testing.T, withUpper bool) (*Dispatcher, *FakePathReader, *FakeMemReader) {
	t.Helper()
	pol := Policy{LowerDir: t.TempDir()}
	if withUpper {
		pol.UpperDir = t.TempDir()
	}
	d := NewDispatcher(pol)
	paths := &FakePathReader{Entries: map[uint64]string{}}
	mr := &FakeMemReader{}
	d.Paths = paths
	d.MemR = mr
	return d, paths, mr
}

func TestUtimensatSetsAtimeMtime(t *testing.T) {
	d, paths, mr := newUtimensatHarness(t, true)
	path := filepath.Join(d.FS.policy.UpperDir, "f")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	paths.Entries[0x9100] = "/f"
	mr.Stage(0x9200, packTimespecPair(1_700_000_000, 0, 1_700_000_500, 123))

	regs := &Regs{NR: SysUtimensAt}
	regs.X[0] = atFDCWDAsX0()
	regs.X[1] = 0x9100
	regs.X[2] = 0x9200
	regs.X[3] = 0
	d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("utimensat returned %d, want 0", int64(regs.X[0]))
	}
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	if st.Atim.Sec != 1_700_000_000 {
		t.Errorf("atime sec = %d, want 1700000000", st.Atim.Sec)
	}
	if st.Mtim.Sec != 1_700_000_500 || st.Mtim.Nsec != 123 {
		t.Errorf("mtime = %d.%d, want 1700000500.123", st.Mtim.Sec, st.Mtim.Nsec)
	}
}

func TestUtimensatNullTimesUsesNow(t *testing.T) {
	d, paths, _ := newUtimensatHarness(t, true)
	path := filepath.Join(d.FS.policy.UpperDir, "now")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Set timestamps far in the past first.
	past := time.Unix(1_000_000_000, 0)
	if err := os.Chtimes(path, past, past); err != nil {
		t.Fatal(err)
	}

	paths.Entries[0x9300] = "/now"
	regs := &Regs{NR: SysUtimensAt}
	regs.X[0] = atFDCWDAsX0()
	regs.X[1] = 0x9300
	regs.X[2] = 0 // NULL times → use current time
	regs.X[3] = 0
	d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("utimensat returned %d, want 0", int64(regs.X[0]))
	}
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	if st.Mtim.Sec < time.Now().Unix()-5 {
		t.Errorf("mtime = %d, expected recent (within 5s)", st.Mtim.Sec)
	}
}

func TestUtimensatCopiesUpLowerFile(t *testing.T) {
	d, paths, mr := newUtimensatHarness(t, true)
	lower := filepath.Join(d.FS.policy.LowerDir, "lib.so")
	if err := os.WriteFile(lower, []byte("BINARY"), 0o444); err != nil {
		t.Fatal(err)
	}
	past := time.Unix(100_000_000, 0)
	if err := os.Chtimes(lower, past, past); err != nil {
		t.Fatal(err)
	}

	paths.Entries[0x9400] = "/lib.so"
	mr.Stage(0x9500, packTimespecPair(1_800_000_000, 0, 1_800_000_000, 0))

	regs := &Regs{NR: SysUtimensAt}
	regs.X[0] = atFDCWDAsX0()
	regs.X[1] = 0x9400
	regs.X[2] = 0x9500
	regs.X[3] = 0
	d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("utimensat returned %d, want 0", int64(regs.X[0]))
	}

	// Lower unchanged.
	var stL syscall.Stat_t
	if err := syscall.Stat(lower, &stL); err != nil {
		t.Fatal(err)
	}
	if stL.Mtim.Sec != 100_000_000 {
		t.Errorf("lower mtime changed: %d", stL.Mtim.Sec)
	}
	// Upper copy has the new mtime.
	upper := filepath.Join(d.FS.policy.UpperDir, "lib.so")
	var stU syscall.Stat_t
	if err := syscall.Stat(upper, &stU); err != nil {
		t.Fatalf("upper copy missing: %v", err)
	}
	if stU.Mtim.Sec != 1_800_000_000 {
		t.Errorf("upper mtime = %d, want 1800000000", stU.Mtim.Sec)
	}
}

func TestUtimensatMissingFileIsENOENT(t *testing.T) {
	d, paths, _ := newUtimensatHarness(t, true)
	paths.Entries[0x9600] = "/nope"
	regs := &Regs{NR: SysUtimensAt}
	regs.X[0] = atFDCWDAsX0()
	regs.X[1] = 0x9600
	regs.X[2] = 0
	regs.X[3] = 0
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.ENOENT)
}

func TestUtimensatNullPathIsENOSYS(t *testing.T) {
	// futimens-style dispatch isn't wired up yet.
	d, _, _ := newUtimensatHarness(t, true)
	regs := &Regs{NR: SysUtimensAt}
	regs.X[0] = atFDCWDAsX0()
	regs.X[1] = 0 // NULL path
	regs.X[2] = 0
	regs.X[3] = 0
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.ENOSYS)
}

func TestUtimensatSymlinkNoFollowIsENOSYS(t *testing.T) {
	d, paths, _ := newUtimensatHarness(t, true)
	paths.Entries[0x9700] = "/x"
	regs := &Regs{NR: SysUtimensAt}
	regs.X[0] = atFDCWDAsX0()
	regs.X[1] = 0x9700
	regs.X[2] = 0
	regs.X[3] = uint64(atSymlinkNoFollow)
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.ENOSYS)
}

func TestUtimensatNoUpperDirIsEROFS(t *testing.T) {
	d, paths, _ := newUtimensatHarness(t, false)
	paths.Entries[0x9800] = "/x"
	regs := &Regs{NR: SysUtimensAt}
	regs.X[0] = atFDCWDAsX0()
	regs.X[1] = 0x9800
	regs.X[2] = 0
	regs.X[3] = 0
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EROFS)
}
