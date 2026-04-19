package gate

import (
	"encoding/binary"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// Linux struct linux_dirent64 wire layout (include/uapi/linux/dirent.h):
//
//	u64  d_ino;     // 8
//	s64  d_off;     // 8
//	u16  d_reclen;  // 2
//	u8   d_type;    // 1
//	char d_name[];  // NUL-terminated; record padded to 8-byte alignment
//
// direntHeaderSize is the fixed prefix (19 bytes); the rest is the
// name plus zero-padding.
const direntHeaderSize = 19

// d_type values from include/uapi/linux/dirent.h. Only the ones we
// actually emit are listed.
const (
	dtUnknown = 0
	dtFifo    = 1
	dtChr     = 2
	dtDir     = 4
	dtBlk     = 6
	dtReg     = 8
	dtLnk     = 10
	dtSock    = 12
)

// dirEntry is a materialised directory entry on its way into a
// linux_dirent64 record. Kept minimal — userspace rarely cares about
// d_ino; we hand out an increasing counter instead of trying to
// preserve real inode numbers across the overlay (the two layers have
// independent inode spaces anyway).
type dirEntry struct {
	name  string
	dtype uint8
	ino   uint64
}

// appendDirent serialises one entry onto buf. off is the d_off field
// — Linux uses it as an opaque seek cookie and most userspace ignores
// it, so we hand out a running byte offset.
func appendDirent(buf []byte, e dirEntry, off uint64) []byte {
	// name length + NUL, total record padded to 8-byte alignment.
	nameLen := len(e.name) + 1
	recLen := direntHeaderSize + nameLen
	recLen = (recLen + 7) &^ 7

	rec := make([]byte, recLen)
	binary.LittleEndian.PutUint64(rec[0:8], e.ino)
	binary.LittleEndian.PutUint64(rec[8:16], off)
	binary.LittleEndian.PutUint16(rec[16:18], uint16(recLen))
	rec[18] = e.dtype
	copy(rec[direntHeaderSize:], e.name)
	// NUL terminator and pad bytes already zero from make.
	return append(buf, rec...)
}

// modeToDType maps an os.FileMode (as returned by os.DirEntry.Type or
// os.FileInfo.Mode) to a Linux DT_* constant. Unknown bits fall back
// to DT_UNKNOWN so userspace always gets a valid d_type (0).
func modeToDType(m fs.FileMode) uint8 {
	switch {
	case m&fs.ModeDir != 0:
		return dtDir
	case m&fs.ModeSymlink != 0:
		return dtLnk
	case m&fs.ModeNamedPipe != 0:
		return dtFifo
	case m&fs.ModeSocket != 0:
		return dtSock
	case m&fs.ModeCharDevice != 0:
		return dtChr
	case m&fs.ModeDevice != 0:
		return dtBlk
	case m.IsRegular():
		return dtReg
	default:
		return dtUnknown
	}
}

// dirSnapshot is a pre-built linux_dirent64 stream for a directory
// guest fd, plus the read cursor. Snapshot-at-open semantics are
// slightly off from Linux — mutations after open are invisible to
// this fd — but userspace readdir loops don't notice in practice, and
// the alternative (incremental overlay merging) is a lot more code
// for no observable benefit.
type dirSnapshot struct {
	buf []byte
	off int
}

// buildDirSnapshot reads one or both overlay layers for absGuest and
// returns a serialised linux_dirent64 stream that respects whiteouts,
// opaque markers, and upper-shadows-lower precedence.
//
// absGuest is the guest-visible absolute path; the function locates
// the host-side upper/lower counterparts itself. A nil return with a
// nil error means "snapshot doesn't apply" — the caller should fall
// back to passthrough getdents64 on the host fd (e.g. when neither
// layer actually has this path as a directory).
func buildDirSnapshot(d *Dispatcher, absGuest string) ([]byte, error) {
	clean := filepath.Clean(absGuest)

	var upperDir, lowerDir string
	if d.FS.policy.UpperDir != "" {
		upperDir = filepath.Join(d.FS.policy.UpperDir, clean)
	}
	if d.FS.policy.LowerDir != "" {
		lowerDir = filepath.Join(d.FS.policy.LowerDir, clean)
	}

	upperExists := false
	if upperDir != "" {
		if info, err := os.Stat(upperDir); err == nil && info.IsDir() {
			upperExists = true
		}
	}
	lowerExists := false
	if lowerDir != "" {
		if info, err := os.Stat(lowerDir); err == nil && info.IsDir() {
			lowerExists = true
		}
	}
	if !upperExists && !lowerExists {
		return nil, nil
	}

	// Entries we'll emit, in order. `.` and `..` first, then upper,
	// then lower-unique. The kernel doesn't actually guarantee this
	// ordering but most userspace doesn't care, and sort stability
	// between test runs is the real property we need.
	var entries []dirEntry
	seen := map[string]bool{}
	whiteouts := map[string]bool{}
	ino := uint64(1)

	entries = append(entries, dirEntry{name: ".", dtype: dtDir, ino: ino})
	ino++
	seen["."] = true
	entries = append(entries, dirEntry{name: "..", dtype: dtDir, ino: ino})
	ino++
	seen[".."] = true

	opaque := false
	if upperExists {
		opaque = isOpaqueDir(upperDir)
		es, err := os.ReadDir(upperDir)
		if err != nil {
			return nil, err
		}
		for _, e := range es {
			name := e.Name()
			full := filepath.Join(upperDir, name)
			info, err := os.Lstat(full)
			if err != nil {
				continue
			}
			if isWhiteoutPath(full, info) {
				whiteouts[name] = true
				continue
			}
			if seen[name] {
				continue
			}
			entries = append(entries, dirEntry{
				name:  name,
				dtype: modeToDType(info.Mode()),
				ino:   ino,
			})
			seen[name] = true
			ino++
		}
	}
	if lowerExists && !opaque {
		es, err := os.ReadDir(lowerDir)
		if err != nil {
			return nil, err
		}
		for _, e := range es {
			name := e.Name()
			if seen[name] || whiteouts[name] {
				continue
			}
			info, err := os.Lstat(filepath.Join(lowerDir, name))
			if err != nil {
				continue
			}
			entries = append(entries, dirEntry{
				name:  name,
				dtype: modeToDType(info.Mode()),
				ino:   ino,
			})
			seen[name] = true
			ino++
		}
	}

	buf := make([]byte, 0, 64*len(entries))
	for _, e := range entries {
		buf = appendDirent(buf, e, uint64(len(buf))+1)
	}
	return buf, nil
}

// serveDirSnapshot hands out the next chunk of the snapshot that
// fits in count bytes, aligned on record boundaries, and advances
// the cursor. Returns (nil, 0) at EOF. Returns (_, syscall.EINVAL)
// when count is too small to fit even the first remaining record —
// that's what getdents64(2) does when passed a buffer smaller than
// sizeof(struct linux_dirent64) + d_namlen.
func serveDirSnapshot(s *dirSnapshot, count int) ([]byte, syscall.Errno) {
	if s.off >= len(s.buf) {
		return nil, 0
	}
	remaining := s.buf[s.off:]
	taken := 0
	for taken < len(remaining) {
		if taken+direntHeaderSize > len(remaining) {
			break
		}
		recLen := int(binary.LittleEndian.Uint16(remaining[taken+16 : taken+18]))
		if recLen == 0 || taken+recLen > len(remaining) {
			break
		}
		if taken+recLen > count {
			break
		}
		taken += recLen
	}
	if taken == 0 {
		return nil, syscall.EINVAL
	}
	out := remaining[:taken]
	s.off += taken
	return out, 0
}
