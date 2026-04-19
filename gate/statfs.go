package gate

import (
	"encoding/binary"
	"syscall"
)

// AArch64 struct statfs64 wire format (asm-generic/statfs.h — the
// shape the statfs(2)/fstatfs(2) syscalls write on arm64/riscv/etc).
// 120 bytes, all little-endian u64 except the two i32 fsid halves:
//
//	0   +8   f_type
//	8   +8   f_bsize
//	16  +8   f_blocks
//	24  +8   f_bfree
//	32  +8   f_bavail
//	40  +8   f_files
//	48  +8   f_ffree
//	56  +8   f_fsid         (two __s32 — val[0], val[1])
//	64  +8   f_namelen
//	72  +8   f_frsize
//	80  +8   f_flags
//	88  +32  f_spare[4]     (zeroed)
//
// We serialise explicitly instead of reinterpret-casting Go's
// syscall.Statfs_t because that struct's layout tracks the HOST arch.
// Sizes match on amd64 and arm64 by coincidence, but field signedness
// differs and the guest is always arm64 regardless of test host.
const aarch64StatfsSize = 120

func packStatfsAarch64(st *syscall.Statfs_t) []byte {
	buf := make([]byte, aarch64StatfsSize)
	le := binary.LittleEndian
	le.PutUint64(buf[0:], uint64(st.Type))
	le.PutUint64(buf[8:], uint64(st.Bsize))
	le.PutUint64(buf[16:], st.Blocks)
	le.PutUint64(buf[24:], st.Bfree)
	le.PutUint64(buf[32:], st.Bavail)
	le.PutUint64(buf[40:], st.Files)
	le.PutUint64(buf[48:], st.Ffree)
	le.PutUint32(buf[56:], uint32(st.Fsid.X__val[0]))
	le.PutUint32(buf[60:], uint32(st.Fsid.X__val[1]))
	le.PutUint64(buf[64:], uint64(st.Namelen))
	le.PutUint64(buf[72:], uint64(st.Frsize))
	le.PutUint64(buf[80:], uint64(st.Flags))
	return buf
}
