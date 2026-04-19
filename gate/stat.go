package gate

import (
	"encoding/binary"
	"syscall"
)

// AArch64 struct stat wire format (asm-generic/stat.h — shared across
// arm64, riscv, loongarch, and every arch using the generic syscall
// table). 128 bytes total, all little-endian:
//
//	0  +8   st_dev
//	8  +8   st_ino
//	16 +4   st_mode
//	20 +4   st_nlink
//	24 +4   st_uid
//	28 +4   st_gid
//	32 +8   st_rdev
//	40 +8   __pad1
//	48 +8   st_size
//	56 +4   st_blksize
//	60 +4   __pad2
//	64 +8   st_blocks
//	72 +8   st_atime.sec
//	80 +8   st_atime.nsec
//	88 +8   st_mtime.sec
//	96 +8   st_mtime.nsec
//	104+8   st_ctime.sec
//	112+8   st_ctime.nsec
//	120+4   __unused4
//	124+4   __unused5
//
// We marshal explicitly rather than reinterpret-casting Go's
// syscall.Stat_t because Go's layout matches the HOST arch; the guest
// always sees arm64. On an x86_64 test host the two layouts diverge
// even though field names are identical (Nlink is uint64 on x86_64,
// uint32 on arm64; Blksize is int64 vs int32; etc).
const aarch64StatSize = 128

// statFieldOff is exported so tests can decode packed blobs without
// copy-pasting the offsets.
const (
	statOffDev    = 0
	statOffIno    = 8
	statOffMode   = 16
	statOffNlink  = 20
	statOffUid    = 24
	statOffGid    = 28
	statOffRdev   = 32
	statOffSize   = 48
	statOffBlksz  = 56
	statOffBlocks = 64
	statOffAtim   = 72
	statOffMtim   = 88
	statOffCtim   = 104
)

// packStatAarch64 serialises st into the aarch64 kernel struct stat
// wire format. The returned slice is always aarch64StatSize bytes.
func packStatAarch64(st *syscall.Stat_t) []byte {
	buf := make([]byte, aarch64StatSize)
	le := binary.LittleEndian
	le.PutUint64(buf[statOffDev:], uint64(st.Dev))
	le.PutUint64(buf[statOffIno:], uint64(st.Ino))
	le.PutUint32(buf[statOffMode:], uint32(st.Mode))
	le.PutUint32(buf[statOffNlink:], uint32(st.Nlink))
	le.PutUint32(buf[statOffUid:], uint32(st.Uid))
	le.PutUint32(buf[statOffGid:], uint32(st.Gid))
	le.PutUint64(buf[statOffRdev:], uint64(st.Rdev))
	le.PutUint64(buf[statOffSize:], uint64(st.Size))
	le.PutUint32(buf[statOffBlksz:], uint32(st.Blksize))
	le.PutUint64(buf[statOffBlocks:], uint64(st.Blocks))
	le.PutUint64(buf[statOffAtim:], uint64(st.Atim.Sec))
	le.PutUint64(buf[statOffAtim+8:], uint64(st.Atim.Nsec))
	le.PutUint64(buf[statOffMtim:], uint64(st.Mtim.Sec))
	le.PutUint64(buf[statOffMtim+8:], uint64(st.Mtim.Nsec))
	le.PutUint64(buf[statOffCtim:], uint64(st.Ctim.Sec))
	le.PutUint64(buf[statOffCtim+8:], uint64(st.Ctim.Nsec))
	return buf
}

// AT_* flags shared across the *at syscalls. Defined here rather than
// relying on syscall.AT_* which isn't portable across Go stdlib
// versions for every constant we need.
const (
	atSymlinkNoFollow = 0x100  // AT_SYMLINK_NOFOLLOW
	atNoAutomount     = 0x800  // AT_NO_AUTOMOUNT (ignored — we don't automount)
	atEmptyPath       = 0x1000 // AT_EMPTY_PATH
)
