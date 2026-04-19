package gate

// This file mirrors the C ABI declared in gum/mojit_hook.h on the Go
// side. The two definitions MUST stay in lockstep. The CI C-ABI test
// (.github/workflows/ci.yml, job gum-c-abi) pins the C constants;
// this file pins the Go ones; and the cgo marshalling layer
// (landing alongside the frida-gum build in M1) converts between
// mojit_regs_t and Regs below.
//
// Every change to mojit_hook.h must bump MOJIT_HOOK_ABI_VERSION over
// there AND update the Verdict constants and Regs layout here.

// ABIVersion mirrors MOJIT_HOOK_ABI_VERSION in gum/mojit_hook.h. The
// cgo wrapper validates equality at registration time so a skew
// between the C half and the Go half fails loudly rather than
// silently misbehaving.
const ABIVersion = 0

// Verdict is the Go-side mirror of mojit_verdict_t from
// gum/mojit_hook.h. Values are identical on purpose — the cgo
// marshalling layer casts directly.
type Verdict int

const (
	// VerdictHandled — the handler produced a result; regs.X[0] holds
	// the return value (or -errno on failure, per Linux syscall
	// convention). The svc hook must NOT re-issue the kernel syscall.
	VerdictHandled Verdict = 0

	// VerdictPassthrough — the handler declines. gum issues the real
	// kernel svc #0 with the captured registers and writes the
	// kernel's return into regs.X[0]. Used for syscalls that are
	// safe to run unfiltered (futex, clock_gettime, getrandom — see
	// the whitelist in the default handler registration below).
	VerdictPassthrough Verdict = 1

	// VerdictKill — the handler detected a policy violation. gum
	// raises SIGSYS on the guest thread. seccomp-BPF is a redundant
	// backstop in case a svc slipped past the userspace hook.
	VerdictKill Verdict = 2
)

// String renders Verdict for logs and test diagnostics.
func (v Verdict) String() string {
	switch v {
	case VerdictHandled:
		return "handled"
	case VerdictPassthrough:
		return "passthrough"
	case VerdictKill:
		return "kill"
	default:
		return "unknown"
	}
}

// Regs is the Go-side mirror of mojit_regs_t from gum/mojit_hook.h.
// x[0..7] are the aarch64 syscall arguments (the Linux AArch64 ABI
// passes args in x0..x5 and rarely x6..x7; we carry all eight for
// future-proofness). NR is x8, the syscall number. PC and SP are
// the guest state at the svc instruction — the dispatcher may use
// them for tracing or policy enforcement (e.g. "all socket() calls
// MUST originate from inside the gate's code range").
type Regs struct {
	X  [8]uint64
	NR uint64
	PC uint64
	SP uint64
}

// Handler services a single intercepted syscall. On VerdictHandled
// the handler has already written the result into regs.X[0] (or a
// negative errno on failure). On VerdictPassthrough the handler
// leaves regs alone and signals gum to re-issue the kernel syscall.
type Handler = func(d *Dispatcher, regs *Regs) Verdict

// AArch64 Linux syscall numbers (generic syscall table —
// asm-generic/unistd.h). Guest ISA is always arm64, so these are
// platform-agnostic from mo-jit's perspective. Only the numbers the
// gate actively reasons about are listed; the rest default to
// passthrough when intercepted.
const (
	// File / path syscalls (arm64 generic table — the classic
	// open/stat/access/readlink/mkdir/unlink/rename numbers do NOT
	// exist on arm64; only the *at variants do).
	SysSetXattr     uint64 = 5
	SysFSetXattr    uint64 = 7
	SysGetXattr     uint64 = 8
	SysFGetXattr    uint64 = 10
	SysListXattr    uint64 = 11
	SysFListXattr   uint64 = 13
	SysRemoveXattr  uint64 = 14
	SysFRemoveXattr uint64 = 16
	SysGetCwd       uint64 = 17
	SysDup          uint64 = 23
	SysDup3         uint64 = 24
	SysFCntl        uint64 = 25
	SysIoctl        uint64 = 29
	SysMkdirAt      uint64 = 34
	SysUnlinkAt     uint64 = 35
	SysSymlinkAt    uint64 = 36
	SysLinkAt       uint64 = 37
	SysRenameAt     uint64 = 38
	SysStatFs       uint64 = 43
	SysFStatFs      uint64 = 44
	SysTruncate     uint64 = 45
	SysFTruncate    uint64 = 46
	SysFAccessAt    uint64 = 48
	SysChDir        uint64 = 49
	SysFChMod       uint64 = 52
	SysFChModAt     uint64 = 53
	SysFChOwnAt     uint64 = 54
	SysFChOwn       uint64 = 55
	SysOpenAt       uint64 = 56
	SysClose        uint64 = 57
	SysPipe2        uint64 = 59
	SysGetDents64   uint64 = 61
	SysLSeek        uint64 = 62
	SysRead         uint64 = 63
	SysWrite        uint64 = 64
	SysReadLinkAt   uint64 = 78
	SysNewFStatAt   uint64 = 79
	SysFStat        uint64 = 80
	SysUtimensAt    uint64 = 88
	SysRenameAt2    uint64 = 276
	SysFAccessAt2   uint64 = 439

	// Network syscalls.
	SysSocket      uint64 = 198
	SysBind        uint64 = 200
	SysListen      uint64 = 201
	SysAccept      uint64 = 202
	SysConnect     uint64 = 203
	SysGetSockName uint64 = 204
	SysGetPeerName uint64 = 205
	SysSendTo      uint64 = 206
	SysRecvFrom    uint64 = 207
	SysSetSockOpt  uint64 = 208
	SysGetSockOpt  uint64 = 209
	SysShutdown    uint64 = 210
	SysSendMsg     uint64 = 211
	SysRecvMsg     uint64 = 212
	SysAccept4     uint64 = 242
)
