// Package gate implements mo-jit's in-process syscall gate.
//
// The gate intercepts every syscall issued by the JIT-translated guest
// and routes it through three subsystems:
//
//   - fsgate: filesystem virtualization with userspace copy-on-write.
//   - netgate: network virtualization with socket redirection and DNS intercept.
//   - procmap: PID-tree scoping for /proc views.
//
// All gates run in-process with the gum code cache. The guest never
// issues a "bare" syscall to the kernel: every svc #0 instruction is
// redirected at translation time by gum, with seccomp-BPF installed at
// process start as a kernel-side belt-and-braces filter.
//
// See https://github.com/om-ashish-soni/mo-jit for the full runtime
// architecture and threat model.
package gate
