# Applying Landlock to the entire process

Before Landlock ABI v8, the Landlock kernel API enabled Landlock only
for the calling OS thread.  This is a problem in Go, because (a) Go is
inherently multithreaded, and (b) the mapping between (many)
goroutines and (fewer) OS threads changes dynamically.

Because the mapping between OS threads and Goroutines is not
guaranteed anyway, and because there is no good security boundary
between OS threads, the Go-Landlock API **always enables the given
Landlock policy for the entire process**.

Depending on the kernel ABI available on the running kernel,
Go-Landlock uses one of two possible approaches for process-wide
policy enforcement:

## `LANDLOCK_RESTRICT_SELF_TSYNC` (ABI V8+)

This flag for
[*landlock_restrict_self*(2)](https://man.gnoack.org/2/landlock_restrict_self)
was introduced in Landlock ABI V8 (Linux 7.0).

## `libpsx` (ABI < V8)

On Linux kernels prior to Landlock ABI V8 (Linux 7.0), Go-Landlock
uses the `psx` library.  `psx` exposes an API that does a system call
with the given arguments on *every OS thread* in a running Go program.

For pure Go programs, `psx` does the same as the
[`syscall.AllThreadsSyscall`
function](https://pkg.go.dev/syscall#AllThreadsSyscall) in the Go
runtime (and that case is straightforward to understand).

For programs linked with `cgo`, there can be more OS threads than just
the ones that were started by the Go runtime. To cover these, `psx`
intercepts calls to the pthread library to infer the list of all
threads, and then uses a trick with Unix signals to execute the given
system call on all of them. (This is unfortunately common practice for
system calls that only apply to the current thread -- glibc uses the
same approach for some system calls. To dig this up in the glibc
source, see `sysdeps/nptl/setxid.h` and its users.)

A deeper discussion of `psx` can be found at:
https://sites.google.com/site/fullycapable/who-ordered-libpsx

> [!TIP]
> By using the `landlocktsync` build constraint, Go-Landlock will only
> support Landlock ABI V8 and higher, effectively removing the
> dependency on `libpsx`.
