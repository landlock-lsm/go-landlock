# Go Landlock library

The Go-Landlock library restricts the current processes' ability to
use files, using Linux 5.13's Landlock feature. ([Package
documentation](https://pkg.go.dev/github.com/landlock-lsm/go-landlock/landlock))

## Goals

Goals of Go-Landlock are:

* Make unprivileged sandboxing easy to use and effective.
* Keep Go-Landlock's implementation at an easily auditable size.

## Technical implementation

Some implementation notes that should simplify auditing.

### Applying Landlock to all Goroutines

The Landlock kernel API enabled Landlock for the current OS thread,
but the mapping between Goroutines and OS threads is not 1:1, and
there are few guarantees about it.

Because the mapping between OS threads and Goroutines is not
guaranteed anyway, the Go-Landlock API always enables the given
Landlock for the entire process.

This is done using the `psx` library, which is a helper library for
the `libcap` library for working with Linux capabilities. `psx`
exposes an API that does a system call with the given arguments on
*every OS thread* in a running Go program.

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
