# Using Landlock with raw syscalls in Go

While we recommend using the
[official Go-Landlock library](https://github.com/landlock-lsm/go-landlock),
we acknowledge that some people choose not to for various reasons.

This document describes the Go peculiarities that you should look for
if you choose to use raw syscalls.

**Please add a comment with your rationale for not using
Go-Landlock**.  We suggest the phrasing "We do not use Go-Landlock
because...".  If your project is open source, this helps us track
missing features in Go-Landlock, which helps improve the Landlock
ecosystem.

We recommend to double check whether you have constraints on the Linux
versions (and Landlock ABI versions) on which your implementation
runs.  Common constraints are the kernels running in Cloud
environments and the phasing out of Linux longterm releases as
published on kernel.org.  If you can assume newer kernels, the
implementation becomes easier.

## The raw system calls

Landlock's three system calls are:

1. *landlock_create_ruleset*(2):
   Create a ruleset file descriptor,
   which represents a Landlock policy to enforce.
2. *landlock_add_rule*(2):
   Add rules to a ruleset, to build the Landlock policy.
3. *landlock_restrict_self*(2):
   Enforce the Landlock ruleset.

Additionally, *landlock_create_ruleset*(2) has the special flags
`LANDLOCK_CREATE_RULESET_VERSION` and
`LANDLOCK_CREATE_RULESET_ERRATA`.  In these modes, the system call
returns information about the Landlock features available with the
running Linux kernel.

See the [Linux Kernel Reference Documentation for
Landlock](https://docs.kernel.org/userspace-api/landlock.html), where
these system calls are described in more detail.

## Which use case do you have?

There are two main use cases, for which the implementation differs
slightly:

1. Sandboxing your own process
2. Sandboxing another process

In both use cases, the *construction of the ruleset*
(*landlock_create_ruleset*(2) and *landlock_add_rule*(2)) are the same
as in any other programming language.  In many cases, programs query
the available Landlock ABI version with
`LANDLOCK_CREATE_RULESET_VERSION` so that they can downgrade the
Landlock policy in line with what the running Linux kernel permits.

This is described in more detail in the Linux kernel documentation as
well.

### Case 1: Applying a Landlock policy to your own Go process

When using Landlock on a Go process, always make sure that *all
threads* are restricted.

**Rationale:** When invoked without any flags,
*landlock_restrict_self*(2) only applies the Landlock policy on the
calling *OS thread*.  But Go is an inherently multithreaded language
and a single Goroutine can change the OS thread on which it is
running.  Furthermore, as OS threads (and Goroutines) share memory,
there are no good security boundaries between them.

To restrict a Landlock ruleset across *all threads*, invoke *landlock_restrict_self*(2) system call with the folowing two flags:

* `LANDLOCK_RESTRICT_SELF_TSYNC` (since ABI v8, Linux 7.3):
  This enforces the policy on all threads of the current process.
* `LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS` (since ABI v11, Linux 7.0):
  This implicitly enables the per-thread "no new privs" flag, which is
  a prerequisite for Landlock enforcement.

#### Before ABI v11

Without the `LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS` flag, you must set
the "no new privs" flag in a separate system call:

```
runtime.LockOSThread()
defer runtime.UnlockOSThread()

if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
	return err
}

if err := landlockRestrictSelf(rulesetFD, LANDLOCK_RESTRICT_SELF_TSYNC); err != nil {
	return err
}
```

Because *prctl*(2) also only applies to the calling thread, we must
*lock* the Goroutine to the OS thread, to ensure that the *prctl*(2)
and *landlock_restrict_self*(2) calls happen on the same OS thread.

*landlock_restrict_self*(2) propagates the "no new privs" flag to all
threads when invoked with the `TSYNC` flag, so it is enough to
establish the "no new privs" prerequisite on the calling thread.

#### Before ABI v8

Without the `LANDLOCK_RESTRICT_SELF_TSYNC` flag, you must make sure
that both *prctl*(2) and *landlock_restrict_self*(2) are being called
by all OS threads:

**In a program that does not use `cgo`**, you can use the
`syscall.AllThreadsSyscall6()` function.  This invokes the given
system call on all Go-managed OS threads.

**In a program that does use `cgo`**, the safe way to do it is to use
the `psx` library from
`kernel.org/pub/linux/libs/security/libcap/psx`.  This library
determines the OS threads belonging to the process and makes them all
invoke the system call.

Both techniques technically create separate Landlock domains which all
enforce the same set of rules.  This makes a small difference compared
to using `TSYNC`: For some Landlock restrictions such as the sending
of Unix signals, Abstract Unix sockets and ptrace, the identity of
Landlock domains is taken into account for the enforcement, and so in
some cases these programs might not be able to use these features
correctly, also depending on the Go runtime distributes Goroutine
execution across OS threads.

### Case 2: Applying a Landlock policy to another program

Direct use of Landlock enforcement with the `os/exec` package is only
[available from Go 1.28 going
forward](https://github.com/golang/go/issues/68595) (early 2027).

Without that, programs have historically resorted to invoking
`syscall.Exec()` directly.  Combined with `runtime.LockOSThread()`,
this lets you use Landlock on only one OS thread (without `TSYNC` or
`psx`).  The commonly employed steps are:

1. `runtime.LockOSThread()` (and `defer runtime.UnlockOSThread()` in case of early error)
2. Invoke *prctl*(2) with `PR_SET_NO_NEW_PRIVS` (assuming Landlock ABI < v11)
3. Invoke *landlock_restrict_self*(2) with the desired ruleset (without `TSYNC` flag)
4. `syscall.Exec()`

Steps 2, 3 and 4 all run on the same OS thread, and so
`syscall.Exec()` replaces the currently running process with the
process image of the desired program, using the Landlock policy that
was enforced in step 3.


## Reference implementation

For reference, the official Go-Landlock library implements the system
call logic in the function `restrict()` in `landlock/restrict.go`, and
some of the `syscall.AllThreadsSyscall` and `psx` aspects in the
`landlock/syscall` package.
