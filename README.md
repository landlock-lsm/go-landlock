📚 [Godoc](https://pkg.go.dev/github.com/landlock-lsm/go-landlock/landlock)
| 🌍 [landlock.io](https://landlock.io/)

# Go Landlock library

Go-Landlock is a Go library for the Landlock LSM.

## TL;DR: Example

In a Go program, after starting up and doing program initialization work, run:

```
err := landlock.V9.BestEffort().RestrictPaths(
    landlock.RODirs("/usr", "/bin"),
    landlock.RWDirs("/tmp"),
)
```

After this invocation, your program can only access the specified paths.

## What is Landlock?

Landlock is a Linux kernel feature and can restrict the following types of access:

* Filesystem access
* Some network operations
* Some IPC operations

More details and examples in the [Go-Landlock
documentation](https://pkg.go.dev/github.com/landlock-lsm/go-landlock/landlock)
and the [Linux Userspace-API documentation for
Landlock](https://docs.kernel.org/userspace-api/landlock.html).

The Landlock LSM was introduced with Linux 5.13 and is today [enabled
on most major Linux
distributions](https://landlock.io/integrations/#linux-distributions).

## Goals

Goals of Go-Landlock are:

* Make unprivileged sandboxing easy to use and effective.
* Keep Go-Landlock's implementation at an easily auditable size.

## How to...

* [...onboard a program to use Go-Landlock](docs/onboarding.md)
* [...upgrade a Go-Landlock usage to use more advanced features](docs/upgrade.md)
