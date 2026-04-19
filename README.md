📚 [Godoc](https://pkg.go.dev/github.com/landlock-lsm/go-landlock/landlock)
| 🌍 [landlock.io](https://landlock.io/)

# Go Landlock library

The Go-Landlock library restricts the current processes' ability to
use files, using Linux 5.13's Landlock feature.

## TL;DR: Example

In a Go program, after starting up and doing program initialization work, run:

```
err := landlock.V8.BestEffort().RestrictPaths(
    landlock.RODirs("/usr", "/bin"),
    landlock.RWDirs("/tmp"),
)
```

After this invocation, your program can only access the specified paths.

Landlock is a Linux kernel feature and can restrict the following types of access:

* Filesystem access
* Some network operations
* Some IPC operations

More details and examples in the [Go-Landlock
documentation](https://pkg.go.dev/github.com/landlock-lsm/go-landlock/landlock).

## Goals

Goals of Go-Landlock are:

* Make unprivileged sandboxing easy to use and effective.
* Keep Go-Landlock's implementation at an easily auditable size.
