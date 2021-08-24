# Go Landlock library

The Go Landlock library restricts the current processes' ability to
use files, using Linux 5.13's Landlock feature. ([Package
documentation](https://pkg.go.dev/github.com/landlock-lsm/go-landlock/landlock))

For a more low-level interface, please see [the landlock/syscall
package](https://pkg.go.dev/github.com/landlock-lsm/go-landlock/landlock/syscall).

This package used to be located at `github.com/gnoack/golandlock`.
Please update your import paths to point to
`github.com/landlock-lsm/go-landlock/landlock`.
