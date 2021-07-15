# Go landlock library

The Go landlock library restricts a thread's ability to use files,
using Linux 5.13's Landlock feature.

## High level interface

To restrict the current process to only see a given set of paths and
subdirectories, use `golandlock.V1.RestrictPaths`.

**Example:** The following invocation will restrict the current thread
so that it can only read from `/usr`, `/bin` and `/tmp`, and only
write to `/tmp`.

```
err := golandlock.V1.RestrictPaths(
    golandlock.RODirs("/usr", "/bin"),
    golandlock.RWDirs("/tmp"),
)
```

Please see the [package
documentation](https://pkg.go.dev/github.com/gnoack/golandlock) for
details.

## Low level interface

The low level interface in `golandlock/syscall` provides access to the
raw Landlock syscalls.

## Caveats

Some filesystem operations can't currently be restricted with
Landlock. Familiarity with the Landlock kernel interface and its
limitations is assumed
([documentation](https://landlock.io/linux-doc/landlock-v34/userspace-api/landlock.html),
[filesystem
flags](https://landlock.io/linux-doc/landlock-v34/userspace-api/landlock.html#filesystem-flags):

> It is currently not possible to restrict some file-related actions
> accessible through these syscall families: `chdir(2)`,
> `truncate(2)`, `stat(2)`, `flock(2)`, `chmod(2)`, `chown(2)`,
> `setxattr(2)`, `utime(2)`, `ioctl(2)`, `fcntl(2)`, `access(2)`.
> Future Landlock evolutions will enable to restrict them.
