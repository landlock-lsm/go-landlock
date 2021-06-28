# Go landlock library

The Go landlock library provides an interface to Linux 5.13's Landlock
kernel sandboxing features.

The library provides access to Landlock on two levels:

## High level interface

To restrict the current process to only see a given set of paths and
subdirectories, use `golandlock.Restrict`. The parameters are lists of
file and directory names.

## Low level interface

The low level interface in `golandlock/syscall` provides access to the
raw Landlock syscalls.
