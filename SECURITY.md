# Security Policy

## Vulnerability Reporting

### What constitutes a Go-Landlock vulnerability

In scope for Go-Landlock vulnerabilities are:

* bugs in Go-Landlock itself
* bugs where Go or Go-Landlock interact in unexpected ways with
  Landlock's underlying semantics

For bugs in the Linux kernel's Landlock implementation, please [report
these to Linux
instead](https://docs.kernel.org/process/security-bugs.html).

### Reporting channel

Please report vulnerabilities through the "Security" tab on the GitHub
project page, at https://github.com/landlock-lsm/go-landlock/security.

We encourage vulnerability reporting, and aim to respond fast and be
transparent about our vulnerabilities.

## Supported Versions

Go-Landlock follows [Go's module versioning
policy](https://go.dev/doc/modules/version-numbers).

We support:

* the newest library version of the newest major release, and
* the newest library version of the second newest major release
  for a year after releasing the new major release.

Updating the library within a major release should never break users
or the sandboxing semantics of existing programs.  **We also uphold this
rule for v0.x.x versions.**

We reserve an exception to do backwards-incompatible changes in the
github.com/landlock-lsm/go-landlock/landlock/syscall package, which
contains less stable internal APIs.
