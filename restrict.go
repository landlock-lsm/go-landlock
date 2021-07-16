// Package golandlock restricts a thread's ability to use files.
//
// The following invocation will restrict the current thread so that
// it can only read from /usr, /bin and /tmp, and only write to /tmp:
//
//     err := golandlock.V1.BestEffort().RestrictPaths(
//         golandlock.RODirs("/usr", "/bin"),
//         golandlock.RWDirs("/tmp"),
//     )
//
// This will restrict file access using Landlock V1 if available. If
// unavailable, it will attempt using earlier Landlock versions than
// the one requested. If no Landlock version is available, it will
// still succeed, without restricting file accesses.
//
// More possible invocations
//
// golandlock.VMax.BestEffort().RestrictPaths(...) enforces the given
// rules as strongly as possible with the newest Landlock version
// known to golandlock. It downgrades transparently.
//
// golandlock.V1.RestrictPaths(...) enforces the given rules using the
// capabilities of Landlock V1, but returns an error if that is not
// available.
//
// Landlock ABI versioning
//
// Callers need to identify at which ABI level they want to use
// Landlock and call RestrictPaths on the corresponding ABI constant.
// Currently the only available ABI variant is V1, which restricts
// basic filesystem operations.
//
// The constant VMax will be updated to reflect the highest possible
// Landlock version. Users of VMax will transparently benefit from
// additional future Landlock capabilities, at the slight risk of
// breaking their program when these capabilities are introduced and
// golandlock is updated.
//
// Users of specific ABI versions other than VMax get the guarantee
// that their programs continue working after an upgrade of the
// golandlock library. In order to still benefit from new Landlock
// features, they will manually have to change to a variant of the
// call with a higher version number in future releases.
//
// Graceful degradation on older kernels
//
// Programs that get run on different kernel versions will want to use
// the ABI.BestEffort() method to gracefully degrade to using the best
// available Landlock version on the current kernel.
//
// Caveats
//
// Some filesystem operations can't currently be restricted with
// Landlock. Quoting the Landlock documentation:
//
//   It is currently not possible to restrict some file-related actions
//   accessible through these syscall families: chdir(2),
//   truncate(2), stat(2), flock(2), chmod(2), chown(2),
//   setxattr(2), utime(2), ioctl(2), fcntl(2), access(2).
//   Future Landlock evolutions will enable to restrict them.
package golandlock

import (
	"errors"
	"fmt"
	"syscall"

	ll "github.com/gnoack/golandlock/syscall"
	"golang.org/x/sys/unix"
)

// Landlocker exposes the Landlock interface for a specific ABI
// version or set of ABI versions. The desired Landlocker can be
// selected by using the Landlock ABI version constants.
//
// RestrictPaths restricts the current thread to only "see" the files
// provided as inputs. After this call successfully returns, the same
// thread will only be able to use files in the ways as they were
// specified in advance in the call to RestrictPaths.
//
// Example: The following invocation will restrict the current thread
// so that it can only read from /usr, /bin and /tmp, and only write
// to /tmp.
//
//   err := golandlock.V1.RestrictPaths(
//       golandlock.RODirs("/usr", "/bin"),
//       golandlock.RWDirs("/tmp"),
//   )
//   if err != nil {
//       log.Fatalf("golandlock.V1.RestrictPaths(): %v", err)
//   }
//
// The notions of what reading and writing means are limited by what
// Landlock can restrict to and are defined in constants in this module.
//
// The overall set of operations that RestrictPaths can restrict are
// specified in AccessFSRoughlyReadWrite.
//
// This function returns an error if any of the given paths does not
// denote an actual directory or if Landlock can't be enforced using
// the ABI versions selected through the Landlocker object.
//
// This function implicitly sets the "no new privileges" flag on the
// current thread.
type Landlocker interface {
	RestrictPaths(opts ...pathOpt) error
}

// Access permission sets for filesystem access.
const (
	// The set of access rights that only apply to files.
	accessFile uint64 = ll.AccessFSExecute | ll.AccessFSWriteFile | ll.AccessFSReadFile

	// The set of access rights associated with read access to files and directories.
	accessFSRead uint64 = ll.AccessFSExecute | ll.AccessFSReadFile | ll.AccessFSReadDir

	// The set of access rights associated with write access to files and directories.
	accessFSWrite uint64 = ll.AccessFSWriteFile | ll.AccessFSRemoveDir | ll.AccessFSRemoveFile | ll.AccessFSMakeChar | ll.AccessFSMakeDir | ll.AccessFSMakeReg | ll.AccessFSMakeSock | ll.AccessFSMakeFifo | ll.AccessFSMakeBlock | ll.AccessFSMakeSym

	// The set of access rights associated with read and write access to files and directories.
	accessFSReadWrite uint64 = accessFSRead | accessFSWrite
)

// ABI represents a specific Landlock ABI version.
//
// The higher the ABI version, the more operations Landlock will be
// able to restrict.
type ABI int

// A list of known Landlock ABI versions.
var (
	V1   ABI = 1  // Landlock V1 support (basic file operations).
	VMax ABI = V1 // The highest known ABI version.
)

type pathOpt struct {
	accessFS uint64
	paths    []string
}

// PathAccess is a RestrictPaths() option that grants the access right
// specified by accessFS to the file hierarchies under the given paths.
//
// When accessFS is larger than what is permitted by the Landlock
// version in use, only the applicable subset of accessFS will be used.
//
// Most users should use the functions RODirs, RWDirs, ROFiles and
// RWFiles instead, which provide canned options for commonly used
// values of accessFS.
//
// Filesystem access rights are represented using bits in a uint64.
// The individual access rights and their meaning are defined in the
// golandlock/syscall package and explained further in the kernel
// documentation at
// https://www.kernel.org/doc/html/latest/userspace-api/landlock.html#access-rights
func PathAccess(accessFS uint64, paths ...string) pathOpt {
	return pathOpt{
		accessFS: accessFS,
		paths:    paths,
	}
}

// RODirs is a RestrictPaths() option that grants common read-only
// access to files and directories and permits executing files.
func RODirs(paths ...string) pathOpt { return PathAccess(accessFSRead, paths...) }

// RWDirs is a RestrictPaths() option that grants full (read and
// write) access to files and directories under the given paths.
func RWDirs(paths ...string) pathOpt { return PathAccess(accessFSReadWrite, paths...) }

// ROFiles is a RestrictPaths() option that grants common read access
// to individual files, but not to directories, for the file
// hierarchies under the given paths.
func ROFiles(paths ...string) pathOpt { return PathAccess(accessFSRead&accessFile, paths...) }

// RWFiles is a RestrictPaths() option that grants common read and
// write access to files under the given paths, but it does not permit
// access to directories.
func RWFiles(paths ...string) pathOpt { return PathAccess(accessFSReadWrite&accessFile, paths...) }

// RestrictPaths restricts file accesses for a specific Landlock ABI version.
func (v ABI) RestrictPaths(opts ...pathOpt) error {
	if v == 0 {
		// ABI v0 is "no Landlock support" and always returns
		// success immediately.
		return nil
	}
	if v < 0 || v > 1 {
		return fmt.Errorf("golandlock does not support ABI version %d", v)
	}
	// TODO(gnoack): HandledAccessFs will need to be different for other ABI versions.
	rulesetAttr := ll.RulesetAttr{
		HandledAccessFs: accessFSReadWrite,
	}
	fd, err := ll.LandlockCreateRuleset(&rulesetAttr, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	for _, opt := range opts {
		accessFS := opt.accessFS & rulesetAttr.HandledAccessFs
		if err := populateRuleset(fd, opt.paths, accessFS); err != nil {
			return err
		}
	}

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}

	if err := ll.LandlockRestrictSelf(fd, 0); err != nil {
		return err
	}
	return nil
}

// BestEffort returns a Landlocker that will opportunistically enforce
// the strongest rules it can, up to the given ABI version, working
// with the level of Landlock support available in the running kernel.
//
// Warning: A best-effort call to RestrictPaths() will succeed without
// error even when Landlock is not available at all on the current kernel.
func (v ABI) BestEffort() Landlocker {
	return gracefulABI(v)
}

type gracefulABI int

// RestrictPaths restricts filesystem accesses on a specific Landlock
// ABI version or a lower ABI version (including "no Landlock").
//
// This degrades gracefully on older kernels and may return
// successfully without restricting anything, if needed.
func (g gracefulABI) RestrictPaths(opts ...pathOpt) error {
	// TODO(gnoack): Retrieve the best supported Landlock ABI
	// version from the kernel using landlock_create_ruleset,
	// instead of trying it out.
	for v := ABI(g); v > 0; v-- {
		err := v.RestrictPaths(opts...)
		if errors.Is(err, syscall.ENOSYS) {
			break // Kernel doesn't have Landlock.
		}
		if errors.Is(err, syscall.EOPNOTSUPP) {
			break // Kernel is new enough, but Landlock is disabled.
		}
		if errors.Is(err, syscall.EINVAL) {
			// EINVAL: The kernel probably only supports lower
			// Landlock versions. Degrade gracefully to the next
			// version
			continue
		} else {
			// Success or other failure, return.
			return err
		}
	}
	// No Landlock support, returning
	return nil
}

// TODO(gnoack): Should file descriptors be int or int32?
// I believe in C they are only int32, but the Go syscalls package uses int,
// which I think is 64 bit on 64 bit architectures.
func populateRuleset(rulesetFd int, paths []string, access uint64) error {
	for _, p := range paths {
		if err := populate(rulesetFd, p, access); err != nil {
			return err
		}
	}
	return nil
}

func populate(rulesetFd int, path string, access uint64) error {
	fd, err := syscall.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	pathBeneath := ll.PathBeneathAttr{
		ParentFd:      fd,
		AllowedAccess: access,
	}
	err = ll.LandlockAddPathBeneathRule(rulesetFd, &pathBeneath, 0)
	if err != nil {
		return fmt.Errorf("failed to update ruleset: %w", err)
	}
	return nil
}
