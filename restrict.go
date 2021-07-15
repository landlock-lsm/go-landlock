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
// basic file system operations.
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
//
// In Landlock, filesystem access permissions are represented using
// bits in a uint64, so these constants each represent a group of
// filesystem access permissions.
//
// Individual permissions are available in the golandlock/syscall package.
//
// The meaning of access rights and the full list of available flags
// is documented at
// https://www.kernel.org/doc/html/latest/userspace-api/landlock.html#access-rights
const (
	// AccessFile is the set of permissions that only apply to files.
	AccessFile uint64 = ll.AccessFSExecute | ll.AccessFSWriteFile | ll.AccessFSReadFile

	// AccessFSRoughlyRead are the set of access permissions associated with read access to files and directories.
	AccessFSRoughlyRead uint64 = ll.AccessFSExecute | ll.AccessFSReadFile | ll.AccessFSReadDir

	// AccessFSRoughlyWrite are the set of access permissions associated with write access to files and directories.
	AccessFSRoughlyWrite uint64 = ll.AccessFSWriteFile | ll.AccessFSRemoveDir | ll.AccessFSRemoveFile | ll.AccessFSMakeChar | ll.AccessFSMakeDir | ll.AccessFSMakeReg | ll.AccessFSMakeSock | ll.AccessFSMakeFifo | ll.AccessFSMakeBlock | ll.AccessFSMakeSym

	// AccessFSRoughlyReadWrite are the set of access permissions associated with read and write access to files and directories.
	AccessFSRoughlyReadWrite uint64 = AccessFSRoughlyRead | AccessFSRoughlyWrite
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
	paths    []string
	accessFS uint64
}

// PathAccess is a RestrictPaths() option that restricts the given path
// to the access permissions given by accessFS.
//
// When accessFS is larger than what is permitted by the Landlock
// version in use, only the applicable subset of accessFS will be
// used.
func PathAccess(accessFS uint64, paths ...string) pathOpt {
	return pathOpt{
		paths:    paths,
		accessFS: accessFS,
	}
}

// RODirs is equivalent to PathAccess(AccessFSRoughlyRead, ...)
func RODirs(paths ...string) pathOpt { return PathAccess(AccessFSRoughlyRead, paths...) }

// RWDirs is equivalent to PathAccess(AccessFSRoughlyReadWrite, ...)
func RWDirs(paths ...string) pathOpt { return PathAccess(AccessFSRoughlyReadWrite, paths...) }

// ROFiles is equivalent to PathAccess(AccessFSRoughlyRead&AccessFile, ...)
//
// This can be used instead of RODirs() if listing directories is not needed.
func ROFiles(paths ...string) pathOpt { return PathAccess(AccessFSRoughlyRead&AccessFile, paths...) }

// RWFiles is equivalent to PathAccess(AccessFSRoughlyReadWrite&AccessFile, ...)
//
// This can be used instead of RWDirs() if read and write access to directory entries is not needed.
func RWFiles(paths ...string) pathOpt {
	return PathAccess(AccessFSRoughlyReadWrite&AccessFile, paths...)
}

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
	// TODO(gnoack): handledAccessFs will need to be different for
	// other ABI versions.
	handledAccessFs := uint64(AccessFSRoughlyReadWrite)
	rulesetAttr := ll.RulesetAttr{
		HandledAccessFs: handledAccessFs,
	}
	fd, err := ll.LandlockCreateRuleset(&rulesetAttr, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	for _, opt := range opts {
		if err := populateRuleset(fd, opt.paths, opt.accessFS&handledAccessFs); err != nil {
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

// BestEffort returns an object whose RestrictPaths() method will
// opportunistically enforce the strongest rules it can, up to the
// given ABI version, working with the level of Landlock support
// available in the running kernel.
//
// Warning: A best-effort call to RestrictPaths() will succeed without
// error even when Landlock is not available at all on the current kernel.
func (v ABI) BestEffort() Landlocker {
	return gracefulABI(v)
}

type gracefulABI int

// RestrictPaths restricts file system accesses on a specific Landlock
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
