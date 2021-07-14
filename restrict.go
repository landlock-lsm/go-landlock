// Package golandlock restricts a thread's ability to use files.
//
// RestrictPaths restricts a thread's access to a given set to file
// system hierarchies, so that only a subset of file system operations
// continues to work.
//
// RestrictPaths comes in two flavours:
//
// RestrictPaths itself is going to restrict more file system
// operations in future versions of this library, and is meant for use
// in programs that are confident that they have specified all
// relevant file hierarchies broadly enough using the helpers RODirs,
// RWDirs, ROFiles and RWFiles. Callers of RestrictPaths will benefit
// from additional future Landlock capabilities, at the slight risk of
// breaking their program when these capabilities are introduced.
//
// Example: If a program does an os.Stat syscall on a file, but that
// file is not covered in the invocation to RestrictPaths, the os.Stat
// syscall might fail at some point in the future, when the golandlock
// library starts restricting this syscall. (os.Stat can't be
// restricted with Landlock ABI V1)
//
// RestrictPathsV1 is a guaranteed future-compatible variant of
// RestrictPaths. Callers of RestrictPathsV1 get the guarantee that
// their programs continue working after an upgrade of the golandlock
// library. In order to still benefit from new Landlock features, they
// will have to change to a variant of the call with a higher version
// number in future releases.
package golandlock

import (
	"fmt"
	"syscall"

	ll "github.com/gnoack/golandlock/syscall"
	"golang.org/x/sys/unix"
)

// Access permission constants for filesystem access.
//
// In Landlock, filesystem access permissions are represented using bits in a uint64,
// so these constants each represent a group of filesystem access permissions.
//
// Individual permissions are available in the golandlock/syscall package.
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

type pathOpt func(rulesetFd int) error

// PathAccess is a RestrictPaths() option that restricts the given path
// to the access permissions given by accessFS.
func PathAccess(accessFS uint64, paths ...string) pathOpt {
	return func(fd int) error {
		return populateRuleset(fd, paths, accessFS)
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

// RestrictPaths restricts the current thread to only "see" the files
// provided as inputs. After this call successfully returns, the same
// thread will only be able to use files in the ways as they were
// specified in advance in the call to RestrictPaths.
//
// Example: The following invocation will restrict the current thread
// so that it can only read from /usr, /bin and /tmp, and only write
// to /tmp.
//
//   err := golandlock.RestrictPaths(
//       golandlock.RODirs("/usr", "/bin"),
//       golandlock.RWDirs("/tmp"),
//   )
//
// The notions of what reading and writing means are limited by what
// Landlock can restrict to and are defined in constants in this module.
//
// Callers to RestrictPaths need to declare broadly the file
// hierarchies that they need to access for roughly-reading and
// -writing. This should be sufficient for most use cases, but there
// is a theoretical risk that such programs might break after a
// golandlock upgrade if they have missed to declare file operations
// which are suddenly enforced in a future Landlock version. If this
// is a concern, the versioned variant RestrictPathsV1 provides the
// same but is guaranteed to not make use of future Landlock features
// in the future.
//
// The overall set of operations that RestrictPaths can restrict are
// specified in AccessFSRoughlyReadWrite.
//
// This function returns an error if the current kernel does not
// support Landlock or if any of the given paths does not denote
// an actual directory.
//
// This function implicitly sets the "no new privileges" flag on the
// current thread.
func RestrictPaths(opts ...pathOpt) error {
	// TODO: Re-think graceful degradation on old kernels
	// and kernels without compiled-in Landlock support.
	rulesetAttr := ll.RulesetAttr{
		HandledAccessFs: uint64(AccessFSRoughlyReadWrite),
	}
	fd, err := ll.LandlockCreateRuleset(&rulesetAttr, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	for _, opt := range opts {
		opt(fd)
	}

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}

	if err := ll.LandlockRestrictSelf(fd, 0); err != nil {
		return err
	}
	return nil
}

// RestrictPathsV1 is like RestrictPaths, but only disables file
// system accesses as supported by Landlock up to ABI V1.
//
// This variant is guaranteed to enforce the exact same rules in
// future versions of this library, but does not automatically benefit
// from new Landlock features in the future.
func RestrictPathsV1(opts ...pathOpt) error {
	return RestrictPaths(opts...)
}

// XXX: Should file descriptors be int or int32?
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

// Restrict is a deprecated shortcut for RestrictPaths().
//
// It's recommended to use RestrictPaths() instead, as it is more
// flexible and it's harder to mix up the different parameters.
// Restrict() will be removed in future versions of golandlock.
//
// Calling Restrict() is equivalent to:
//
// 	RestrictPaths(
// 		RODirs(roDirs...),
// 		ROFiles(roFiles...),
// 		RWDirs(rwDirs...),
// 		RWFiles(rwFiles...),
// 	)
//
func Restrict(roDirs, roFiles, rwDirs, rwFiles []string) error {
	return RestrictPaths(
		RODirs(roDirs...),
		ROFiles(roFiles...),
		RWDirs(rwDirs...),
		RWFiles(rwFiles...),
	)
}
