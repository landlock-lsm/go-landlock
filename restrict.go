// Package golandlock provides a high-level interface to the Linux Landlock sandboxing feature.
package golandlock

import (
	"fmt"
	"syscall"

	ll "github.com/gnoack/golandlock/syscall"
	"golang.org/x/sys/unix"
)

// Access permission constants for file system access.
//
// In Landlock, file system access permissions are represented using bits in a uint64,
// so these constants each represent a group of file system access permissions.
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

// PathAccess is a RestrictPath() option that restricts the given path
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
// thread can't open files for reading and writing any more and
// modify subdirectories.
//
// Example: The following invocation will restrict the current thread
// so that it can only read from /usr, /bin and /tmp, and only write
// to /tmp. (The notions of what reading and writing means are limited
// by what Landlock can restrict to.)
//
//   err := golandlock.RestrictPaths(
//       golandlock.RODirs("/usr", "/bin"),
//       golandlock.RWDirs("/tmp"),
//   )
//
// This function returns an error if the current kernel does not
// support Landlock or if any of the given paths does not denote
// an actual directory.
//
// This function implicitly sets the "no new privileges" flag on the
// current process.
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

// Restrict is a shortcut for:
//
// 	RestrictPaths(
// 		RODirs(roDirs...),
// 		ROFiles(roFiles...),
// 		RWDirs(rwDirs...),
// 		RWFiles(rwFiles...),
// 	)
//
// It's recommended to use RestrictPath() instead, as it is more
// flexible and it's harder to mix up the different parameters.
func Restrict(roDirs, roFiles, rwDirs, rwFiles []string) error {
	return RestrictPaths(
		RODirs(roDirs...),
		ROFiles(roFiles...),
		RWDirs(rwDirs...),
		RWFiles(rwFiles...),
	)
}
