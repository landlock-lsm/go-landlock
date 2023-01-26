package landlock

import (
	"fmt"

	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// PathOpt is an option value for RestrictPaths().
type PathOpt struct {
	accessFS      AccessFSSet
	enforceSubset bool // enforce that accessFS is a subset of cfg.handledAccessFS
	paths         []string
}

// withRights adds the given access rights to the right enforced in the path option
// and returns the result as a new PathOpt.
func (p PathOpt) withRights(a AccessFSSet) PathOpt {
	return PathOpt{
		accessFS:      p.accessFS.union(a),
		enforceSubset: p.enforceSubset,
		paths:         p.paths,
	}
}

// WithRefer adds the "refer" access right to a path option.
//
// Notably, asking for the "refer" access right does not work on
// kernels below 5.19. In best effort mode, this will fall back to not
// using Landlock enforcement at all on these kernel versions. If you
// want to use Landlock on these kernels, do not use the "refer"
// access right.
func (p PathOpt) WithRefer() PathOpt {
	return p.withRights(ll.AccessFSRefer)
}

func (p PathOpt) String() string {
	return fmt.Sprintf("REQUIRE %v for paths %v", p.accessFS, p.paths)
}

func (p PathOpt) compatibleWithHandledAccessFS(handledAccessFS AccessFSSet) bool {
	a := p.accessFS
	if !p.enforceSubset {
		// If !enforceSubset, this PathOpt is potentially overspecifying flags,
		// so we should not check the subset property. We make an exception
		// for the "refer" flag, which should still get checked though.
		a = a.intersect(ll.AccessFSRefer)
	}
	return a.isSubset(handledAccessFS)
}

func (p PathOpt) effectiveAccessFS(handledAccessFS AccessFSSet) AccessFSSet {
	if !p.enforceSubset {
		return handledAccessFS.intersect(p.accessFS)
	}
	return p.accessFS
}

// PathAccess is a [Config.RestrictPaths] option which grants the
// access right specified by accessFS to the file hierarchies under
// the given paths.
//
// When accessFS is larger than what is permitted by the Landlock
// version in use, only the applicable subset of accessFS will be used.
//
// Most users should use the functions [RODirs], [RWDirs], [ROFiles]
// and [RWFiles] instead, which provide canned options for commonly
// used values of accessFS.
//
// Filesystem access rights are represented using bits in a uint64.
// The individual access rights and their meaning are defined in the
// landlock/syscall package and explained further in the
// [Kernel Documentation about Access Rights].
//
// accessFS must be a subset of the permissions that the Config
// restricts.
//
// [Kernel Documentation about Access Rights]: https://www.kernel.org/doc/html/latest/userspace-api/landlock.html#access-rights
func PathAccess(accessFS AccessFSSet, paths ...string) PathOpt {
	return PathOpt{
		accessFS:      accessFS,
		paths:         paths,
		enforceSubset: true,
	}
}

// RODirs is a [Config.RestrictPaths] option which grants common
// read-only access to files and directories and permits executing
// files.
func RODirs(paths ...string) PathOpt {
	return PathOpt{
		accessFS:      accessFSRead,
		paths:         paths,
		enforceSubset: false,
	}
}

// RWDirs is a [Config.RestrictPaths] option which grants full (read
// and write) access to files and directories under the given paths.
func RWDirs(paths ...string) PathOpt {
	return PathOpt{
		accessFS:      accessFSReadWrite,
		paths:         paths,
		enforceSubset: false,
	}
}

// ROFiles is a [Config.RestrictPaths] option which grants common read
// access to individual files, but not to directories, for the file
// hierarchies under the given paths.
func ROFiles(paths ...string) PathOpt {
	return PathOpt{
		accessFS:      accessFSRead & accessFile,
		paths:         paths,
		enforceSubset: false,
	}
}

// RWFiles is a [Config.RestrictPaths] option which grants common read
// and write access to files under the given paths, but it does not
// permit access to directories.
func RWFiles(paths ...string) PathOpt {
	return PathOpt{
		accessFS:      accessFSReadWrite & accessFile,
		paths:         paths,
		enforceSubset: false,
	}
}
