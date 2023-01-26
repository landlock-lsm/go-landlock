package landlock

import (
	"errors"
	"fmt"
	"syscall"

	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

// PathOpt is an option value for RestrictPaths().
type PathOpt struct {
	accessFS      AccessFSSet
	enforceSubset bool // enforce that accessFS is a subset of cfg.handledAccessFS
	paths         []string
}

// withRights adds the given access rights to the rights enforced in the path option
// and returns the result as a new PathOpt.
func (p PathOpt) withRights(a AccessFSSet) PathOpt {
	return PathOpt{
		accessFS:      p.accessFS.union(a),
		enforceSubset: p.enforceSubset,
		paths:         p.paths,
	}
}

// intersectRights intersects the given access rights with the rights
// enforced in the path option and returns the result as a new PathOpt.
func (p PathOpt) intersectRights(a AccessFSSet) PathOpt {
	return PathOpt{
		accessFS:      p.accessFS.intersect(a),
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

// compatibleWithConfig returns true if the given option is compatible
// for use with the config c.
func (p PathOpt) compatibleWithConfig(c Config) bool {
	a := p.accessFS
	if !p.enforceSubset {
		// If !enforceSubset, this PathOpt is potentially overspecifying flags,
		// so we should not check the subset property. We make an exception
		// for the "refer" flag, which should still get checked though.
		a = a.intersect(ll.AccessFSRefer)
	}
	return a.isSubset(c.handledAccessFS)
}

func (p PathOpt) addToRuleset(rulesetFD int, c Config) error {
	effectiveAccessFS := p.accessFS
	if !p.enforceSubset {
		effectiveAccessFS = effectiveAccessFS.intersect(c.handledAccessFS)
	}
	for _, path := range p.paths {
		if err := addPath(rulesetFD, path, effectiveAccessFS); err != nil {
			return fmt.Errorf("populating ruleset for %q with access %v: %w", path, effectiveAccessFS, err)
		}
	}
	return nil
}

func addPath(rulesetFd int, path string, access AccessFSSet) error {
	fd, err := syscall.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	pathBeneath := ll.PathBeneathAttr{
		ParentFd:      fd,
		AllowedAccess: uint64(access),
	}
	err = ll.LandlockAddPathBeneathRule(rulesetFd, &pathBeneath, 0)
	if err != nil {
		if errors.Is(err, syscall.EINVAL) {
			// The ruleset access permissions must be a superset of the ones we restrict to.
			// This should never happen because the call to addPath() ensures that.
			err = bug(fmt.Errorf("invalid flags, or inconsistent access in the rule: %w", err))
		} else if errors.Is(err, syscall.ENOMSG) && access == 0 {
			err = fmt.Errorf("empty access rights: %w", err)
		} else {
			// Other errors should never happen.
			err = bug(err)
		}
		return fmt.Errorf("landlock_add_rule: %w", err)
	}
	return nil
}

// downgrade calculates the actual ruleset to be enforced given the
// current config (and assuming that the config is going to work under
// the running kernel).
//
// It establishes that opt.accessFS ⊆ c.handledAccessFS.
//
// If ok is false, downgrade is impossible and we need to fall back to doing nothing.
func (p PathOpt) downgrade(c Config) (out restrictOpt, ok bool) {
	// In case that "refer" is requested on a path, we
	// require Landlock V2+, or we have to downgrade to V0.
	// You can't get the refer capability with V1, but linking/
	// renaming files is always implicitly restricted.
	if hasRefer(p.accessFS) && !hasRefer(c.handledAccessFS) {
		return PathOpt{}, false
	}
	return p.intersectRights(c.handledAccessFS), true
}

// PathAccess is a [Config.RestrictPaths] option which grants the
// access rights specified by accessFS to the file hierarchies under
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
