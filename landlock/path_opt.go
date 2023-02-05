package landlock

import (
	"errors"
	"fmt"
	"syscall"

	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

// FSRule is a Rule which permits access to file system paths.
type FSRule struct {
	accessFS      AccessFSSet
	enforceSubset bool // enforce that accessFS is a subset of cfg.handledAccessFS
	paths         []string
}

// withRights adds the given access rights to the rights enforced in the FSRule
// and returns the result as a new FSRule.
func (r FSRule) withRights(a AccessFSSet) FSRule {
	return FSRule{
		accessFS:      r.accessFS.union(a),
		enforceSubset: r.enforceSubset,
		paths:         r.paths,
	}
}

// intersectRights intersects the given access rights with the rights
// enforced in the FSRule and returns the result as a new FSRule.
func (r FSRule) intersectRights(a AccessFSSet) FSRule {
	return FSRule{
		accessFS:      r.accessFS.intersect(a),
		enforceSubset: r.enforceSubset,
		paths:         r.paths,
	}
}

// WithRefer adds the "refer" access right to a FSRule.
//
// Notably, asking for the "refer" access right does not work on
// kernels below 5.19. In best effort mode, this will fall back to not
// using Landlock enforcement at all on these kernel versions. If you
// want to use Landlock on these kernels, do not use the "refer"
// access right.
func (r FSRule) WithRefer() FSRule {
	return r.withRights(ll.AccessFSRefer)
}

func (r FSRule) String() string {
	return fmt.Sprintf("REQUIRE %v for paths %v", r.accessFS, r.paths)
}

// compatibleWithConfig returns true if the given rule is compatible
// for use with the config c.
func (r FSRule) compatibleWithConfig(c Config) bool {
	a := r.accessFS
	if !r.enforceSubset {
		// If !enforceSubset, this FSRule is potentially overspecifying flags,
		// so we should not check the subset property. We make an exception
		// for the "refer" flag, which should still get checked though.
		a = a.intersect(ll.AccessFSRefer)
	}
	return a.isSubset(c.handledAccessFS)
}

func (r FSRule) addToRuleset(rulesetFD int, c Config) error {
	effectiveAccessFS := r.accessFS
	if !r.enforceSubset {
		effectiveAccessFS = effectiveAccessFS.intersect(c.handledAccessFS)
	}
	for _, path := range r.paths {
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
// It establishes that rule.accessFS ⊆ c.handledAccessFS.
//
// If ok is false, downgrade is impossible and we need to fall back to doing nothing.
func (r FSRule) downgrade(c Config) (out Rule, ok bool) {
	// In case that "refer" is requested on a path, we
	// require Landlock V2+, or we have to downgrade to V0.
	// You can't get the refer capability with V1, but linking/
	// renaming files is always implicitly restricted.
	if hasRefer(r.accessFS) && !hasRefer(c.handledAccessFS) {
		return FSRule{}, false
	}
	return r.intersectRights(c.handledAccessFS), true
}

// PathAccess is a [Rule] which grants the access rights specified by
// accessFS to the file hierarchies under the given paths.
//
// When accessFS is larger than what is permitted by the Landlock
// version in use, only the applicable subset of accessFS will be used.
//
// Most users should use the functions [RODirs], [RWDirs], [ROFiles]
// and [RWFiles] instead, which provide canned rules for commonly
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
func PathAccess(accessFS AccessFSSet, paths ...string) FSRule {
	return FSRule{
		accessFS:      accessFS,
		paths:         paths,
		enforceSubset: true,
	}
}

// RODirs is a [Rule] which grants common read-only access to files
// and directories and permits executing files.
func RODirs(paths ...string) FSRule {
	return FSRule{
		accessFS:      accessFSRead,
		paths:         paths,
		enforceSubset: false,
	}
}

// RWDirs is a [Rule] which grants full (read and write) access to
// files and directories under the given paths.
func RWDirs(paths ...string) FSRule {
	return FSRule{
		accessFS:      accessFSReadWrite,
		paths:         paths,
		enforceSubset: false,
	}
}

// ROFiles is a [Rule] which grants common read access to individual
// files, but not to directories, for the file hierarchies under the
// given paths.
func ROFiles(paths ...string) FSRule {
	return FSRule{
		accessFS:      accessFSRead & accessFile,
		paths:         paths,
		enforceSubset: false,
	}
}

// RWFiles is a [Rule] which grants common read and write access to
// files under the given paths, but it does not permit access to
// directories.
func RWFiles(paths ...string) FSRule {
	return FSRule{
		accessFS:      accessFSReadWrite & accessFile,
		paths:         paths,
		enforceSubset: false,
	}
}
