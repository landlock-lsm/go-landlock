package golandlock

import (
	"errors"
	"fmt"
	"syscall"

	ll "github.com/gnoack/golandlock/syscall"
	"golang.org/x/sys/unix"
)

// The actual restrictPaths implementation.
func restrictPaths(c Config, opts ...pathOpt) error {
	rulesetAttr := ll.RulesetAttr{
		HandledAccessFS: c.handledAccessFS,
	}
	abi := getSupportedABIVersion()
	if c.bestEffort {
		rulesetAttr.HandledAccessFS &= abi.supportedAccessFS
	} else {
		if !flagSubset(rulesetAttr.HandledAccessFS, abi.supportedAccessFS) {
			return fmt.Errorf("Missing kernel Landlock support. Got Landlock ABI v%v, wanted %v", abi.version, c.name)
		}
	}
	if rulesetAttr.HandledAccessFS == 0 {
		return nil // Success: Nothing to restrict.
	}

	fd, err := ll.LandlockCreateRuleset(&rulesetAttr, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EOPNOTSUPP) {
			err = errors.New("Landlock is not supported by kernel or not enabled at boot time")
		}
		if errors.Is(err, syscall.EINVAL) {
			err = errors.New("unknown flags, unknown access, or too small size")
		}
		// Bug, because these should have been caught up front with the ABI version check.
		return bug(fmt.Errorf("landlock_create_ruleset: %w", err))
	}
	defer syscall.Close(fd)

	for _, opt := range opts {
		accessFS := opt.accessFS & rulesetAttr.HandledAccessFS
		if err := populateRuleset(fd, opt.paths, accessFS); err != nil {
			return err
		}
	}

	if err := ll.AllThreadsPrctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		// This prctl invocation should always work.
		return bug(fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %v", err))
	}

	if err := ll.AllThreadsLandlockRestrictSelf(fd, 0); err != nil {
		if errors.Is(err, syscall.E2BIG) {
			// Other errors than E2BIG should never happen.
			return fmt.Errorf("the maximum number of stacked rulesets is reached for the current thread: %w", err)
		}
		return bug(fmt.Errorf("landlock_restrict_self: %w", err))
	}
	return nil
}

func populateRuleset(rulesetFd int, paths []string, access uint64) error {
	for _, p := range paths {
		if err := populate(rulesetFd, p, access); err != nil {
			return fmt.Errorf("populating ruleset for %q: %w", p, err)
		}
	}
	return nil
}

func populate(rulesetFd int, path string, access uint64) error {
	fd, err := syscall.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	pathBeneath := ll.PathBeneathAttr{
		ParentFd:      fd,
		AllowedAccess: access,
	}
	err = ll.LandlockAddPathBeneathRule(rulesetFd, &pathBeneath, 0)
	if err != nil {
		if errors.Is(err, syscall.EINVAL) {
			// The ruleset access permissions must be a superset of the ones we restrict to.
			// This should never happen because the call to populate() ensures that.
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

// flagSubset returns true if the 1-bits in a are a subset of 1-bits in b.
func flagSubset(a, b uint64) bool {
	return a&b == a
}

// Denotes an error that should not have happened.
// If such an error occurs anyway, please try upgrading the library
// and file a bug to github.com/gnoack/golandlock if the issue persists.
func bug(err error) error {
	return fmt.Errorf("BUG(golandlock): This should not have happened: %w", err)
}
