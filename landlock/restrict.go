package landlock

import (
	"errors"
	"fmt"
	"syscall"

	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

// downgrade calculates the actual ruleset to be enforced given the
// current kernel's Landlock ABI level.
//
// It establishes that opt.accessFS ⊆ handledAccessFS ⊆ abi.supportedAccessFS.
func downgrade(handledAccessFS AccessFSSet, opts []PathOpt, abi abiInfo) (AccessFSSet, []PathOpt) {
	handledAccessFS = handledAccessFS.intersect(abi.supportedAccessFS)

	resOpts := make([]PathOpt, len(opts))
	copy(resOpts, opts)
	for i := 0; i < len(resOpts); i++ {
		// In case that "refer" is requested on a path, we
		// require Landlock V2+, or we have to downgrade to V0.
		// You can't get the refer capability with V1, but linking/
		// renaming files is always implicitly restricted.
		if hasRefer(resOpts[i].accessFS) && !hasRefer(handledAccessFS) {
			return 0, nil // Use "ABI V0" (do nothing)
		}
		resOpts[i].accessFS = resOpts[i].accessFS.intersect(handledAccessFS)
	}
	return handledAccessFS, resOpts
}

func hasRefer(a AccessFSSet) bool {
	return a&ll.AccessFSRefer != 0
}

// restrictPaths is the actual RestrictPaths implementation.
func restrictPaths(c Config, opts ...PathOpt) error {
	handledAccessFS := c.handledAccessFS
	// Check validity of options early.
	for _, opt := range opts {
		if !opt.compatibleWithHandledAccessFS(handledAccessFS) {
			return fmt.Errorf("too broad option %v: %w", opt.accessFS, unix.EINVAL)
		}
	}

	abi := getSupportedABIVersion()
	if c.bestEffort {
		handledAccessFS, opts = downgrade(handledAccessFS, opts, abi)
	}
	if !handledAccessFS.isSubset(abi.supportedAccessFS) {
		return fmt.Errorf("missing kernel Landlock support. Got Landlock ABI v%v, wanted %v", abi.version, c.String())
	}

	// TODO: This might be incorrect - the "refer" permission is
	// always implicit, even in Landlock V1. So enabling Landlock
	// on a Landlock V1 kernel without any handled access rights
	// will still forbid linking files between directories.
	if handledAccessFS.isEmpty() {
		return nil // Success: Nothing to restrict.
	}

	rulesetAttr := ll.RulesetAttr{
		HandledAccessFS: uint64(handledAccessFS),
	}
	fd, err := ll.LandlockCreateRuleset(&rulesetAttr, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EOPNOTSUPP) {
			err = errors.New("landlock is not supported by kernel or not enabled at boot time")
		}
		if errors.Is(err, syscall.EINVAL) {
			err = errors.New("unknown flags, unknown access, or too small size")
		}
		// Bug, because these should have been caught up front with the ABI version check.
		return bug(fmt.Errorf("landlock_create_ruleset: %w", err))
	}
	defer syscall.Close(fd)

	for _, opt := range opts {
		accessFS := opt.effectiveAccessFS(handledAccessFS)
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

func populateRuleset(rulesetFd int, paths []string, access AccessFSSet) error {
	for _, p := range paths {
		if err := populate(rulesetFd, p, access); err != nil {
			return fmt.Errorf("populating ruleset for %q with access %v: %w", p, access, err)
		}
	}
	return nil
}

func populate(rulesetFd int, path string, access AccessFSSet) error {
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

// Denotes an error that should not have happened.
// If such an error occurs anyway, please try upgrading the library
// and file a bug to github.com/landlock-lsm/go-landlock if the issue persists.
func bug(err error) error {
	return fmt.Errorf("BUG(go-landlock): This should not have happened: %w", err)
}
