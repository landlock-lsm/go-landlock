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
// It establishes that opt.accessFS ⊆ c.handledAccessFS ⊆ abi.supportedAccessFS.
func downgrade(c Config, opts []PathOpt, abi abiInfo) (Config, []PathOpt) {
	c = c.restrictTo(abi)

	resOpts := make([]PathOpt, 0, len(opts))
	for _, opt := range opts {
		opt, ok := opt.downgrade(c)
		if !ok {
			return v0, nil // Use "ABI V0" (do nothing)
		}
		resOpts = append(resOpts, opt)
	}
	return c, resOpts
}

func hasRefer(a AccessFSSet) bool {
	return a&ll.AccessFSRefer != 0
}

// restrictPaths is the actual RestrictPaths implementation.
func restrictPaths(c Config, opts ...PathOpt) error {
	// Check validity of options early.
	for _, opt := range opts {
		if !opt.compatibleWithConfig(c) {
			return fmt.Errorf("too broad option %v: %w", opt.accessFS, unix.EINVAL)
		}
	}

	abi := getSupportedABIVersion()
	if c.bestEffort {
		c, opts = downgrade(c, opts, abi)
	}
	if !c.compatibleWithABI(abi) {
		return fmt.Errorf("missing kernel Landlock support. Got Landlock ABI v%v, wanted %v", abi.version, c)
	}

	// TODO: This might be incorrect - the "refer" permission is
	// always implicit, even in Landlock V1. So enabling Landlock
	// on a Landlock V1 kernel without any handled access rights
	// will still forbid linking files between directories.
	if c.handledAccessFS.isEmpty() {
		return nil // Success: Nothing to restrict.
	}

	rulesetAttr := ll.RulesetAttr{
		HandledAccessFS: uint64(c.handledAccessFS),
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
		if err := opt.addToRuleset(fd, c); err != nil {
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

// Denotes an error that should not have happened.
// If such an error occurs anyway, please try upgrading the library
// and file a bug to github.com/landlock-lsm/go-landlock if the issue persists.
func bug(err error) error {
	return fmt.Errorf("BUG(go-landlock): This should not have happened: %w", err)
}
