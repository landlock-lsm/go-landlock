//go:build linux

package landlock

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"

	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

// downgrade calculates the actual ruleset to be enforced given the
// current kernel's Landlock ABI level.
//
// It establishes that rule.compatibleWithConfig(c) and c.compatibleWithABI(abi).
func downgrade(c Config, rules []Rule, abi abiInfo) (Config, []Rule) {
	c = c.restrictTo(abi)

	resRules := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		rule, ok := rule.downgrade(c)
		if !ok {
			return v0, nil // Use "ABI V0" (do nothing)
		}
		resRules = append(resRules, rule)
	}
	return c, resRules
}

// newRulesetFD is the implementation of [Config.NewRulesetFD].
func newRulesetFD(c Config, rules ...Rule) (fd int, flags uint32, err error) {
	fd, c, err = createRuleset(c, supportedABIVersion(), rules)
	if err != nil || fd < 0 {
		return -1, 0, err
	}
	return fd, uint32(c.flags), nil
}

// createRuleset validates c and rules, downgrades them in best effort
// mode, and creates a Landlock ruleset with the given rules.
//
// It returns the ruleset FD together with the effective Config which
// the ruleset was created for.  If there is nothing to restrict, the
// returned FD is -1.  On error, no FD remains open.
func createRuleset(c Config, abi abiInfo, rules []Rule) (fd int, eff Config, err error) {
	// Check before the best effort downgrade, which would drop
	// unknown access rights silently.
	if !c.valid() {
		return -1, Config{}, fmt.Errorf("unsupported access rights in %v (upgrade go-landlock?): %w", c, syscall.EINVAL)
	}

	// Check validity of rules early.
	for _, rule := range rules {
		if !rule.compatibleWithConfig(c) {
			return -1, Config{}, fmt.Errorf("incompatible rule %v: %w", rule, unix.EINVAL)
		}
	}

	if c.bestEffort {
		c, rules = downgrade(c, rules, abi)
	}
	if !c.compatibleWithABI(abi) {
		return -1, Config{}, fmt.Errorf("missing kernel Landlock support. Got Landlock ABI v%v, wanted %v", abi.version, c)
	}

	// Remark: The "refer" right is implicit, but only enabled if
	// any of the other filesystem access rights is handled.
	if c.HandledAccessFS.isEmpty() && c.HandledAccessNet.isEmpty() && c.Scoped.isEmpty() {
		return -1, c, nil // Success: Nothing to restrict.
	}

	rulesetAttr := c.rulesetAttr()
	fd, err = ll.LandlockCreateRuleset(&rulesetAttr, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EOPNOTSUPP) {
			err = errors.New("landlock is not supported by kernel or not enabled at boot time")
		}
		if errors.Is(err, syscall.EINVAL) {
			err = errors.New("unknown flags, unknown access, or too small size")
		}
		// Bug, because these should have been caught up front with the ABI version check.
		return -1, Config{}, bug(fmt.Errorf("landlock_create_ruleset: %w", err))
	}

	for _, rule := range rules {
		if err := rule.addToRuleset(fd, c); err != nil {
			syscall.Close(fd)
			return -1, Config{}, err
		}
	}
	return fd, c, nil
}

// restrict is the actual implementation which sets up Landlock.
func restrict(c Config, rules ...Rule) error {
	abi := supportedABIVersion()
	useTsync := abi.version >= 8
	if !useTsync {
		// Work around https://github.com/landlock-lsm/go-landlock/issues/39
		//
		// This is specific to the libpsx enforcement below,
		// and must not be part of createRuleset().
		rules = maybeWorkaroundBug39(c, rules)
	}

	fd, c, err := createRuleset(c, abi, rules)
	if err != nil {
		return err
	}
	if fd < 0 {
		return nil // Success: Nothing to restrict.
	}
	defer syscall.Close(fd)

	if !useTsync {
		if err := ll.AllThreadsPrctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			// This prctl invocation should always work.
			return bug(fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", err))
		}

		if err := ll.AllThreadsLandlockRestrictSelf(fd, uint32(c.flags)); err != nil {
			if errors.Is(err, syscall.E2BIG) {
				// Other errors than E2BIG should never happen.
				return fmt.Errorf("the maximum number of stacked rulesets is reached for the current thread: %w", err)
			}
			return bug(fmt.Errorf("landlock_restrict_self: %w", err))
		}
		return nil
	}

	flags := uint32(c.flags) | ll.FlagRestrictSelfTSync | ll.FlagRestrictSelfNoNewPrivs
	if abi.version < 11 {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		// The kernel sets no_new_privs on all threads, but
		// only if the ruleset enforcement succeeds.
		flags &^= ll.FlagRestrictSelfNoNewPrivs
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return bug(fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %v", err))
		}
	}

	if err := ll.LandlockRestrictSelf(fd, flags); err != nil {
		if errors.Is(err, syscall.E2BIG) {
			return fmt.Errorf("the maximum number of stacked rulesets is reached for the current thread: %w", err)
		}
		return bug(fmt.Errorf("landlock_restrict_self: %w", err))
	}
	return nil
}

// bug constructs an error that should not have happened.
//
// If such an error occurs anyway, please try upgrading the library
// and file a bug to github.com/landlock-lsm/go-landlock if the issue persists.
func bug(err error) error {
	return fmt.Errorf("BUG(go-landlock): This should not have happened: %w", err)
}
