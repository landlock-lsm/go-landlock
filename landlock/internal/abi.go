package internal

import (
	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// DetectedABIVersion returns the Landlock ABI version supported by the
// running kernel, after applying errata-based downgrades.
// Returns 0 if Landlock is not supported by the kernel.
func DetectedABIVersion() int {
	v, err := ll.LandlockGetABIVersion()
	if err != nil {
		return 0
	}
	if v >= 6 {
		// Check that the signal scoping bug is fixed,
		// otherwise downgrade to v5.  This should happen only
		// seldomly, as the bugfix was backported to newer
		// versions of the 6.12 LTS kernel.
		errata, err := ll.LandlockGetErrata()
		if err != nil {
			errata = 0 // pretend none fixed
		}
		if (errata & 0x2) == 0 {
			v = 5
		}
	}
	if v < minimumRequiredABIVersion() {
		return 0
	}
	return v
}
