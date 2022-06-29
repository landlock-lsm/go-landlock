package landlock_test

import (
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

func TestCustomConfig(t *testing.T) {
	RunInSubprocess(t, func() {
		if v, err := ll.LandlockGetABIVersion(); err != nil || v < 1 {
			t.Skip("Requires Landlock V1")
		}

		if !canAccess("/etc/passwd") {
			t.Skipf("expected normal accesses to /etc/passwd to work")
		}

		if !canAccess("/etc/group") {
			t.Skipf("expected normal accesses to /etc/group to work")
		}

		readFile := landlock.AccessFSSet(ll.AccessFSReadFile)
		if err := landlock.MustConfig(readFile).RestrictPaths(
			landlock.PathAccess(readFile, "/etc/passwd"),
		); err != nil {
			t.Fatalf("Could not restrict paths: %v", err)
		}

		if !canAccess("/etc/passwd") {
			t.Error("expected to have read access to /etc/passwd, but didn't")
		}
		if canAccess("/etc/group") {
			t.Error("expected to have NO read access to /etc/group, but did")
		}
	})
}
