package landlock_test

import (
	"os"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// True if the given path can be opened for reading.
func canAccess(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	return true
}

func TestCustomConfig(t *testing.T) {
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
}
