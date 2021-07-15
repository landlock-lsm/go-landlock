package golandlock_test

import (
	"errors"
	"os"
	"syscall"
	"testing"

	"github.com/gnoack/golandlock"
)

// Make sure that after landlocking, the password file can't be read any more.
// XXX: Landlocking in the test itself makes it difficult to compose.
func TestAccessingPasswordFile(t *testing.T) {
	_, err := os.ReadFile("/etc/passwd")
	if err != nil {
		t.Skipf("expected normal accesses to /etc/passwd to work, got error: %v", err)
	}

	err = golandlock.V1.RestrictPaths(golandlock.RODirs("/tmp"))
	if err != nil {
		t.Skipf("kernel does not support Landlock v1; tests cannot be run.")
	}

	_, err = os.ReadFile("/etc/passwd")
	if !errors.Is(err, syscall.EACCES) {
		t.Errorf("expected that bar/a can't be read, got error: %v", err)
	}
}
