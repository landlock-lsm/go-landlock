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

	roDirs := []string{"/tmp"}
	err = golandlock.Restrict(roDirs, nil, nil, nil)
	if errors.Is(err, syscall.ENOSYS) {
		t.Skipf("kernel does not support Landlock; tests cannot be run: %v", err)
	} else if errors.Is(err, syscall.EOPNOTSUPP) {
		t.Skipf("landlock not enabled in kernel; tests cannot be run: %v", err)
	}

	_, err = os.ReadFile("/etc/passwd")
	if !errors.Is(err, syscall.EACCES) {
		t.Errorf("expected that bar/a can't be read, got error: %v", err)
	}
}
