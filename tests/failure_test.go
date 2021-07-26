// Package failure_test tests scenarios where golandlock can't enforce anything.
//
// The beauty with these tests is that they don't enforce anything, so
// it's somewhat safe to put them into the same package - at least as
// long as they work.
package failure_test

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/gnoack/golandlock"
)

func TestPathDoesNotExist(t *testing.T) {
	doesNotExistPath := filepath.Join(t.TempDir(), "does_not_exist")

	err := golandlock.V1.RestrictPaths(
		golandlock.RODirs(doesNotExistPath),
	)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected 'not exist' error, got: %v", err)
	}
}

func TestRestrictingPlainFileWithDirectoryFlags(t *testing.T) {
	err := golandlock.V1.RestrictPaths(
		golandlock.RODirs("/etc/passwd"),
	)
	if !errors.Is(err, syscall.EINVAL) {
		t.Errorf("expected 'invalid argument' error, got: %v", err)
	}
}
