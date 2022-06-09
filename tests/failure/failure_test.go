// Package failure_test tests scenarios where landlock can't enforce anything.
//
// The beauty with these tests is that they don't enforce anything, so
// it's somewhat safe to put them into the same package - at least as
// long as they work.
package failure_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

func TestPathDoesNotExist(t *testing.T) {
	if v, err := ll.LandlockGetABIVersion(); err != nil || v < 1 {
		t.Skip("Requires Landlock V1")
	}

	doesNotExistPath := filepath.Join(t.TempDir(), "does_not_exist")

	err := landlock.V1.RestrictPaths(
		landlock.RODirs(doesNotExistPath),
	)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected 'not exist' error, got: %v", err)
	}
}

func TestRestrictingPlainFileWithDirectoryFlags(t *testing.T) {
	if v, err := ll.LandlockGetABIVersion(); err != nil || v < 1 {
		t.Skip("Requires Landlock V1")
	}

	err := landlock.V1.RestrictPaths(
		landlock.RODirs("/etc/passwd"),
	)
	if !errors.Is(err, unix.EINVAL) {
		t.Errorf("expected 'invalid argument' error, got: %v", err)
	}
}

func TestEmptyAccessRights(t *testing.T) {
	if v, err := ll.LandlockGetABIVersion(); err != nil || v < 1 {
		t.Skip("Requires Landlock V1")
	}

	err := landlock.V1.RestrictPaths(
		landlock.PathAccess(0, "/etc/passwd"),
	)
	if !errors.Is(err, unix.ENOMSG) {
		t.Errorf("expected ENOMSG, got: %v", err)
	}
	want := "empty access rights"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("expected error message with %q, got: %v", want, err)
	}
}

func TestOverlyBroadPathOpt(t *testing.T) {
	if v, err := ll.LandlockGetABIVersion(); err != nil || v < 1 {
		t.Skip("Requires Landlock V1")
	}

	handled := landlock.AccessFSSet(0b011)
	excempt := landlock.AccessFSSet(0b111) // superset of handled!
	err := landlock.MustConfig(handled).RestrictPaths(
		landlock.PathAccess(excempt, "/tmp"),
	)
	if !errors.Is(err, unix.EINVAL) {
		t.Errorf("expected 'invalid argument' error, got: %v", err)
	}
}
