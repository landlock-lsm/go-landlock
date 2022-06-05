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
	"golang.org/x/sys/unix"
)

func TestPathDoesNotExist(t *testing.T) {
	doesNotExistPath := filepath.Join(t.TempDir(), "does_not_exist")

	err := landlock.V1.RestrictPaths(
		landlock.RODirs(doesNotExistPath),
	)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected 'not exist' error, got: %v", err)
	}
}

func TestRestrictingPlainFileWithDirectoryFlags(t *testing.T) {
	err := landlock.V1.RestrictPaths(
		landlock.RODirs("/etc/passwd"),
	)
	if !errors.Is(err, unix.EINVAL) {
		t.Errorf("expected 'invalid argument' error, got: %v", err)
	}
}

func TestEmptyAccessRights(t *testing.T) {
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
	handled := landlock.AccessFSSet(0b011)
	excempt := landlock.AccessFSSet(0b111) // superset of handled!
	err := landlock.MustConfig(handled).RestrictPaths(
		landlock.PathAccess(excempt, "/tmp"),
	)
	if !errors.Is(err, unix.EINVAL) {
		t.Errorf("expected 'invalid argument' error, got: %v", err)
	}
}

func TestReferNotPermittedInStrictV1(t *testing.T) {
	// 'refer' is incompatible with Landlock ABI V1.
	// Users should use Landlock V2 instead or construct a custom
	// config that handles the 'refer' access right.
	// You can technically also just enable V1 best-effort mode,
	// but that combination always falls back to "no enforcement".
	for _, opt := range []landlock.PathOpt{
		landlock.RWDirs("/etc").WithRefer(),
		landlock.PathAccess(0, "/etc").WithRefer(),
	}{
		err := landlock.V1.RestrictPaths(opt)
		if !errors.Is(err, unix.EINVAL) {
			t.Errorf("expected 'invalid argument' error, got: %v", err)
		}
		if !strings.Contains(err.Error(), "too broad option") {
			t.Errorf("expected a 'too broad option' error, got: %v", err)
		}
	}
}
