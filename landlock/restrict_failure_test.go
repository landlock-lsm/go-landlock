package landlock_test

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

func RequireLandlockABI(t testing.TB, want int) {
	t.Helper()

	if v, err := ll.LandlockGetABIVersion(); err != nil || v < want {
		t.Skipf("Requires Landlock >= V%v, got V%v (err=%v)", want, v, err)
	}
}

func MustWriteFile(t testing.TB, path string) {
	t.Helper()

	if err := os.WriteFile(path, []byte("somecontent"), 0600); err != nil {
		t.Fatalf("os.WriteFile(%q, ...): %v", path, err)
	}
}

func MustMkdir(t testing.TB, path string) {
	t.Helper()

	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatalf("os.Mkdir(%q): %v", path, err)
	}
}

// TempDir is a replacement for t.TempDir() to be used in Landlock tests.
// If we were using t.TempDir(), the test framework would try to remove it
// after the test, even in Landlocked subprocess tests where this fails.
//
// TODO: It would be nicer if all tests could just use t.TempDir()
// without the test framework trying to delete these later in the subprocesses.
func TempDir(t testing.TB) string {
	t.Helper()

	if IsRunningInSubprocess {
		dir, err := os.MkdirTemp("", "LandlockTestTempDir")
		if err != nil {
			t.Fatalf("os.MkdirTemp: %v", err)
		}
		return dir
	}
	return t.TempDir()
}

func MakeSomeFile(t testing.TB) string {
	t.Helper()
	fpath := filepath.Join(TempDir(t), "somefile")
	MustWriteFile(t, fpath)
	return fpath
}

func TestPathDoesNotExist(t *testing.T) {
	RequireLandlockABI(t, 1)

	doesNotExistPath := filepath.Join(t.TempDir(), "does_not_exist")

	err := landlock.V1.RestrictPaths(
		landlock.RODirs(doesNotExistPath),
	)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected 'not exist' error, got: %v", err)
	}
}

func TestPathDoesNotExist_Ignored(t *testing.T) {
	RunInSubprocess(t, func() {
		RequireLandlockABI(t, 1)

		doesNotExistPath := filepath.Join(TempDir(t), "does_not_exist")

		err := landlock.V1.RestrictPaths(
			landlock.RODirs(doesNotExistPath).IgnoreIfMissing(),
		)
		if err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
	})
}

func TestRestrictingPlainFileWithDirectoryFlags(t *testing.T) {
	RequireLandlockABI(t, 1)

	fpath := MakeSomeFile(t)

	err := landlock.V1.RestrictPaths(
		landlock.RODirs(fpath),
	)
	if !errors.Is(err, unix.EINVAL) {
		t.Errorf("expected 'invalid argument' error, got: %v", err)
	}
}

func TestEmptyAccessRights(t *testing.T) {
	RequireLandlockABI(t, 1)

	fpath := MakeSomeFile(t)

	err := landlock.V1.RestrictPaths(
		landlock.PathAccess(0, fpath),
	)
	if !errors.Is(err, unix.ENOMSG) {
		t.Errorf("expected ENOMSG, got: %v", err)
	}
	want := "empty access rights"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("expected error message with %q, got: %v", want, err)
	}
}

func TestOverlyBroadFSRule(t *testing.T) {
	RequireLandlockABI(t, 1)

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
	RequireLandlockABI(t, 1)

	// 'refer' is incompatible with Landlock ABI V1.
	// Users should use Landlock V2 instead or construct a custom
	// config that handles the 'refer' access right.
	// You can technically also just enable V1 best-effort mode,
	// but that combination always falls back to "no enforcement".
	for _, rule := range []landlock.Rule{
		landlock.RWDirs("/etc").WithRefer(),
		landlock.PathAccess(0, "/etc").WithRefer(),
	} {
		err := landlock.V1.RestrictPaths(rule)
		if !errors.Is(err, unix.EINVAL) {
			t.Errorf("expected 'invalid argument' error, got: %v", err)
		}
		if !strings.Contains(err.Error(), "incompatible rule") {
			t.Errorf("expected a 'incompatible rule' error, got: %v", err)
		}
	}
}
