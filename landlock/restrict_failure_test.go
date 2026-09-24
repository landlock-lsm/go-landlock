//go:build linux

package landlock_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/landlock-lsm/go-landlock/landlock/lltest"
	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

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

func MakeSomeFile(t testing.TB) string {
	t.Helper()
	fpath := filepath.Join(lltest.TempDir(t), "somefile")
	MustWriteFile(t, fpath)
	return fpath
}

func TestPathDoesNotExist(t *testing.T) {
	lltest.RequireABI(t, 1)

	doesNotExistPath := filepath.Join(t.TempDir(), "does_not_exist")

	err := landlock.V1.RestrictPaths(
		landlock.RODirs(doesNotExistPath),
	)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Want 'not exist' error, got: %v", err)
	}
}

func TestPathDoesNotExist_Ignored(t *testing.T) {
	lltest.RunInSubprocess(t, func() {
		lltest.RequireABI(t, 1)

		doesNotExistPath := filepath.Join(lltest.TempDir(t), "does_not_exist")

		err := landlock.V1.RestrictPaths(
			landlock.RODirs(doesNotExistPath).IgnoreIfMissing(),
		)
		if err != nil {
			t.Errorf("Want no error, got: %v", err)
		}
	})
}

func TestRestrictingPlainFileWithDirectoryFlags(t *testing.T) {
	lltest.RequireABI(t, 1)

	fpath := MakeSomeFile(t)

	err := landlock.V1.RestrictPaths(
		landlock.RODirs(fpath),
	)
	if !errors.Is(err, unix.EINVAL) {
		t.Errorf("Want 'invalid argument' error, got: %v", err)
	}
	if isGoLandlockBug(err) {
		t.Errorf("Should not be marked as a go-landlock bug, but was: %v", err)
	}
}

func isGoLandlockBug(err error) bool {
	return strings.Contains(err.Error(), "BUG(go-landlock)")
}

func TestEmptyAccessRights(t *testing.T) {
	lltest.RequireABI(t, 1)

	lltest.RunInSubprocess(t, func() {
		fpath := MakeSomeFile(t)

		err := landlock.V1.RestrictPaths(
			landlock.PathAccess(0, fpath),
		)
		if err != nil {
			t.Errorf("Want success, got: %v", err)
		}
	})
}

func TestOverlyBroadFSRule(t *testing.T) {
	lltest.RequireABI(t, 1)

	handled := landlock.AccessFSSet(0b011)
	excempt := landlock.AccessFSSet(0b111) // superset of handled!
	err := landlock.MustConfig(handled).RestrictPaths(
		landlock.PathAccess(excempt, "/tmp"),
	)
	if !errors.Is(err, unix.EINVAL) {
		t.Errorf("Want 'invalid argument' error, got: %v", err)
	}
}

func TestReferNotPermittedInStrictV1(t *testing.T) {
	lltest.RequireABI(t, 1)

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
			t.Errorf("Want 'invalid argument' error, got: %v", err)
		}
		if !strings.Contains(err.Error(), "incompatible rule") {
			t.Errorf("Want a 'incompatible rule' error, got: %v", err)
		}
	}
}

// Unknown access rights are rejected, also in best effort mode.
// No RequireABI: the Config is rejected before any syscall.
func TestUnknownAccessRights(t *testing.T) {
	const (
		unknownFS     = landlock.AccessFSSet(1 << 63)
		unknownNet    = landlock.AccessNetSet(1 << 63)
		unknownScoped = landlock.ScopedSet(1 << 63)
	)

	for _, tc := range []struct {
		name    string
		cfg     landlock.Config
		enforce func(landlock.Config) error
	}{
		{
			name:    "RestrictPaths",
			cfg:     landlock.Config{HandledAccessFS: ll.AccessFSReadFile | unknownFS},
			enforce: func(c landlock.Config) error { return c.RestrictPaths(landlock.RODirs("/")) },
		},
		{
			name:    "RestrictNet",
			cfg:     landlock.Config{HandledAccessNet: ll.AccessNetConnectTCP | unknownNet},
			enforce: func(c landlock.Config) error { return c.RestrictNet(landlock.ConnectTCP(53)) },
		},
		{
			name:    "RestrictScoped",
			cfg:     landlock.Config{Scoped: ll.ScopeSignal | unknownScoped},
			enforce: func(c landlock.Config) error { return c.RestrictScoped() },
		},
		{
			name:    "Restrict",
			cfg:     landlock.Config{HandledAccessFS: unknownFS},
			enforce: func(c landlock.Config) error { return c.Restrict(landlock.RODirs("/")) },
		},
	} {
		for _, mode := range []struct {
			name string
			cfg  landlock.Config
		}{
			{name: "strict", cfg: tc.cfg},
			{name: "best_effort", cfg: tc.cfg.BestEffort()},
		} {
			t.Run(tc.name+"_"+mode.name, func(t *testing.T) {
				err := tc.enforce(mode.cfg)
				if err == nil {
					t.Fatalf("Want 'invalid argument' error, got success")
				}
				if !errors.Is(err, unix.EINVAL) {
					t.Errorf("Want 'invalid argument' error, got: %v", err)
				}
				if !strings.Contains(err.Error(), "upgrade go-landlock") {
					t.Errorf("Want an 'upgrade go-landlock' error, got: %v", err)
				}
				if isGoLandlockBug(err) {
					t.Errorf("Should not be marked as a go-landlock bug, but was: %v", err)
				}
			})
		}
	}
}
