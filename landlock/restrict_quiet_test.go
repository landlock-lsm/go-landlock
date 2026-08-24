//go:build linux

package landlock_test

import (
	"path/filepath"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/landlock-lsm/go-landlock/landlock/lltest"
	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

func TestQuietPathsWithRestrictPaths(t *testing.T) {
	lltest.RunInSubprocess(t, func() {
		dir := lltest.TempDir(t)

		cfg := landlock.V10.QuietAll().BestEffort()
		if err := cfg.RestrictPaths(
			landlock.RODirs(dir),
			landlock.QuietPaths(dir),
		); err != nil {
			t.Errorf("%v.RestrictPaths(): unexpected error: %v", cfg, err)
		}
	})
}

func TestQuietPortsWithRestrictNet(t *testing.T) {
	lltest.RunInSubprocess(t, func() {
		cfg := landlock.V10.QuietAll().BestEffort()
		if err := cfg.RestrictNet(
			landlock.BindTCP(8080),
			landlock.QuietPorts(631),
		); err != nil {
			t.Errorf("%v.RestrictNet(): unexpected error: %v", cfg, err)
		}
	})
}

func TestQuietRulesRequireQuietAll(t *testing.T) {
	lltest.RunInSubprocess(t, func() {
		dir := lltest.TempDir(t)

		// Best effort mode does not excuse the missing
		// Config.QuietAll(): The rule would silently not do
		// what the caller asked for.
		for _, tt := range []struct {
			name string
			cfg  landlock.Config
			rule landlock.Rule
		}{
			{"QuietPaths", landlock.V10.BestEffort(), landlock.QuietPaths(dir)},
			{"QuietPorts", landlock.V10.BestEffort(), landlock.QuietPorts(631)},
		} {
			t.Run(tt.name, func(t *testing.T) {
				if err := tt.cfg.Restrict(tt.rule); err == nil {
					t.Errorf("%v.Restrict(%v) succeeded, want error", tt.cfg, tt.rule)
				}
			})
		}
	})
}

func TestQuietAllWithoutKernelSupport(t *testing.T) {
	if v, err := ll.LandlockGetABIVersion(); err != nil || v >= 10 {
		t.Skipf("Requires Landlock < V10, got V%v (err=%v)", v, err)
	}

	lltest.RunInSubprocess(t, func() {
		cfg := landlock.V10.QuietAll()
		if err := cfg.Restrict(); err == nil {
			t.Errorf("%v.Restrict() succeeded, want error on a kernel without quieting support", cfg)
		}
	})
}

func TestQuietingDoesNotGrantAccess(t *testing.T) {
	lltest.RunInSubprocess(t, func() {
		lltest.RequireABI(t, 10)

		readableDir := lltest.TempDir(t)
		quietFile := MakeSomeFile(t)

		cfg := landlock.V10.QuietAll()
		if err := cfg.Restrict(
			landlock.RODirs(readableDir),
			landlock.QuietPaths(quietFile),
			landlock.QuietPorts(631),
		); err != nil {
			t.Fatalf("%v.Restrict(): unexpected error: %v", cfg, err)
		}

		if err := openForRead(quietFile); err == nil {
			t.Errorf("openForRead(%q) succeeded, want error: quieting must not grant access", quietFile)
		}
	})
}

func TestQuietPathsIgnoreIfMissing(t *testing.T) {
	lltest.RunInSubprocess(t, func() {
		lltest.RequireABI(t, 10)

		missing := filepath.Join(lltest.TempDir(t), "does_not_exist")
		cfg := landlock.V10.QuietAll()

		// Without the modifier, the missing path is an error.
		if err := cfg.Restrict(landlock.QuietPaths(missing)); err == nil {
			t.Errorf("Restrict(QuietPaths(%q)) succeeded, want error", missing)
		}

		// With the modifier, the missing path is skipped.
		if err := cfg.Restrict(landlock.QuietPaths(missing).IgnoreIfMissing()); err != nil {
			t.Errorf("Restrict(QuietPaths(%q).IgnoreIfMissing()): unexpected error: %v", missing, err)
		}
	})
}
