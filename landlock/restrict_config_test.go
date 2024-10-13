//go:build linux

package landlock_test

import (
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/landlock-lsm/go-landlock/landlock/lltest"
	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

func TestCustomConfig(t *testing.T) {
	lltest.RunInSubprocess(t, func() {
		lltest.RequireABI(t, 1)

		pathRO := MakeSomeFile(t)
		pathNoAccess := MakeSomeFile(t)

		readFile := landlock.AccessFSSet(ll.AccessFSReadFile)
		if err := landlock.MustConfig(readFile).RestrictPaths(
			landlock.PathAccess(readFile, pathRO),
		); err != nil {
			t.Fatalf("Could not restrict paths: %v", err)
		}

		if err := openForRead(pathRO); err != nil {
			t.Errorf("openForRead(%q): %v", pathRO, err)
		}
		if err := openForRead(pathNoAccess); err == nil {
			t.Errorf("openForRead(%q) successful, want error", pathNoAccess)
		}
	})
}

func TestAbsurdDowngradeCase(t *testing.T) {
	// This is a regression test for a bug where:
	//
	// - we run on a kernel that supports Landlock but does not
	//   support the truncate access right
	// - Go-Landlock will "downgrade" the file system rule to "no access rights",
	//   because the requested access right "truncate" is not supported.
	// - It should not try to add that rule (but it used to).
	if v, err := ll.LandlockGetABIVersion(); err != nil || v <= 0 || v > 2 {
		t.Skipf("Requires Landlock version 1 or 2, got V%v (err=%v)", v, err)
	}

	lltest.RunInSubprocess(t, func() {
		cfg := landlock.MustConfig(
			landlock.AccessFSSet(ll.AccessFSTruncate | ll.AccessFSMakeDir),
		).BestEffort()

		path := MakeSomeFile(t)
		err := cfg.Restrict(landlock.PathAccess(ll.AccessFSTruncate, path))
		if err != nil {
			t.Errorf("Landlock restriction error: %v", err)
		}
	})

}
