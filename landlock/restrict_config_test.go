//go:build linux

package landlock_test

import (
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

func TestCustomConfig(t *testing.T) {
	RunInSubprocess(t, func() {
		RequireLandlockABI(t, 1)

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
