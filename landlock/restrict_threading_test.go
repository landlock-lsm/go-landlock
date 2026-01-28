//go:build linux

package landlock_test

import (
	"sync"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/landlock-lsm/go-landlock/landlock/lltest"
)

// Verify that Landlock applies to all system threads that belong to
// the current Go process. The raw landlock_restrict_self syscall only
// applies to the current system thread, but these are managed by the
// Go runtime and not easily controlled. The same issue has already
// been discussed in the context of seccomp at
// https://github.com/golang/go/issues/3405.
func TestRestrictInPresenceOfThreading(t *testing.T) {
	lltest.RunInSubprocess(t, func() {
		lltest.RequireABI(t, 1)

		fpath := MakeSomeFile(t)

		err := landlock.V1.RestrictPaths() // No access permitted at all.
		if err != nil {
			t.Skipf("kernel does not support Landlock v1; tests cannot be run.")
		}

		var wg sync.WaitGroup
		defer wg.Wait()

		const (
			parallelism = 3
			attempts    = 10
		)
		for range parallelism {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range attempts {
					if err := openForRead(fpath); err == nil {
						t.Errorf("openForRead(%q) successful, want error", fpath)
					}
				}
			}()
		}
	})
}
