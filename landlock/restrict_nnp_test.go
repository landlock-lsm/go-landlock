//go:build linux

package landlock_test

import (
	"runtime"
	"sync"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/landlock-lsm/go-landlock/landlock/lltest"
	"golang.org/x/sys/unix"
)

// Verify that enforcing a Landlock ruleset sets the no_new_privs
// attribute on all system threads of the Go process.  Depending on
// the Landlock ABI version, this is done with prctl(2) or as part of
// landlock_restrict_self(2).
func TestRestrictSetsNoNewPrivs(t *testing.T) {
	lltest.RunInSubprocess(t, func() {
		lltest.RequireABI(t, 1)

		if err := landlock.V1.RestrictPaths(); err != nil {
			t.Fatalf("landlock.V1.RestrictPaths() = %v, want nil", err)
		}

		var wg sync.WaitGroup
		defer wg.Wait()

		const parallelism = 5
		for range parallelism {
			wg.Go(func() {
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()

				got, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
				if err != nil {
					t.Errorf("prctl(PR_GET_NO_NEW_PRIVS): %v", err)
					return
				}
				if got != 1 {
					t.Errorf("prctl(PR_GET_NO_NEW_PRIVS) = %v, want 1", got)
				}
			})
		}
	})
}
