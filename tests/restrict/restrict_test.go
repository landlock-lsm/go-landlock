package landlock_test

import (
	"os"
	"sync"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
)

// True if the given path can be opened for reading.
func canAccess(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	return true
}

// Verify that Landlock applies to all system threads that belong to
// the current Go process. The raw landlock_restrict_self syscall only
// applies to the current system thread, but these are managed by the
// Go runtime and not easily controlled. The same issue has already
// been discussed in the context of seccomp at
// https://github.com/golang/go/issues/3405.
func TestRestrictInPresenceOfThreading(t *testing.T) {
	if !canAccess("/etc/passwd") {
		t.Skipf("expected normal accesses to /etc/passwd to work")
	}

	err := landlock.V1.RestrictPaths() // No access permitted at all.
	if err != nil {
		t.Skipf("kernel does not support Landlock v1; tests cannot be run.")
	}

	path := "/etc/passwd" // expected to exist and be openable

	var wg sync.WaitGroup
	defer wg.Wait()

	const (
		parallelism = 3
		attempts    = 10
	)
	for g := 0; g < parallelism; g++ {
		wg.Add(1)
		go func(grIdx int) {
			defer wg.Done()
			for i := 0; i < attempts; i++ {
				if canAccess(path) {
					t.Errorf("os.Open(%q): expected access denied, but it worked (goroutine %d, attempt %d)", path, grIdx, i)
				}
			}
		}(g)
	}
}
