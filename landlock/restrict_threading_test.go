package landlock_test

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
)

// Verify that Landlock applies to all system threads that belong to
// the current Go process. The raw landlock_restrict_self syscall only
// applies to the current system thread, but these are managed by the
// Go runtime and not easily controlled. The same issue has already
// been discussed in the context of seccomp at
// https://github.com/golang/go/issues/3405.
func TestRestrictInPresenceOfThreading(t *testing.T) {
	RunInSubprocess(t, func() {
		RequireLandlockABI(t, 1)

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
		for g := 0; g < parallelism; g++ {
			wg.Add(1)
			go func(grIdx int) {
				defer wg.Done()
				for i := 0; i < attempts; i++ {
					assertEacces(t, openForRead(fpath), "os.Open()")
				}
			}(g)
		}
	})
}

var IsRunningInSubprocess = false

// RunInSubprocess runs the given test function in a subprocess
// and forwards its output.
func RunInSubprocess(t *testing.T, f func()) {
	if os.Getenv("IS_SUBPROCESS") != "" {
		IsRunningInSubprocess = true
		f()
		return
	}

	args := append(os.Args[1:], "-test.run="+regexp.QuoteMeta(t.Name()))

	// Make sure that the parent process cleans up the actual TempDir.
	// If the child process uses t.TempDir(), it'll create it in $TMPDIR.
	t.Setenv("TMPDIR", t.TempDir())

	t.Setenv("IS_SUBPROCESS", "yes")
	buf, err := exec.Command(os.Args[0], args...).Output()

	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("Could not execute test in subprocess: %v", err)
	}

	lines := strings.Split(string(buf), "\n")
	for _, l := range lines {
		if l == "FAIL" {
			defer func() { t.Error("Test failed in subprocess") }()
			continue
		}
		if strings.HasPrefix(l, "--- SKIP") {
			defer func() { t.Skip("Test skipped in subprocess") }()
			continue
		}
		if strings.HasPrefix(l, "===") || strings.HasPrefix(l, "---") || l == "PASS" || l == "" {
			continue
		}
		fmt.Println(l)
	}
}
