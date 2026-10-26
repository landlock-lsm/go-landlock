//go:build linux

package syscall

import (
	"os"
	"strconv"
	"testing"
)

// TestKernelABIVersion checks that the kernel provides the Landlock ABI
// version given in $LANDLOCK_GO_TEST_ABI.
//
// This is used when testing against a matrix of kernels, so that a
// misconfigured kernel does not lead to silently skipped tests.
func TestKernelABIVersion(t *testing.T) {
	env := os.Getenv("LANDLOCK_GO_TEST_ABI")
	if env == "" {
		t.Skip("LANDLOCK_GO_TEST_ABI is not set")
	}
	want, err := strconv.Atoi(env)
	if err != nil {
		t.Fatalf("Invalid LANDLOCK_GO_TEST_ABI=%q: %v", env, err)
	}

	got, err := LandlockGetABIVersion()
	if err != nil {
		// Landlock is unsupported or disabled.
		got = 0
	}
	if got != want {
		t.Errorf("LandlockGetABIVersion() = %v (err: %v), want %v", got, err, want)
	}
}
