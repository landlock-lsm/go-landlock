//go:build !linux

package landlock_test

import (
	"strings"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
)

func TestRestrictNonLinux_BestEffort(t *testing.T) {
	err := landlock.V3.BestEffort().RestrictPaths(
		landlock.RODirs("/"),
	)
	if err != nil {
		t.Errorf("expected success (downgraded to doing nothing)")
	}
}

func TestRestrictNonLinux_Strict(t *testing.T) {
	err := landlock.V3.RestrictPaths(
		landlock.RODirs("/"),
	)
	errStr := "missing kernel Landlock support"
	if !strings.Contains(err.Error(), errStr) {
		t.Errorf("expected error with %q, got %v", errStr, err)
	}
}
