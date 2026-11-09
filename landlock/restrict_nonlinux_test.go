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
		t.Errorf("Expected success (downgraded to doing nothing)")
	}
}

func TestRestrictNonLinux_Strict(t *testing.T) {
	err := landlock.V3.RestrictPaths(
		landlock.RODirs("/"),
	)
	errStr := "missing kernel Landlock support"
	if !strings.Contains(err.Error(), errStr) {
		t.Errorf("Expected error with %q, got %v", errStr, err)
	}
}

func TestRestrictNonLinux_UnknownAccessRights(t *testing.T) {
	cfg := landlock.Config{HandledAccessFS: 1 << 63}
	for _, c := range []landlock.Config{cfg, cfg.BestEffort()} {
		err := c.RestrictPaths(landlock.RODirs("/"))
		errStr := "upgrade go-landlock"
		if err == nil || !strings.Contains(err.Error(), errStr) {
			t.Errorf("Expected error with %q, got %v", errStr, err)
		}
	}
}

func TestNewRulesetFDNonLinux_BestEffort(t *testing.T) {
	fd, flags, err := landlock.V3.BestEffort().NewRulesetFD(landlock.RODirs("/"))
	if fd != -1 || flags != 0 || err != nil {
		t.Errorf("NewRulesetFD() = (%v, %#x, %v), want (-1, 0, nil)", fd, flags, err)
	}
}

func TestNewRulesetFDNonLinux_Strict(t *testing.T) {
	fd, flags, err := landlock.V3.NewRulesetFD(landlock.RODirs("/"))
	errStr := "missing kernel Landlock support"
	if err == nil || !strings.Contains(err.Error(), errStr) {
		t.Errorf("Expected error with %q, got %v", errStr, err)
	}
	if fd != -1 || flags != 0 {
		t.Errorf("NewRulesetFD() = (%v, %#x, _), want (-1, 0, _)", fd, flags)
	}
}
