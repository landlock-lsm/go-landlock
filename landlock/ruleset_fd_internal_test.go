//go:build linux

package landlock

import (
	"syscall"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock/lltest"
)

func TestCreateRuleset_DowngradesFlags(t *testing.T) {
	lltest.RequireABI(t, 6)

	// Pretend to run on a V6 kernel, which does not support the
	// logging flags.  In best effort mode, they get dropped.
	c := V7.BestEffort().EnableLoggingForSubprocesses()
	fd, eff, err := createRuleset(c, abiInfos[6], nil)
	if err != nil {
		t.Fatalf("createRuleset: %v", err)
	}
	defer syscall.Close(fd)

	if eff.flags != 0 {
		t.Errorf("createRuleset: got effective flags %v, want none", eff.flags)
	}
	if eff.HandledAccessFS != V6.HandledAccessFS {
		t.Errorf("createRuleset: got handled FS access %v, want %v", eff.HandledAccessFS, V6.HandledAccessFS)
	}
}
