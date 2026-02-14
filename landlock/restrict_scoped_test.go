//go:build linux

package landlock_test

import (
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/landlock-lsm/go-landlock/landlock/lltest"
	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

func TestRestrictScoped(t *testing.T) {
	const name = "@abstract/go-landlock/test"

	// Bring up an abstract Unix Domain Socket service in the
	// parent process, which the subprocesses can dial.
	if !lltest.IsRunningInSubprocess() {
		ls, err := net.Listen("unix", name)
		if err != nil {
			t.Fatalf("net.Listen(unix:%q): %v", name, err)
		}
		defer ls.Close()
	}

	for _, tt := range []struct {
		Name           string
		EnableLandlock func() error
		RequiredABI    int
		WantDialErr    error
		WantKillErr    error
	}{
		{
			Name:           "Unrestricted",
			RequiredABI:    0,
			EnableLandlock: func() error { return nil },
		},
		{
			Name:        "RestrictAbstractUnixSockets",
			RequiredABI: 6,
			EnableLandlock: func() error {
				return landlock.MustConfig(
					landlock.ScopedSet(ll.ScopeAbstractUnixSocket),
				).Restrict()
			},
			WantDialErr: syscall.EPERM,
		},
		{
			Name:        "RestrictSignal",
			RequiredABI: 6,
			EnableLandlock: func() error {
				return landlock.MustConfig(
					landlock.ScopedSet(ll.ScopeSignal),
				).Restrict()
			},
			WantKillErr: syscall.EPERM,
		},
		{
			Name:        "RestrictAll",
			RequiredABI: 6,
			EnableLandlock: func() error {
				return landlock.V6.RestrictScoped()
			},
			WantDialErr: syscall.EPERM,
			WantKillErr: syscall.EPERM,
		},
	} {
		t.Run(tt.Name, func(t *testing.T) {
			lltest.RunInSubprocess(t, func() {
				lltest.RequireABI(t, tt.RequiredABI)

				err := tt.EnableLandlock()
				if err != nil {
					t.Fatalf("Enabling Landlock: %v", err)
				}

				cs, err := net.Dial("unix", name)
				if want := tt.WantDialErr; !errEqual(err, want) {
					t.Errorf("Dial(unix:%q): err=%q, want %q", name, err, want)
				}
				if err == nil {
					defer cs.Close()
				}

				killErr := syscall.Kill(os.Getppid(), syscall.SIGUSR1)
				if want := tt.WantKillErr; killErr != want {
					t.Errorf("Kill(ppid, USR1): err=%q, want %q", killErr, want)
				}
			})
		})
	}
}
