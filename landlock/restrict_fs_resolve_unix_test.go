//go:build linux

package landlock_test

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/landlock-lsm/go-landlock/landlock/lltest"
)

// TestResolveUnix verifies that the "resolve unix" access right
// (Landlock ABI v9) restricts connect(2) on pathname UNIX domain
// sockets created outside the Landlock domain, and permits it on
// paths which are explicitly allowed for it.
func TestResolveUnix(t *testing.T) {
	// The socket is created in the parent process before the test
	// subprocess starts, so that from the subprocess's point of
	// view, it is a UNIX server socket that was created outside of
	// its Landlock domain.  The path is passed to the subprocess
	// via an environment variable.
	const sockEnv = "LANDLOCK_TEST_RESOLVE_UNIX_SOCK"
	sockPath := os.Getenv(sockEnv)
	if !lltest.IsRunningInSubprocess() {
		sockPath = filepath.Join(t.TempDir(), "sock")
		t.Setenv(sockEnv, sockPath)
		ls, err := net.Listen("unix", sockPath)
		if err != nil {
			t.Fatalf("net.Listen(unix:%q): %v", sockPath, err)
		}
		defer ls.Close()
	}

	for _, tt := range []struct {
		Name    string
		Rule    landlock.Rule
		WantErr error
	}{
		{
			Name:    "WithoutResolveUnix",
			Rule:    landlock.RWFiles(sockPath),
			WantErr: syscall.EACCES,
		},
		{
			Name:    "WithResolveUnix",
			Rule:    landlock.RWFiles(sockPath).WithResolveUnix(),
			WantErr: nil,
		},
	} {
		t.Run(tt.Name, func(t *testing.T) {
			lltest.RunInSubprocess(t, func() {
				lltest.RequireABI(t, 9)

				if err := landlock.V9.RestrictPaths(tt.Rule); err != nil {
					t.Fatalf("Enabling Landlock: %v", err)
				}

				cs, err := net.Dial("unix", sockPath)
				if !errEqual(err, tt.WantErr) {
					t.Errorf("Dial(unix:%q): got err %q, want %q", sockPath, err, tt.WantErr)
				}
				if err == nil {
					cs.Close()
				}
			})
		})
	}
}
