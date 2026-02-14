//go:build linux

package landlock_test

import (
	"os"
	"syscall"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/landlock-lsm/go-landlock/landlock/lltest"
	"golang.org/x/sys/unix"
)

func TestIoctlDev(t *testing.T) {
	const (
		path     = "/dev/zero"
		FIONREAD = 0x541b
	)
	for _, tt := range []struct {
		Name    string
		Rule    landlock.Rule
		WantErr error
	}{
		{
			Name:    "WithoutIoctlDev",
			Rule:    landlock.RWFiles(path),
			WantErr: syscall.EACCES,
		},
		{
			Name: "WithIoctlDev",
			Rule: landlock.RWFiles(path).WithIoctlDev(),
			// ENOTTY means that the IOCTL was dispatched
			// to device.  (Would be nicer to find an
			// IOCTL that returns success here, but the
			// available devices on qemu are limited.)
			WantErr: syscall.ENOTTY,
		},
	} {
		t.Run(tt.Name, func(t *testing.T) {
			lltest.RunInSubprocess(t, func() {
				lltest.RequireABI(t, 5)

				err := landlock.V5.BestEffort().RestrictPaths(tt.Rule)
				if err != nil {
					t.Fatalf("Enabling Landlock: %v", err)
				}

				f, err := os.Open(path)
				if err != nil {
					t.Fatalf("os.Open(%q): %v", path, err)
				}
				defer func() { f.Close() }()

				_, err = unix.IoctlGetInt(int(f.Fd()), FIONREAD)
				if !errEqual(err, tt.WantErr) {
					t.Errorf("ioctl(%v, FIONREAD): got err «%v», want «%v»", f, err, tt.WantErr)
				}
			})
		})
	}
}
