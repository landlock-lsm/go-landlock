//go:build linux

package landlock_test

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/landlock-lsm/go-landlock/landlock/lltest"
	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

func TestRestrictNet(t *testing.T) {
	const (
		cPort = 4242
		bPort = 4343
	)

	for _, tt := range []struct {
		Name           string
		EnableLandlock func() error
		RequiredABI    int
		WantConnectErr error
		WantBindErr    error
	}{
		{
			Name:        "ABITooOld",
			RequiredABI: 3,
			EnableLandlock: func() error {
				return landlock.V3.RestrictNet()
			},
			WantConnectErr: nil,
			WantBindErr:    nil,
		},
		{
			Name:        "ABITooOldWithDowngrade",
			RequiredABI: 3,
			EnableLandlock: func() error {
				return landlock.V3.BestEffort().RestrictNet()
			},
			WantConnectErr: nil,
			WantBindErr:    nil,
		},
		{
			Name:        "RestrictingPathsShouldNotBreakNetworking",
			RequiredABI: 1,
			EnableLandlock: func() error {
				return landlock.V4.BestEffort().RestrictPaths(
					landlock.ROFiles("/etc/hosts"),
				)
			},
			WantConnectErr: nil,
			WantBindErr:    nil,
		},
		{
			Name:        "RestrictingBindButConnectShouldWork",
			RequiredABI: 4,
			EnableLandlock: func() error {
				return landlock.MustConfig(
					landlock.AccessNetSet(ll.AccessNetBindTCP),
				).RestrictNet()
			},
			WantConnectErr: nil,
			WantBindErr:    syscall.EACCES,
		},
		{
			Name:        "RestrictingConnectButBindShouldWork",
			RequiredABI: 4,
			EnableLandlock: func() error {
				return landlock.MustConfig(
					landlock.AccessNetSet(ll.AccessNetConnectTCP),
				).RestrictNet()
			},
			WantConnectErr: syscall.EACCES,
			WantBindErr:    nil,
		},
		{
			Name:        "PermitTheConnectPort",
			RequiredABI: 4,
			EnableLandlock: func() error {
				return landlock.V4.RestrictNet(landlock.ConnectTCP(cPort))
			},
			WantConnectErr: nil,
			WantBindErr:    syscall.EACCES,
		},
		{
			Name:        "PermitTheBindPort",
			RequiredABI: 4,
			EnableLandlock: func() error {
				return landlock.V4.RestrictNet(landlock.BindTCP(bPort))
			},
			WantConnectErr: syscall.EACCES,
			WantBindErr:    nil,
		},
		{
			Name:        "PermitBothPorts",
			RequiredABI: 4,
			EnableLandlock: func() error {
				return landlock.V4.RestrictNet(
					landlock.BindTCP(bPort),
					landlock.ConnectTCP(cPort),
				)
			},
			WantConnectErr: nil,
			WantBindErr:    nil,
		},
		{
			Name:        "PermitTheWrongPorts",
			RequiredABI: 4,
			EnableLandlock: func() error {
				return landlock.V4.RestrictNet(
					landlock.BindTCP(bPort+1),
					landlock.ConnectTCP(cPort+1),
				)
			},
			WantConnectErr: syscall.EACCES,
			WantBindErr:    syscall.EACCES,
		},
	} {
		t.Run(tt.Name, func(t *testing.T) {
			lltest.RunInSubprocess(t, func() {
				lltest.RequireABI(t, tt.RequiredABI)

				// Set up a service that we can dial for the test.
				runBackgroundService(t, "tcp", fmt.Sprintf("localhost:%v", cPort))

				err := tt.EnableLandlock()
				if err != nil {
					t.Fatalf("Enabling Landlock: %v", err)
				}

				if err := tryDial(cPort); !errEqual(err, tt.WantConnectErr) {
					t.Errorf("net.Dial(tcp, localhost:%v) = «%v»; want «%v»", cPort, err, tt.WantConnectErr)
				}
				if err := trySinglePathListen(bPort); !errEqual(err, tt.WantBindErr) {
					t.Errorf("net.Listen(single-path tcp, localhost:%v) = «%v»; want «%v»", bPort, err, tt.WantBindErr)
				}
			})
		})
	}
}

func runBackgroundService(t *testing.T, network, addr string) {
	l, err := net.Listen(network, addr)
	if err != nil {
		t.Fatalf("net.Listen: Failed to set up local service to connect to: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				// Return on error (e.g. if l gets closed asynchronously)
				return
			}
			c.Close()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		wg.Wait()
	})
}

func tryDial(port int) error {
	conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%v", port))
	if err == nil {
		conn.Close()
	}
	return err
}

func trySinglePathListen(port int) error {
	var lc net.ListenConfig
	lc.SetMultipathTCP(false)
	conn, err := lc.Listen(context.Background(), "tcp", fmt.Sprintf("localhost:%v", port))
	if err == nil {
		conn.Close()
	}
	return err
}
