//go:build linux

package landlock_test

import (
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/landlock-lsm/go-landlock/landlock/lltest"
	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// TestRestrictNetUDP verifies the Landlock V10 access rights for UDP
// sockets.
//
// The three probes exercise the three UDP operations that Landlock
// distinguishes: an explicit bind(2) on a fixed local port, a
// connect(2) which implicitly autobinds an ephemeral local port, and a
// sendto(2) on a socket which was already bound before enforcement.
func TestRestrictNetUDP(t *testing.T) {
	const (
		bPort = 4444 // the local port that gets bind(2)-ed
		cPort = 4545 // the remote port that gets connect(2)-ed and sent to
	)

	bindUDP := landlock.AccessNetSet(ll.AccessNetBindUDP)
	connectSendUDP := landlock.AccessNetSet(ll.AccessNetConnectSendUDP)
	tcpOnly := landlock.AccessNetSet(ll.AccessNetBindTCP | ll.AccessNetConnectTCP)

	for _, tt := range []struct {
		Name           string
		EnableLandlock func() error
		WantBindErr    error
		WantDialErr    error
		WantSendErr    error
	}{
		{
			Name:           "V9DoesNotRestrictUDP",
			EnableLandlock: func() error { return landlock.V9.RestrictNet() },
		},
		{
			Name:           "TCPRightsDoNotRestrictUDP",
			EnableLandlock: func() error { return landlock.MustConfig(tcpOnly).RestrictNet() },
		},
		{
			Name:           "BindUDPWithoutRules",
			EnableLandlock: func() error { return landlock.MustConfig(bindUDP).RestrictNet() },
			WantBindErr:    syscall.EACCES,
			WantDialErr:    syscall.EACCES, // connect(2) autobinds an ephemeral port
		},
		{
			Name:           "PermitTheBindPort",
			EnableLandlock: func() error { return landlock.MustConfig(bindUDP).RestrictNet(landlock.BindUDP(bPort)) },
			WantDialErr:    syscall.EACCES, // the ephemeral autobind port is still denied
		},
		{
			Name:           "PermitTheWrongBindPort",
			EnableLandlock: func() error { return landlock.MustConfig(bindUDP).RestrictNet(landlock.BindUDP(bPort + 1)) },
			WantBindErr:    syscall.EACCES,
			WantDialErr:    syscall.EACCES,
		},
		{
			Name:           "PermitEphemeralAutobind",
			EnableLandlock: func() error { return landlock.MustConfig(bindUDP).RestrictNet(landlock.BindUDP(0)) },
			WantBindErr:    syscall.EACCES,
		},
		{
			Name:           "ConnectSendUDPWithoutRules",
			EnableLandlock: func() error { return landlock.MustConfig(connectSendUDP).RestrictNet() },
			WantDialErr:    syscall.EACCES,
			WantSendErr:    syscall.EACCES,
		},
		{
			Name: "PermitTheConnectSendPort",
			EnableLandlock: func() error {
				return landlock.MustConfig(connectSendUDP).RestrictNet(landlock.ConnectSendUDP(cPort))
			},
		},
		{
			Name: "PermitTheWrongConnectSendPort",
			EnableLandlock: func() error {
				return landlock.MustConfig(connectSendUDP).RestrictNet(landlock.ConnectSendUDP(cPort + 1))
			},
			WantDialErr: syscall.EACCES,
			WantSendErr: syscall.EACCES,
		},
		{
			Name:           "V10WithoutRules",
			EnableLandlock: func() error { return landlock.V10.RestrictNet() },
			WantBindErr:    syscall.EACCES,
			WantDialErr:    syscall.EACCES,
			WantSendErr:    syscall.EACCES,
		},
		{
			Name: "V10WithRules",
			EnableLandlock: func() error {
				return landlock.V10.RestrictNet(
					landlock.BindUDP(bPort),
					landlock.BindUDP(0),
					landlock.ConnectSendUDP(cPort),
				)
			},
		},
	} {
		t.Run(tt.Name, func(t *testing.T) {
			lltest.RunInSubprocess(t, func() {
				lltest.RequireABI(t, 10)

				// Set up a service that we can send datagrams to.
				runBackgroundPacketService(t, udpAddr(cPort))

				// A socket which is already bound before
				// enforcement, so that the sendto(2) probe
				// below is unaffected by the bind rights.
				sender := listenPacket(t, udpAddr(0))

				if err := tt.EnableLandlock(); err != nil {
					t.Fatalf("Enabling Landlock: %v", err)
				}

				if err := tryUDPBind(bPort); !errEqual(err, tt.WantBindErr) {
					t.Errorf("net.ListenPacket(udp, %v) = «%v»; want «%v»", udpAddr(bPort), err, tt.WantBindErr)
				}
				if err := tryUDPDial(cPort); !errEqual(err, tt.WantDialErr) {
					t.Errorf("net.Dial(udp, %v) = «%v»; want «%v»", udpAddr(cPort), err, tt.WantDialErr)
				}
				if err := trySendTo(sender, cPort); !errEqual(err, tt.WantSendErr) {
					t.Errorf("PacketConn.WriteTo(%v) = «%v»; want «%v»", udpAddr(cPort), err, tt.WantSendErr)
				}
			})
		})
	}
}

// udpAddr returns a numeric loopback address, so that the probes below
// do not invoke the DNS resolver (which would itself use UDP).
func udpAddr(port int) string {
	return fmt.Sprintf("127.0.0.1:%v", port)
}

func listenPacket(t *testing.T, addr string) net.PacketConn {
	t.Helper()

	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("net.ListenPacket(udp, %v): %v", addr, err)
	}
	t.Cleanup(func() { pc.Close() })
	return pc
}

func runBackgroundPacketService(t *testing.T, addr string) {
	pc := listenPacket(t, addr)
	go func() {
		buf := make([]byte, 1)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				// Return on error (e.g., if pc gets closed asynchronously)
				return
			}
		}
	}()
}

func tryUDPBind(port int) error {
	pc, err := net.ListenPacket("udp", udpAddr(port))
	if err == nil {
		pc.Close()
	}
	return err
}

func tryUDPDial(port int) error {
	conn, err := net.Dial("udp", udpAddr(port))
	if err == nil {
		conn.Close()
	}
	return err
}

func trySendTo(pc net.PacketConn, port int) error {
	addr, err := net.ResolveUDPAddr("udp", udpAddr(port))
	if err != nil {
		return err
	}
	_, err = pc.WriteTo([]byte("x"), addr)
	return err
}
