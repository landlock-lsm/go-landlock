package landlock

import (
	"fmt"

	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

type NetRule struct {
	access AccessNetSet
	port   uint16
}

// ConnectTCP is a [Rule] which grants the right to connect a socket
// to a given TCP port.
//
// In Go, the connect(2) operation is usually run as part of
// [net.Dial].
func ConnectTCP(port uint16) NetRule {
	return NetRule{
		access: ll.AccessNetConnectTCP,
		port:   port,
	}
}

// BindTCP is a [Rule] which grants the right to bind a socket to a
// given TCP port.
//
// In Go, the bind(2) operation is usually run as part of
// [net.Listen].  Since Go 1.24, [net.Listen] defaults to Multipath
// TCP, see the discussion in the package documentation.
func BindTCP(port uint16) NetRule {
	return NetRule{
		access: ll.AccessNetBindTCP,
		port:   port,
	}
}

// BindUDP is a [Rule] which grants the right to bind a UDP socket to
// a given local port.
//
// This access right is available since Landlock V10.
//
// The port 0 has a special meaning: Granting [BindUDP] on port 0
// permits bind(2) calls on port 0, which make the kernel pick an
// arbitrary port from the ephemeral port range.  This also covers the
// implicit "autobind" which the kernel performs when an unbound UDP
// socket gets a remote peer set or sends its first datagram.  Programs
// which handle both [BindUDP] and [ConnectSendUDP] and which use UDP
// sockets that were not already bound before enforcement therefore
// need to grant either [BindUDP](0), or [BindUDP] on a specific port
// which they bind(2) to before connecting or sending.
func BindUDP(port uint16) NetRule {
	return NetRule{
		access: ll.AccessNetBindUDP,
		port:   port,
	}
}

// ConnectSendUDP is a [Rule] which grants the right to set the remote
// port of a UDP socket to the given port with connect(2), and to send
// datagrams to that remote port with e.g. sendto(2), regardless of any
// destination that was previously set on the socket.
//
// This access right is available since Landlock V10.
//
// Note that setting a remote address or sending a first datagram makes
// the kernel autobind the UDP socket to an ephemeral local source port,
// if it is not already bound.  See [BindUDP] for how to permit that.
func ConnectSendUDP(port uint16) NetRule {
	return NetRule{
		access: ll.AccessNetConnectSendUDP,
		port:   port,
	}
}

func (n NetRule) String() string {
	return fmt.Sprintf("ALLOW %v on port %v", n.access, n.port)
}

func (n NetRule) compatibleWithConfig(c Config) bool {
	return n.access.isSubset(c.handledAccessNet)
}

func (n NetRule) addToRuleset(rulesetFD int, c Config) error {
	if n.access == 0 {
		// Adding this to the ruleset would be a no-op
		// and result in an error.
		return nil
	}
	flags := 0
	attr := &ll.NetPortAttr{
		AllowedAccess: uint64(n.access),
		Port:          uint64(n.port),
	}
	return ll.LandlockAddNetPortRule(rulesetFD, attr, flags)
}

func (n NetRule) downgrade(c Config) (out Rule, ok bool) {
	return NetRule{
		access: n.access.intersect(c.handledAccessNet),
		port:   n.port,
	}, true
}
