package landlock

import (
	"testing"

	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

func TestNetPrettyPrint(t *testing.T) {
	for _, tc := range []struct {
		a    AccessNetSet
		want string
	}{
		{a: 0, want: "∅"},
		{a: ll.AccessNetBindTCP, want: "{bind_tcp}"},
		{a: ll.AccessNetConnectTCP, want: "{connect_tcp}"},
		{a: ll.AccessNetBindUDP, want: "{bind_udp}"},
		{a: ll.AccessNetConnectSendUDP, want: "{connect_send_udp}"},
		{a: supportedAccessNet, want: "{bind_tcp,connect_tcp,bind_udp,connect_send_udp}"},
		{a: ll.AccessNetBindUDP | 1<<63, want: "{bind_udp,1<<63}"},
	} {
		got := tc.a.String()
		if got != tc.want {
			t.Errorf("AccessNetSet(%08x).String() = %q, want %q", uint64(tc.a), got, tc.want)
		}
	}
}

func TestNetValid(t *testing.T) {
	for _, tc := range []struct {
		a    AccessNetSet
		want bool
	}{
		{a: 0, want: true},
		{a: ll.AccessNetBindTCP, want: true},
		{a: ll.AccessNetConnectSendUDP, want: true},
		{a: supportedAccessNet, want: true},
		{a: 1 << 4, want: false},
		{a: 1 << 63, want: false},
	} {
		got := tc.a.valid()
		if got != tc.want {
			t.Errorf("AccessNetSet(%08x).valid() = %v, want %v", uint64(tc.a), got, tc.want)
		}
	}
}
