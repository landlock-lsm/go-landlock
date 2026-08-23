package landlock

import "testing"

func TestNetRuleString(t *testing.T) {
	for _, tc := range []struct {
		rule NetRule
		want string
	}{
		{rule: BindTCP(8080), want: "ALLOW {bind_tcp} on port 8080"},
		{rule: ConnectTCP(53), want: "ALLOW {connect_tcp} on port 53"},
		{rule: BindUDP(0), want: "ALLOW {bind_udp} on port 0"},
		{rule: ConnectSendUDP(53), want: "ALLOW {connect_send_udp} on port 53"},
	} {
		got := tc.rule.String()
		if got != tc.want {
			t.Errorf("%#v.String() = %q, want %q", tc.rule, got, tc.want)
		}
	}
}
