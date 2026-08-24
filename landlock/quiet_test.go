package landlock

import (
	"testing"

	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// QuietPaths returns a dedicated rule type, so that the access right
// modifiers of FSRule (WithRefer, WithIoctlDev, WithResolveUnix) can
// not be applied to a quiet rule.
var _ QuietFSRule = QuietPaths("/tmp")

func TestQuietPathsRequireQuietAll(t *testing.T) {
	rule := QuietPaths("/tmp")

	if rule.compatibleWithConfig(V10) {
		t.Errorf("QuietPaths(…).compatibleWithConfig(V10) = true, want false (Config.QuietAll() is missing)")
	}
	if !rule.compatibleWithConfig(V10.QuietAll()) {
		t.Errorf("QuietPaths(…).compatibleWithConfig(V10.QuietAll()) = false, want true")
	}
}

func TestQuietPathsString(t *testing.T) {
	got := QuietPaths("/tmp", "/var/cache").String()
	want := "QUIET for paths [/tmp /var/cache]"
	if got != want {
		t.Errorf("QuietPaths(…).String() = %q, want %q", got, want)
	}
}

var _ QuietNetRule = QuietPorts(53)

func TestQuietPortsRequireQuietAll(t *testing.T) {
	rule := QuietPorts(53)

	if rule.compatibleWithConfig(V10) {
		t.Errorf("QuietPorts(…).compatibleWithConfig(V10) = true, want false (Config.QuietAll() is missing)")
	}
	if !rule.compatibleWithConfig(V10.QuietAll()) {
		t.Errorf("QuietPorts(…).compatibleWithConfig(V10.QuietAll()) = false, want true")
	}
}

func TestQuietPortsString(t *testing.T) {
	got := QuietPorts(53, 631).String()
	want := "QUIET on ports [53 631]"
	if got != want {
		t.Errorf("QuietPorts(…) = %q, want %q", got, want)
	}
}

func TestQuietPathsAddRuleFlags(t *testing.T) {
	for _, tt := range []struct {
		name string
		rule QuietFSRule
		cfg  Config
		want int
	}{
		{
			name: "quiet rule with quieting enabled",
			rule: QuietPaths("/tmp"),
			cfg:  V10.QuietAll(),
			want: ll.FlagAddRuleQuiet,
		},
		{
			name: "quiet rule without quieting enabled",
			rule: QuietPaths("/tmp"),
			cfg:  V10,
			want: 0,
		},
		{
			// The kernel rejects LANDLOCK_ADD_RULE_QUIET with
			// EINVAL if the ruleset's quiet mask is empty.
			name: "quiet rule in a Config without filesystem access rights",
			rule: QuietPaths("/tmp"),
			cfg:  MustConfig(AccessNetSet(ll.AccessNetBindTCP)).QuietAll(),
			want: 0,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rule.addRuleFlags(tt.cfg); got != tt.want {
				t.Errorf("addRuleFlags() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestQuietPortsAddRuleFlags(t *testing.T) {
	for _, tt := range []struct {
		name string
		rule QuietNetRule
		cfg  Config
		want int
	}{
		{
			name: "quiet rule with quieting enabled",
			rule: QuietPorts(53),
			cfg:  V10.QuietAll(),
			want: ll.FlagAddRuleQuiet,
		},
		{
			name: "quiet rule without quieting enabled",
			rule: QuietPorts(53),
			cfg:  V10,
			want: 0,
		},
		{
			// The kernel rejects LANDLOCK_ADD_RULE_QUIET with
			// EINVAL if the ruleset's quiet mask is empty.
			name: "quiet rule in a Config without network access rights",
			rule: QuietPorts(53),
			cfg:  MustConfig(AccessFSSet(ll.AccessFSReadFile)).QuietAll(),
			want: 0,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rule.addRuleFlags(tt.cfg); got != tt.want {
				t.Errorf("addRuleFlags() = %v, want %v", got, tt.want)
			}
		})
	}
}
