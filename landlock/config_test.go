package landlock

import (
	"fmt"
	"testing"

	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

func TestConfigString(t *testing.T) {
	for _, tc := range []struct {
		cfg  Config
		want string
	}{
		{
			cfg:  Config{handledAccessFS: 0},
			want: fmt.Sprintf("{Landlock V1; HandledAccessFS: %v}", AccessFSSet(0)),
		},
		{
			cfg:  Config{handledAccessFS: ll.AccessFSWriteFile},
			want: "{Landlock V1; HandledAccessFS: {WriteFile}}",
		},
		{
			cfg:  V1,
			want: "{Landlock V1; HandledAccessFS: all}",
		},
		{
			cfg:  V1.BestEffort(),
			want: "{Landlock V1; HandledAccessFS: all (best effort)}",
		},
	} {
		got := tc.cfg.String()
		if got != tc.want {
			t.Errorf("cfg.String() = %q, want %q", got, tc.want)
		}
	}
}

func TestValidateSuccess(t *testing.T) {
	for _, c := range []Config{
		V1, V1.BestEffort(),
		Config{handledAccessFS: ll.AccessFSWriteFile},
		Config{handledAccessFS: 0},
	} {
		err := c.validate()
		if err != nil {
			t.Errorf("%v.validate(): expected success, got %v", c, err)
		}
	}
}

func TestValidateFailure(t *testing.T) {
	for _, c := range []Config{
		Config{handledAccessFS: 0xffffffffffffffff},
		Config{handledAccessFS: highestKnownABIVersion.supportedAccessFS + 1},
	} {
		err := c.validate()
		if err == nil {
			t.Errorf("%v.validate(): expected error, got success", c)
		}
	}
}
