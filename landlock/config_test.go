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
