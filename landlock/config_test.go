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
		{
			cfg:  Config{handledAccessFS: 1 << 63},
			want: "{Landlock V???; HandledAccessFS: {1<<63} (unsupported HandledAccessFS value)}",
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

func TestNewConfig(t *testing.T) {
	c, err := NewConfig(AccessFSSet(ll.AccessFSWriteFile))
	if err != nil {
		t.Errorf("NewConfig(): expected success, got %v", err)
	}
	want := AccessFSSet(ll.AccessFSWriteFile)
	if c.handledAccessFS != want {
		t.Errorf("c.handledAccessFS = %v, want %v", c.handledAccessFS, want)
	}
}

func TestNewConfigFailures(t *testing.T) {
	for _, args := range [][]interface{}{
		{ll.AccessFSWriteFile},
		{123},
		{"a string"},
		{"foo", 42},
		// May not specify two AccessFSSets
		{AccessFSSet(ll.AccessFSWriteFile), AccessFSSet(ll.AccessFSReadFile)},
		// May not specify an unsupported AccessFSSet value
		{AccessFSSet(1 << 63)},
	} {
		_, err := NewConfig(args...)
		if err == nil {
			t.Errorf("NewConfig(%v) success, expected error", args)
		}
	}
}
