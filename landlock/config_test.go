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
			want: fmt.Sprintf("{Landlock V0; HandledAccessFS: %v}", AccessFSSet(0)),
		},
		{
			cfg:  Config{handledAccessFS: ll.AccessFSWriteFile},
			want: "{Landlock V1; HandledAccessFS: {write_file}}",
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
			want: "{Landlock V???; HandledAccessFS: {1<<63}}",
		},
	} {
		got := tc.cfg.String()
		if got != tc.want {
			t.Errorf("cfg.String() = %q, want %q", got, tc.want)
		}
	}
}

func TestNewConfig(t *testing.T) {
	for _, a := range []AccessFSSet{
		ll.AccessFSWriteFile, ll.AccessFSRefer,
	} {
		c, err := NewConfig(a)
		if err != nil {
			t.Errorf("NewConfig(): expected success, got %v", err)
		}
		want := a
		if c.handledAccessFS != want {
			t.Errorf("c.handledAccessFS = %v, want %v", c.handledAccessFS, want)
		}
	}
}

func TestNewConfigEmpty(t *testing.T) {
	// Constructing an empty config is a bit pointless, but should work.
	c, err := NewConfig()
	if err != nil {
		t.Errorf("NewConfig(): expected success, got %v", err)
	}
	want := AccessFSSet(0)
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
		{AccessFSSet(1 << 15)},
		{AccessFSSet(1 << 63)},
	} {
		_, err := NewConfig(args...)
		if err == nil {
			t.Errorf("NewConfig(%v) success, expected error", args)
		}
	}
}
