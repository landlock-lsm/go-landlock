package landlock

import (
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock/syscall"
	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

func TestConfigString(t *testing.T) {
	for _, tc := range []struct {
		cfg  Config
		want string
	}{
		{
			cfg:  Config{handledAccessFS: 0, handledAccessNet: 0},
			want: "{Landlock V0; FS: ∅; Net: ∅; Audit: sameexec+subdomains}",
		},
		{
			cfg:  Config{handledAccessFS: ll.AccessFSWriteFile},
			want: "{Landlock V1; FS: {write_file}; Net: ∅; Audit: sameexec+subdomains}",
		},
		{
			cfg:  Config{handledAccessNet: ll.AccessNetBindTCP},
			want: "{Landlock V4; FS: ∅; Net: {bind_tcp}; Audit: sameexec+subdomains}",
		},
		{
			cfg:  V1,
			want: "{Landlock V1; FS: all; Net: ∅; Audit: sameexec+subdomains}",
		},
		{
			cfg:  V1.BestEffort(),
			want: "{Landlock V1; FS: all; Net: ∅; Audit: sameexec+subdomains (best effort)}",
		},
		{
			cfg:  Config{handledAccessFS: 1 << 63},
			want: "{Landlock V???; FS: {1<<63}; Net: ∅; Audit: sameexec+subdomains}",
		},
		{
			cfg:  Config{restrictFlags: syscall.RestrictSelfLogSameExecOff | syscall.RestrictSelfLogNewExecOn | syscall.RestrictSelfLogSubdomainsOff},
			want: "{Landlock V0; FS: ∅; Net: ∅; Audit: newexec}",
		},
		{
			cfg:  Config{restrictFlags: syscall.RestrictSelfLogSameExecOff | syscall.RestrictSelfLogSubdomainsOff},
			want: "{Landlock V0; FS: ∅; Net: ∅; Audit: -}",
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
		{AccessFSSet(1 << 16)},
		{AccessFSSet(1 << 63)},
	} {
		_, err := NewConfig(args...)
		if err == nil {
			t.Errorf("NewConfig(%v) success, expected error", args)
		}
	}
}
