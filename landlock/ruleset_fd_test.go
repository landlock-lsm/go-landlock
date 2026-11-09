//go:build linux

package landlock_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/landlock-lsm/go-landlock/landlock/lltest"
	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

func countOpenFDs(t testing.TB) int {
	t.Helper()

	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("os.ReadDir(/proc/self/fd): %v", err)
	}
	return len(entries)
}

// restrictCurrentThread enforces the ruleset on the current OS thread
// only.  The caller must have called runtime.LockOSThread.
func restrictCurrentThread(t testing.TB, fd int, flags uint32) {
	t.Helper()

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatalf("prctl(PR_SET_NO_NEW_PRIVS): %v", err)
	}
	if err := ll.LandlockRestrictSelf(fd, flags); err != nil {
		t.Fatalf("landlock_restrict_self: %v", err)
	}
}

func TestNewRulesetFD_Enforce(t *testing.T) {
	lltest.RunInSubprocess(t, func() {
		lltest.RequireABI(t, 1)

		dir := lltest.TempDir(t)
		fpath := filepath.Join(dir, "file")

		fd, flags, err := landlock.V1.NewRulesetFD(landlock.RODirs("/"))
		if err != nil {
			t.Fatalf("NewRulesetFD: %v", err)
		}
		defer syscall.Close(fd)

		// Creating the ruleset does not restrict anything yet.
		MustWriteFile(t, fpath)

		runtime.LockOSThread() // Never unlocked; the thread exits with the goroutine.
		restrictCurrentThread(t, fd, flags)

		err = os.WriteFile(fpath, []byte("x"), 0600)
		if !errors.Is(err, syscall.EACCES) {
			t.Errorf("os.WriteFile(%q) after enforcement: got err %v, want EACCES", fpath, err)
		}
	})
}

func TestNewRulesetFD_Flags(t *testing.T) {
	lltest.RequireABI(t, 7)

	for _, tc := range []struct {
		name string
		cfg  landlock.Config
		want uint32
	}{
		{
			name: "NoFlags",
			cfg:  landlock.V7,
			want: 0,
		},
		{
			name: "LoggingFlags",
			cfg:  landlock.V7.EnableLoggingForSubprocesses().DisableLoggingForSubdomains(),
			want: ll.FlagRestrictSelfLogNewExecOn | ll.FlagRestrictSelfLogSubdomainsOff,
		},
		{
			name: "BestEffort",
			cfg:  landlock.V11.BestEffort().DisableLoggingForOriginatingProcess(),
			want: ll.FlagRestrictSelfLogSameExecOff,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fd, flags, err := tc.cfg.NewRulesetFD()
			if err != nil {
				t.Fatalf("NewRulesetFD: %v", err)
			}
			defer syscall.Close(fd)

			if fd < 0 {
				t.Errorf("NewRulesetFD: got fd %v, want a valid FD", fd)
			}
			if flags != tc.want {
				t.Errorf("NewRulesetFD: got flags %#x, want %#x", flags, tc.want)
			}
		})
	}
}

func TestNewRulesetFD_CloseOnExec(t *testing.T) {
	lltest.RequireABI(t, 1)

	fd, _, err := landlock.V1.NewRulesetFD()
	if err != nil {
		t.Fatalf("NewRulesetFD: %v", err)
	}
	defer syscall.Close(fd)

	fdFlags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("fcntl(F_GETFD): %v", err)
	}
	if fdFlags&unix.FD_CLOEXEC == 0 {
		t.Errorf("ruleset FD does not have FD_CLOEXEC set")
	}
}

func TestNewRulesetFD_NothingToRestrict(t *testing.T) {
	for _, cfg := range []landlock.Config{
		{},
		landlock.Config{}.BestEffort().EnableLoggingForSubprocesses(),
	} {
		fd, flags, err := cfg.NewRulesetFD()
		if fd != -1 || flags != 0 || err != nil {
			t.Errorf("%v.NewRulesetFD() = (%v, %#x, %v), want (-1, 0, nil)", cfg, fd, flags, err)
		}
	}
}

func TestNewRulesetFD_Errors(t *testing.T) {
	lltest.RequireABI(t, 1)

	doesNotExist := filepath.Join(t.TempDir(), "does_not_exist")

	for _, tc := range []struct {
		name    string
		cfg     landlock.Config
		rules   []landlock.Rule
		wantErr string
	}{
		{
			name:    "MissingPath",
			cfg:     landlock.V1,
			rules:   []landlock.Rule{landlock.RODirs("/"), landlock.RODirs(doesNotExist)},
			wantErr: "no such file or directory",
		},
		{
			name:    "IncompatibleRule",
			cfg:     landlock.V1,
			rules:   []landlock.Rule{landlock.RODirs("/").WithRefer()},
			wantErr: "incompatible rule",
		},
		{
			name:    "UnknownAccessRights",
			cfg:     landlock.Config{HandledAccessFS: 1 << 63}.BestEffort(),
			wantErr: "upgrade go-landlock",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := countOpenFDs(t)

			fd, flags, err := tc.cfg.NewRulesetFD(tc.rules...)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("NewRulesetFD: got err %v, want error with %q", err, tc.wantErr)
			}
			if fd != -1 || flags != 0 {
				t.Errorf("NewRulesetFD: got (%v, %#x), want (-1, 0)", fd, flags)
			}
			if after := countOpenFDs(t); after != before {
				t.Errorf("NewRulesetFD leaked FDs: %v open before, %v after", before, after)
			}
		})
	}
}
