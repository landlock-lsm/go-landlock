//go:build linux

package syscall

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestRestrictSelfFlags(t *testing.T) {
	// TODO: replace with unix.LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON once we can uprade the x/sys/unix dependency.
	if FlagRestrictSelfLogNewExecOn != 0x2 {
		t.Errorf("FlagRestrictSelfLogNewExecOn differs from x/sys/unix definition; got %v, want %v", FlagRestrictSelfLogNewExecOn, unix.LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON)
	}

	// TODO: replace with unix.LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF once we can uprade the x/sys/unix dependency.
	if FlagRestrictSelfLogSameExecOff != 0x1 {
		t.Errorf("FlagRestrictSelfLogSameExecOff differs from x/sys/unix definition; got %v, want %v", FlagRestrictSelfLogSameExecOff, unix.LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF)
	}

	// TODO: replace with unix.LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF once we can uprade the x/sys/unix dependency.
	if FlagRestrictSelfLogSubdomainsOff != 0x4 {
		t.Errorf("FlagRestrictSelfLogSubdomainsOff differs from x/sys/unix definition; got %v, want %v", FlagRestrictSelfLogSubdomainsOff, unix.LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF)
	}
}

func TestAccessRights(t *testing.T) {
	for _, tt := range []struct {
		Name        string
		LandlockDef uint64
		SyscallDef  uint64
	}{
		{"FSExecute", AccessFSExecute, unix.LANDLOCK_ACCESS_FS_EXECUTE},
		{"FSWriteFile", AccessFSWriteFile, unix.LANDLOCK_ACCESS_FS_WRITE_FILE},
		{"FSReadFile", AccessFSReadFile, unix.LANDLOCK_ACCESS_FS_READ_FILE},
		{"FSReadDir", AccessFSReadDir, unix.LANDLOCK_ACCESS_FS_READ_DIR},
		{"FSRemoveDir", AccessFSRemoveDir, unix.LANDLOCK_ACCESS_FS_REMOVE_DIR},
		{"FSRemoveFile", AccessFSRemoveFile, unix.LANDLOCK_ACCESS_FS_REMOVE_FILE},
		{"FSMakeChar", AccessFSMakeChar, unix.LANDLOCK_ACCESS_FS_MAKE_CHAR},
		{"FSMakeDir", AccessFSMakeDir, unix.LANDLOCK_ACCESS_FS_MAKE_DIR},
		{"FSMakeReg", AccessFSMakeReg, unix.LANDLOCK_ACCESS_FS_MAKE_REG},
		{"FSMakeSock", AccessFSMakeSock, unix.LANDLOCK_ACCESS_FS_MAKE_SOCK},
		{"FSMakeFifo", AccessFSMakeFifo, unix.LANDLOCK_ACCESS_FS_MAKE_FIFO},
		{"FSMakeBlock", AccessFSMakeBlock, unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK},
		{"FSMakeSym", AccessFSMakeSym, unix.LANDLOCK_ACCESS_FS_MAKE_SYM},
		{"FSRefer", AccessFSRefer, unix.LANDLOCK_ACCESS_FS_REFER},
		{"FSTruncate", AccessFSTruncate, unix.LANDLOCK_ACCESS_FS_TRUNCATE},
		{"FSIoctlDev", AccessFSIoctlDev, unix.LANDLOCK_ACCESS_FS_IOCTL_DEV},
		{"NetBindTCP", AccessNetBindTCP, unix.LANDLOCK_ACCESS_NET_BIND_TCP},
		{"NetConnectTCP", AccessNetConnectTCP, unix.LANDLOCK_ACCESS_NET_CONNECT_TCP},
	} {
		t.Run(tt.Name, func(t *testing.T) {
			if tt.LandlockDef != tt.SyscallDef {
				t.Errorf("Landlock definition differs from x/sys/unix definition; got %v, want %v", tt.LandlockDef, tt.SyscallDef)
			}
		})
	}
}
