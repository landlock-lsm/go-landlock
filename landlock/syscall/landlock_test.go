//go:build linux

package syscall

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestAccessRights(t *testing.T) {
	for _, tt := range []struct {
		Name        string
		LandlockDef uint64
		SyscallDef  uint64
	}{
		{"Execute", AccessFSExecute, unix.LANDLOCK_ACCESS_FS_EXECUTE},
		{"WriteFile", AccessFSWriteFile, unix.LANDLOCK_ACCESS_FS_WRITE_FILE},
		{"ReadFile", AccessFSReadFile, unix.LANDLOCK_ACCESS_FS_READ_FILE},
		{"ReadDir", AccessFSReadDir, unix.LANDLOCK_ACCESS_FS_READ_DIR},
		{"RemoveDir", AccessFSRemoveDir, unix.LANDLOCK_ACCESS_FS_REMOVE_DIR},
		{"RemoveFile", AccessFSRemoveFile, unix.LANDLOCK_ACCESS_FS_REMOVE_FILE},
		{"MakeChar", AccessFSMakeChar, unix.LANDLOCK_ACCESS_FS_MAKE_CHAR},
		{"MakeDir", AccessFSMakeDir, unix.LANDLOCK_ACCESS_FS_MAKE_DIR},
		{"MakeReg", AccessFSMakeReg, unix.LANDLOCK_ACCESS_FS_MAKE_REG},
		{"MakeSock", AccessFSMakeSock, unix.LANDLOCK_ACCESS_FS_MAKE_SOCK},
		{"MakeFifo", AccessFSMakeFifo, unix.LANDLOCK_ACCESS_FS_MAKE_FIFO},
		{"MakeBlock", AccessFSMakeBlock, unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK},
		{"MakeSym", AccessFSMakeSym, unix.LANDLOCK_ACCESS_FS_MAKE_SYM},
		{"Refer", AccessFSRefer, unix.LANDLOCK_ACCESS_FS_REFER},
		{"Truncate", AccessFSTruncate, AccessFSRefer << 1},
	} {
		t.Run(tt.Name, func(t *testing.T) {
			if tt.LandlockDef != tt.SyscallDef {
				t.Errorf("Landlock definition differs from x/sys/unix definition; got %v, want %v", tt.LandlockDef, tt.SyscallDef)
			}
		})
	}
}
