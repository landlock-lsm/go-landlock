// Package syscall provides a low-level interface to the Linux Landlock sandboxing feature.
package syscall

import (
	"syscall"
	"unsafe"
)

// TODO: These syscall numbers will soon show up in the x/sys/unix package.
const (
	SYS_LANDLOCK_CREATE_RULESET = 444
	SYS_LANDLOCK_ADD_RULE       = 445
	SYS_LANDLOCK_RESTRICT_SELF  = 446
)

// Landlock access permissions
const (
	AccessFSExecute    = (1 << 0)
	AccessFSWriteFile  = (1 << 1)
	AccessFSReadFile   = (1 << 2)
	AccessFSReadDir    = (1 << 3)
	AccessFSRemoveDir  = (1 << 4)
	AccessFSRemoveFile = (1 << 5)
	AccessFSMakeChar   = (1 << 6)
	AccessFSMakeDir    = (1 << 7)
	AccessFSMakeReg    = (1 << 8)
	AccessFSMakeSock   = (1 << 9)
	AccessFSMakeFifo   = (1 << 10)
	AccessFSMakeBlock  = (1 << 11)
	AccessFSMakeSym    = (1 << 12)
)

// RulesetAttr is the Landlock ruleset definition.
//
// Argument of LandlockCreateRuleset(). This structure can grow in future versions of Landlock.
//
// C version is in usr/include/linux/landlock.h
type RulesetAttr struct {
	HandledAccessFs uint64
}

const rulesetAttrSize = 8

func LandlockCreateRuleset(attr *RulesetAttr, flags int) (fd int, err error) {
	r0, _, e1 := syscall.Syscall(SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(attr)), uintptr(rulesetAttrSize), uintptr(flags))
	fd = int(r0)
	if e1 != 0 {
		err = syscall.Errno(e1)
	}
	return
}

type ruleType int

const RuleTypePathBeneath ruleType = 1

type PathBeneathAttr struct {
	// AllowedAccess is a bitmask of allowed actions for this file hierarchy
	// (cf. "Filesystem flags").
	AllowedAccess uint64

	// ParentFd is a file descriptor, open with `O_PATH`, which identifies
	// the parent directory of a file hierarchy, or just a file.
	ParentFd int
}

func LandlockAddRule(rulesetFd int, ruleType ruleType, ruleAttr unsafe.Pointer, flags int) (err error) {
	_, _, e1 := syscall.Syscall6(SYS_LANDLOCK_ADD_RULE, uintptr(rulesetFd), uintptr(ruleType), uintptr(ruleAttr), uintptr(flags), 0, 0)
	if e1 != 0 {
		err = syscall.Errno(e1)
	}
	return
}

func LandlockRestrictSelf(rulesetFd int, flags int) (err error) {
	_, _, e1 := syscall.Syscall(SYS_LANDLOCK_RESTRICT_SELF, uintptr(rulesetFd), uintptr(flags), 0)
	if e1 != 0 {
		err = syscall.Errno(e1)
	}
	return
}
