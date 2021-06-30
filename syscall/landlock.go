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

// Landlock access permissions, for use in "access" bit fields:
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

// The size of the RulesetAttr struct in bytes.
const rulesetAttrSize = 8

// LandlockCreateRuleset creates a ruleset file descriptor with the
// given attributes.
func LandlockCreateRuleset(attr *RulesetAttr, flags int) (fd int, err error) {
	r0, _, e1 := syscall.Syscall(SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(attr)), uintptr(rulesetAttrSize), uintptr(flags))
	fd = int(r0)
	if e1 != 0 {
		err = syscall.Errno(e1)
	}
	return
}

// The Landlock rule types:
const (
	RuleTypePathBeneath = 1
)

// PathBeneathAttr references a file hierarchy and defines the desired
// extent to which it should be usable when the rule is enforced.
type PathBeneathAttr struct {
	// AllowedAccess is a bitmask of allowed actions for this file
	// hierarchy (cf. "Filesystem flags"). The enabled bits must
	// be a subset of the bits defined in the ruleset.
	AllowedAccess uint64

	// ParentFd is a file descriptor, open with `O_PATH`, which identifies
	// the parent directory of a file hierarchy, or just a file.
	ParentFd int
}

// LandlockAddPathBeneathRule adds a rule of type "path beneath" to
// the given ruleset fd. attr defines the rule parameters. flags must
// currently be 0.
func LandlockAddPathBeneathRule(rulesetFd int, attr *PathBeneathAttr, flags int) error {
	return LandlockAddRule(rulesetFd, RuleTypePathBeneath, unsafe.Pointer(attr), flags)
}

// LandlockAddRule is the generic landlock_add_rule syscall.
func LandlockAddRule(rulesetFd int, ruleType int, ruleAttr unsafe.Pointer, flags int) (err error) {
	_, _, e1 := syscall.Syscall6(SYS_LANDLOCK_ADD_RULE, uintptr(rulesetFd), uintptr(ruleType), uintptr(ruleAttr), uintptr(flags), 0, 0)
	if e1 != 0 {
		err = syscall.Errno(e1)
	}
	return
}

// LandlockRestrictSelf enforces the given ruleset on the calling thread.
func LandlockRestrictSelf(rulesetFd int, flags int) (err error) {
	_, _, e1 := syscall.Syscall(SYS_LANDLOCK_RESTRICT_SELF, uintptr(rulesetFd), uintptr(flags), 0)
	if e1 != 0 {
		err = syscall.Errno(e1)
	}
	return
}
