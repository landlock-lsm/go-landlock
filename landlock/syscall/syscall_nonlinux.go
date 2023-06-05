//go:build !linux

package syscall

import (
	"syscall"
	"unsafe"
)

func LandlockCreateRuleset(attr *RulesetAttr, flags int) (fd int, err error) {
	return -1, syscall.ENOSYS
}

func LandlockGetABIVersion() (version int, err error) {
	return -1, syscall.ENOSYS
}

// LandlockAddRule is the generic landlock_add_rule syscall.
func LandlockAddRule(rulesetFd int, ruleType int, ruleAttr unsafe.Pointer, flags int) (err error) {
	return syscall.ENOSYS
}

func LandlockAddPathBeneathRule(rulesetFd int, attr *PathBeneathAttr, flags int) error {
	return syscall.ENOSYS
}

// AllThreadsLandlockRestrictSelf enforces the given ruleset on all OS
// threads belonging to the current process.
func AllThreadsLandlockRestrictSelf(rulesetFd int, flags int) (err error) {
	return syscall.ENOSYS
}

// AllThreadsPrctl is like unix.Prctl, but gets applied on all OS threads at the same time.
func AllThreadsPrctl(option int, arg2 uintptr, arg3 uintptr, arg4 uintptr, arg5 uintptr) (err error) {
	return syscall.ENOSYS
}
