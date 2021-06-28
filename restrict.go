package golandlock

import (
	"fmt"
	"syscall"
	"unsafe"

	ll "github.com/gnoack/golandlock/syscall"
	"golang.org/x/sys/unix"
)

const (
	accessFile           = ll.AccessFSExecute | ll.AccessFSWriteFile | ll.AccessFSReadFile
	accessFsRoughlyRead  = ll.AccessFSExecute | ll.AccessFSReadFile | ll.AccessFSReadDir
	accessFsRoughlyWrite = ll.AccessFSWriteFile | ll.AccessFSRemoveDir | ll.AccessFSRemoveFile | ll.AccessFSMakeChar | ll.AccessFSMakeDir | ll.AccessFSMakeReg | ll.AccessFSMakeSock | ll.AccessFSMakeFifo | ll.AccessFSMakeBlock | ll.AccessFSMakeSym
)

func Restrict(roDirs, ro, rwDirs, rw []string) error {
	rulesetAttr := ll.RulesetAttr{
		HandledAccessFs: uint64(accessFsRoughlyRead | accessFsRoughlyWrite),
	}
	fd, err := ll.LandlockCreateRuleset(&rulesetAttr, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	if err := populateRuleset(fd, roDirs, accessFsRoughlyRead); err != nil {
		return err
	}
	if err := populateRuleset(fd, ro, accessFsRoughlyRead&accessFile); err != nil {
		return err
	}
	if err := populateRuleset(fd, rwDirs, accessFsRoughlyWrite); err != nil {
		return err
	}
	if err := populateRuleset(fd, rw, accessFsRoughlyWrite&accessFile); err != nil {
		return err
	}

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}

	if err := ll.LandlockRestrictSelf(fd, 0); err != nil {
		return err
	}
	// xxx enable
	return nil
}

// XXX: Should file descriptors be int or int32?
// I believe in C they are only int32, but the Go syscalls package uses int,
// which I think is 64 bit on 64 bit architectures.
func populateRuleset(rulesetFd int, paths []string, access uint64) error {
	for _, p := range paths {
		if err := populate(rulesetFd, p, access); err != nil {
			return err
		}
	}
	return nil
}

func populate(rulesetFd int, path string, access uint64) error {
	fd, err := syscall.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	pathBeneath := ll.PathBeneathAttr{
		ParentFd:      fd,
		AllowedAccess: access,
	}
	err = ll.LandlockAddRule(rulesetFd, ll.RuleTypePathBeneath, unsafe.Pointer(&pathBeneath), 0)
	if err != nil {
		return fmt.Errorf("failed to update ruleset: %w", err)
	}
	return nil
}
