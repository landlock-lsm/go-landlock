// Package golandlock provides a high-level interface to the Linux Landlock sandboxing feature.
package golandlock

import (
	"fmt"
	"syscall"

	ll "github.com/gnoack/golandlock/syscall"
	"golang.org/x/sys/unix"
)

const (
	accessFile           = ll.AccessFSExecute | ll.AccessFSWriteFile | ll.AccessFSReadFile
	accessFSRoughlyRead  = ll.AccessFSExecute | ll.AccessFSReadFile | ll.AccessFSReadDir
	accessFSRoughlyWrite = ll.AccessFSWriteFile | ll.AccessFSRemoveDir | ll.AccessFSRemoveFile | ll.AccessFSMakeChar | ll.AccessFSMakeDir | ll.AccessFSMakeReg | ll.AccessFSMakeSock | ll.AccessFSMakeFifo | ll.AccessFSMakeBlock | ll.AccessFSMakeSym
)

// Restrict restricts the current process to only "see" the files
// provided as inputs. After this call successfully returns, the same
// process can't open files for reading and writing any more and
// modify subdirectories.
//
// roDirs: Directory paths permitted for reading. All files and
// directories below should be readable.
//
// ro: Specific files permitted for reading.
//
// rwDirs: Directory paths permitted for writing. All files and
// directories below are writable, and directory entries can be
// modified.
//
// rw: Specific files permitted for writing.
//
// This function returns an error if the current kernel does not
// support Landlock or if any of the given paths does not denote
// an actual directory.
//
// This function implicitly sets the "no new privileges" flag on the
// current process.
func Restrict(roDirs, ro, rwDirs, rw []string) error {
	rulesetAttr := ll.RulesetAttr{
		HandledAccessFs: uint64(accessFSRoughlyRead | accessFSRoughlyWrite),
	}
	fd, err := ll.LandlockCreateRuleset(&rulesetAttr, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	if err := populateRuleset(fd, roDirs, accessFSRoughlyRead); err != nil {
		return err
	}
	if err := populateRuleset(fd, ro, accessFSRoughlyRead&accessFile); err != nil {
		return err
	}
	if err := populateRuleset(fd, rwDirs, accessFSRoughlyWrite); err != nil {
		return err
	}
	if err := populateRuleset(fd, rw, accessFSRoughlyWrite&accessFile); err != nil {
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
	err = ll.LandlockAddPathBeneathRule(rulesetFd, &pathBeneath, 0)
	if err != nil {
		return fmt.Errorf("failed to update ruleset: %w", err)
	}
	return nil
}
