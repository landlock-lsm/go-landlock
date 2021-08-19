package golandlock

import ll "github.com/gnoack/golandlock/syscall"

// Access permission sets for filesystem access.
const (
	// The set of access rights that only apply to files.
	accessFile AccessFSSet = ll.AccessFSExecute | ll.AccessFSWriteFile | ll.AccessFSReadFile

	// The set of access rights associated with read access to files and directories.
	accessFSRead AccessFSSet = ll.AccessFSExecute | ll.AccessFSReadFile | ll.AccessFSReadDir

	// The set of access rights associated with write access to files and directories.
	accessFSWrite AccessFSSet = ll.AccessFSWriteFile | ll.AccessFSRemoveDir | ll.AccessFSRemoveFile | ll.AccessFSMakeChar | ll.AccessFSMakeDir | ll.AccessFSMakeReg | ll.AccessFSMakeSock | ll.AccessFSMakeFifo | ll.AccessFSMakeBlock | ll.AccessFSMakeSym

	// The set of access rights associated with read and write access to files and directories.
	accessFSReadWrite AccessFSSet = accessFSRead | accessFSWrite
)

// These are the currently supported Landlock ABI versions.
//
// The higher the ABI version, the more operations Landlock will be
// able to restrict.
var (
	// Landlock V1 support (basic file operations).
	V1 = Config{
		name:            "v1",
		handledAccessFS: abiInfos[1].supportedAccessFS,
	}
)

// The Landlock configuration describes the desired Landlock ABI level
// and operations to be restricted.
type Config struct {
	name            string
	handledAccessFS AccessFSSet
	bestEffort      bool
}

// BestEffort returns a config that will opportunistically enforce
// the strongest rules it can, up to the given ABI version, working
// with the level of Landlock support available in the running kernel.
//
// Warning: A best-effort call to RestrictPaths() will succeed without
// error even when Landlock is not available at all on the current kernel.
func (c Config) BestEffort() Config {
	cfg := c
	cfg.bestEffort = true
	return cfg
}

type pathOpt struct {
	accessFS AccessFSSet
	paths    []string
}

// PathAccess is a RestrictPaths() option that grants the access right
// specified by accessFS to the file hierarchies under the given paths.
//
// When accessFS is larger than what is permitted by the Landlock
// version in use, only the applicable subset of accessFS will be used.
//
// Most users should use the functions RODirs, RWDirs, ROFiles and
// RWFiles instead, which provide canned options for commonly used
// values of accessFS.
//
// Filesystem access rights are represented using bits in a uint64.
// The individual access rights and their meaning are defined in the
// golandlock/syscall package and explained further in the kernel
// documentation at
// https://www.kernel.org/doc/html/latest/userspace-api/landlock.html#access-rights
func PathAccess(accessFS AccessFSSet, paths ...string) pathOpt {
	return pathOpt{
		accessFS: accessFS,
		paths:    paths,
	}
}

// RODirs is a RestrictPaths() option that grants common read-only
// access to files and directories and permits executing files.
func RODirs(paths ...string) pathOpt { return PathAccess(accessFSRead, paths...) }

// RWDirs is a RestrictPaths() option that grants full (read and
// write) access to files and directories under the given paths.
func RWDirs(paths ...string) pathOpt { return PathAccess(accessFSReadWrite, paths...) }

// ROFiles is a RestrictPaths() option that grants common read access
// to individual files, but not to directories, for the file
// hierarchies under the given paths.
func ROFiles(paths ...string) pathOpt { return PathAccess(accessFSRead&accessFile, paths...) }

// RWFiles is a RestrictPaths() option that grants common read and
// write access to files under the given paths, but it does not permit
// access to directories.
func RWFiles(paths ...string) pathOpt { return PathAccess(accessFSReadWrite&accessFile, paths...) }

// RestrictPaths restricts all goroutines to only "see" the files
// provided as inputs. After this call successfully returns, the
// goroutines will only be able to use files in the ways as they were
// specified in advance in the call to RestrictPaths.
//
// Example: The following invocation will restrict all goroutines so
// that it can only read from /usr, /bin and /tmp, and only write to
// /tmp:
//
//   err := golandlock.V1.RestrictPaths(
//       golandlock.RODirs("/usr", "/bin"),
//       golandlock.RWDirs("/tmp"),
//   )
//   if err != nil {
//       log.Fatalf("golandlock.V1.RestrictPaths(): %v", err)
//   }
//
// RestrictPaths returns an error if any of the given paths does not
// denote an actual directory or file, or if Landlock can't be enforced
// using the desired ABI version constraints.
//
// RestrictPaths also sets the "no new privileges" flag for all OS
// threads managed by the Go runtime.
//
// Restrictable access rights
//
// The notions of what "reading" and "writing" mean are limited by what
// the selected Landlock version supports.
//
// Calling RestrictPaths() with a given Landlock ABI version will
// inhibit all future calls to the access rights supported by this ABI
// version, unless the accessed path is in a file hierarchy that is
// specifically allow-listed for a specific set of access rights.
//
// The overall set of operations that RestrictPaths can restrict are:
//
// For reading:
//
// • Executing a file (V1+)
//
// • Opening a file with read access (V1+)
//
// • Opening a directory or listing its content (V1+)
//
//
// For writing:
//
// • Opening a file with write access (V1+)
//
//
// For directory manipulation:
//
// • Removing an empty directory or renaming one (V1+)
//
// • Removing (or renaming) a file (V1+)
//
// • Creating (or renaming or linking) a character device (V1+)
//
// • Creating (or renaming) a directory (V1+)
//
// • Creating (or renaming or linking) a regular file (V1+)
//
// • Creating (or renaming or linking) a UNIX domain socket (V1+)
//
// • Creating (or renaming or linking) a named pipe (V1+)
//
// • Creating (or renaming or linking) a block device (V1+)
//
// • Creating (or renaming or linking) a symbolic link (V1+)
//
// Future versions of Landlock will be able to inhibit more operations.
// Quoting the Landlock documentation:
//
//   It is currently not possible to restrict some file-related
//   actions accessible through these syscall families: chdir(2),
//   truncate(2), stat(2), flock(2), chmod(2), chown(2), setxattr(2),
//   utime(2), ioctl(2), fcntl(2), access(2). Future Landlock
//   evolutions will enable to restrict them.
//
// The access rights are documented in more depth at:
// https://www.kernel.org/doc/html/latest/userspace-api/landlock.html#access-rights
//
// Helper functions for selecting access rights
//
// These helper functions help selecting common subsets of access rights:
//
// • RODirs() selects access rights in the group "for reading".
// In V1, this means reading files, listing directories and executing files.
//
// • RWDirs() selects access rights in the group "for reading", "for writing" and
// "for directory manipulation". In V1, this grants the full set of access rights.
//
// • ROFiles() is like RODirs(), but does not select directory-specific access rights.
// In V1, this means reading and executing files.
//
// • RWFiles() is like RWDirs(), but does not select directory-specific access rights.
// In V1, this means reading, writing and executing files.
//
// The PathAccess() option lets callers define custom subsets of these
// access rights.
func (c Config) RestrictPaths(opts ...pathOpt) error {
	return restrictPaths(c, opts...)
}
