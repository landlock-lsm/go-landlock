package landlock

import (
	"errors"
	"fmt"

	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// Access permission sets for filesystem access.
const (
	// The set of access rights that only apply to files.
	accessFile AccessFSSet = ll.AccessFSExecute | ll.AccessFSWriteFile | ll.AccessFSReadFile

	// The set of access rights associated with read access to files and directories.
	accessFSRead AccessFSSet = ll.AccessFSExecute | ll.AccessFSReadFile | ll.AccessFSReadDir

	// The set of access rights associated with write access to files and directories.
	accessFSWrite AccessFSSet = ll.AccessFSWriteFile | ll.AccessFSRemoveDir | ll.AccessFSRemoveFile | ll.AccessFSMakeChar | ll.AccessFSMakeDir | ll.AccessFSMakeReg | ll.AccessFSMakeSock | ll.AccessFSMakeFifo | ll.AccessFSMakeBlock | ll.AccessFSMakeSym | ll.AccessFSTruncate

	// The set of access rights associated with read and write access to files and directories.
	accessFSReadWrite AccessFSSet = accessFSRead | accessFSWrite
)

// These are Landlock configurations for the currently supported
// Landlock ABI versions, configured to restrict the highest possible
// set of operations possible for each version.
//
// The higher the ABI version, the more operations Landlock will be
// able to restrict.
var (
	// Landlock V1 support (basic file operations).
	V1 = Config{
		handledAccessFS: abiInfos[1].supportedAccessFS,
	}
	// Landlock V2 support (V1 + file reparenting between different directories)
	V2 = Config{
		handledAccessFS: abiInfos[2].supportedAccessFS,
	}
	// Landlock V3 support (V2 + file truncation)
	V3 = Config{
		handledAccessFS: abiInfos[3].supportedAccessFS,
	}
)

// The Landlock configuration describes the desired set of
// landlockable operations to be restricted and the constraints on it
// (e.g. best effort mode).
type Config struct {
	handledAccessFS AccessFSSet
	bestEffort      bool
}

// NewConfig creates a new Landlock configuration with the given parameters.
//
// Passing an AccessFSSet will set that as the set of file system
// operations to restrict when enabling Landlock. The AccessFSSet
// needs to stay within the bounds of what go-landlock supports.
// (If you are getting an error, you might need to upgrade to a newer
// version of go-landlock.)
func NewConfig(args ...interface{}) (*Config, error) {
	// Implementation note: This factory is written with future
	// extensibility in mind. Only specific types are supported as
	// input, but in the future more might be added.
	//
	// This constructor ensures that callers can't construct
	// invalid Config values.
	var c Config
	for _, arg := range args {
		if afs, ok := arg.(AccessFSSet); ok {
			if !c.handledAccessFS.isEmpty() {
				return nil, errors.New("only one AccessFSSet may be provided")
			}
			if !afs.valid() {
				return nil, errors.New("unsupported AccessFSSet value; upgrade go-landlock?")
			}
			c.handledAccessFS = afs
		} else {
			return nil, fmt.Errorf("unknown argument %v; only AccessFSSet-type argument is supported", arg)
		}
	}
	return &c, nil
}

// MustConfig is like NewConfig but panics on error.
func MustConfig(args ...interface{}) Config {
	c, err := NewConfig(args...)
	if err != nil {
		panic(err)
	}
	return *c
}

// String builds a human-readable representation of the Config.
func (c Config) String() string {
	abi := abiInfo{version: -1} // invalid
	for i := len(abiInfos) - 1; i >= 0; i-- {
		a := abiInfos[i]
		if c.handledAccessFS.isSubset(a.supportedAccessFS) {
			abi = a
		}
	}

	var desc = c.handledAccessFS.String()
	if abi.supportedAccessFS == c.handledAccessFS && c.handledAccessFS != 0 {
		desc = "all"
	}

	var bestEffort = ""
	if c.bestEffort {
		bestEffort = " (best effort)"
	}

	var version string
	if abi.version < 0 {
		version = "V???"
	} else {
		version = fmt.Sprintf("V%v", abi.version)
	}

	return fmt.Sprintf("{Landlock %v; HandledAccessFS: %v%v}", version, desc, bestEffort)
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

// RestrictPaths restricts all goroutines to only "see" the files
// provided as inputs. After this call successfully returns, the
// goroutines will only be able to use files in the ways as they were
// specified in advance in the call to RestrictPaths.
//
// Example: The following invocation will restrict all goroutines so
// that it can only read from /usr, /bin and /tmp, and only write to
// /tmp:
//
//	err := landlock.V3.RestrictPaths(
//	    landlock.RODirs("/usr", "/bin"),
//	    landlock.RWDirs("/tmp"),
//	)
//	if err != nil {
//	    log.Fatalf("landlock.V3.RestrictPaths(): %v", err)
//	}
//
// RestrictPaths returns an error if any of the given paths does not
// denote an actual directory or file, or if Landlock can't be enforced
// using the desired ABI version constraints.
//
// RestrictPaths also sets the "no new privileges" flag for all OS
// threads managed by the Go runtime.
//
// # Restrictable access rights
//
// The notions of what "reading" and "writing" mean are limited by what
// the selected Landlock version supports.
//
// Calling RestrictPaths with a given Landlock ABI version will
// inhibit all future calls to the access rights supported by this ABI
// version, unless the accessed path is in a file hierarchy that is
// specifically allow-listed for a specific set of access rights.
//
// The overall set of operations that RestrictPaths can restrict are:
//
// For reading:
//
//   - Executing a file (V1+)
//   - Opening a file with read access (V1+)
//   - Opening a directory or listing its content (V1+)
//
// For writing:
//
//   - Opening a file with write access (V1+)
//   - Truncating file contents (V3+)
//
// For directory manipulation:
//
//   - Removing an empty directory or renaming one (V1+)
//   - Removing (or renaming) a file (V1+)
//   - Creating (or renaming or linking) a character device (V1+)
//   - Creating (or renaming) a directory (V1+)
//   - Creating (or renaming or linking) a regular file (V1+)
//   - Creating (or renaming or linking) a UNIX domain socket (V1+)
//   - Creating (or renaming or linking) a named pipe (V1+)
//   - Creating (or renaming or linking) a block device (V1+)
//   - Creating (or renaming or linking) a symbolic link (V1+)
//   - Renaming or linking a file between directories (V2+)
//
// Future versions of Landlock will be able to inhibit more operations.
// Quoting the Landlock documentation:
//
//	It is currently not possible to restrict some file-related
//	actions accessible through these syscall families: chdir(2),
//	stat(2), flock(2), chmod(2), chown(2), setxattr(2), utime(2),
//	ioctl(2), fcntl(2), access(2). Future Landlock evolutions will
//	enable to restrict them.
//
// The access rights are documented in more depth in the
// [Kernel Documentation about Access Rights].
//
// # Helper functions for selecting access rights
//
// These helper functions help selecting common subsets of access rights:
//
//   - [RODirs] selects access rights in the group "for reading".
//     In V1, this means reading files, listing directories and executing files.
//   - [RWDirs] selects access rights in the group "for reading", "for writing" and
//     "for directory manipulation". This grants the full set of access rights which are
//     available within the configuration.
//   - [ROFiles] is like [RODirs], but does not select directory-specific access rights.
//     In V1, this means reading and executing files.
//   - [RWFiles] is like [RWDirs], but does not select directory-specific access rights.
//     In V1, this means reading, writing and executing files.
//
// The [PathAccess] option lets callers define custom subsets of these
// access rights. AccessFSSets permitted using [PathAccess] must be a
// subset of the [AccessFSSet] that the Config restricts.
//
// [Kernel Documentation about Access Rights]: https://www.kernel.org/doc/html/latest/userspace-api/landlock.html#access-rights
func (c Config) RestrictPaths(opts ...PathOpt) error {
	return restrictPaths(c, opts...)
}
