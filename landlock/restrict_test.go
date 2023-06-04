//go:build linux

package landlock_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
	"golang.org/x/sys/unix"
)

func TestRestrictPaths(t *testing.T) {
	// On kernels before 5.19.8, some refer cases returned EXDEV
	// which now return EACCES.
	exdevBefore5198 := syscall.EXDEV
	if major, minor, patch := OSRelease(t); 1000*1000*major+1000*minor+patch >= 5019008 {
		exdevBefore5198 = syscall.EACCES
	}

	for _, tt := range []struct {
		Name            string
		EnableLandlock  func(dir, fpath string) error
		RequiredABI     int
		WantOpenErr     error
		WantReadDirErr  error
		WantCreateErr   error
		WantMkdirErr    error
		WantUnlinkErr   error
		WantMkfifoErr   error
		WantReferErr    error
		WantTruncateErr error
	}{
		{
			Name:        "EverythingForbidden",
			RequiredABI: 1,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths()
			},
			WantOpenErr:     syscall.EACCES,
			WantReadDirErr:  syscall.EACCES,
			WantCreateErr:   syscall.EACCES,
			WantMkdirErr:    syscall.EACCES,
			WantUnlinkErr:   syscall.EACCES,
			WantMkfifoErr:   syscall.EACCES,
			WantReferErr:    exdevBefore5198,
			WantTruncateErr: nil,
		},
		{
			Name:        "ROFilesPermissionsOnFile",
			RequiredABI: 1,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths(landlock.ROFiles(fpath))
			},
			WantOpenErr:     nil,
			WantReadDirErr:  syscall.EACCES,
			WantCreateErr:   syscall.EACCES,
			WantMkdirErr:    syscall.EACCES,
			WantUnlinkErr:   syscall.EACCES,
			WantMkfifoErr:   syscall.EACCES,
			WantReferErr:    exdevBefore5198,
			WantTruncateErr: nil,
		},
		{
			Name:        "RWFilesPermissionsOnFile",
			RequiredABI: 1,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths(landlock.RWFiles(fpath))
			},
			WantOpenErr:     nil,
			WantReadDirErr:  syscall.EACCES,
			WantCreateErr:   nil,
			WantMkdirErr:    syscall.EACCES,
			WantUnlinkErr:   syscall.EACCES,
			WantMkfifoErr:   syscall.EACCES,
			WantReferErr:    exdevBefore5198,
			WantTruncateErr: nil,
		},
		{
			Name:        "ROFilesPermissionsOnDir",
			RequiredABI: 1,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths(landlock.ROFiles(dir))
			},
			WantOpenErr:     nil,
			WantReadDirErr:  syscall.EACCES,
			WantCreateErr:   syscall.EACCES,
			WantMkdirErr:    syscall.EACCES,
			WantUnlinkErr:   syscall.EACCES,
			WantMkfifoErr:   syscall.EACCES,
			WantReferErr:    exdevBefore5198,
			WantTruncateErr: nil,
		},
		{
			Name:        "RWFilesPermissionsOnDir",
			RequiredABI: 1,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths(landlock.RWFiles(dir))
			},
			WantOpenErr:     nil,
			WantReadDirErr:  syscall.EACCES,
			WantCreateErr:   nil,
			WantMkdirErr:    syscall.EACCES,
			WantUnlinkErr:   syscall.EACCES,
			WantMkfifoErr:   syscall.EACCES,
			WantReferErr:    exdevBefore5198,
			WantTruncateErr: nil,
		},
		{
			Name:        "RODirsPermissionsOnDir",
			RequiredABI: 1,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths(landlock.RODirs(dir))
			},
			WantOpenErr:     nil,
			WantReadDirErr:  nil,
			WantCreateErr:   syscall.EACCES,
			WantMkdirErr:    syscall.EACCES,
			WantUnlinkErr:   syscall.EACCES,
			WantMkfifoErr:   syscall.EACCES,
			WantReferErr:    exdevBefore5198,
			WantTruncateErr: nil,
		},
		{
			Name:        "RWDirsPermissionsOnDir",
			RequiredABI: 1,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths(landlock.RWDirs(dir))
			},
			WantOpenErr:     nil,
			WantReadDirErr:  nil,
			WantCreateErr:   nil,
			WantMkdirErr:    nil,
			WantUnlinkErr:   nil,
			WantMkfifoErr:   nil,
			WantReferErr:    syscall.EXDEV,
			WantTruncateErr: nil,
		},
		{
			Name:        "RWDirsWithRefer",
			RequiredABI: 2,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V2.RestrictPaths(landlock.RWDirs(dir).WithRefer())
			},
			WantOpenErr:     nil,
			WantReadDirErr:  nil,
			WantCreateErr:   nil,
			WantMkdirErr:    nil,
			WantUnlinkErr:   nil,
			WantMkfifoErr:   nil,
			WantReferErr:    nil,
			WantTruncateErr: nil,
		},
		{
			Name:        "RWDirsWithoutRefer",
			RequiredABI: 2,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V2.RestrictPaths(landlock.RWDirs(dir) /* without refer */)
			},
			WantOpenErr:     nil,
			WantReadDirErr:  nil,
			WantCreateErr:   nil,
			WantMkdirErr:    nil,
			WantUnlinkErr:   nil,
			WantMkfifoErr:   nil,
			WantReferErr:    syscall.EXDEV,
			WantTruncateErr: nil,
		},
		{
			Name:        "RWDirsV3",
			RequiredABI: 3,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V3.RestrictPaths(landlock.RWDirs(dir))
			},
			WantOpenErr:     nil,
			WantReadDirErr:  nil,
			WantCreateErr:   nil,
			WantMkdirErr:    nil,
			WantUnlinkErr:   nil,
			WantMkfifoErr:   nil,
			WantReferErr:    syscall.EXDEV,
			WantTruncateErr: nil,
		},
		{
			Name:        "EverythingForbiddenV3",
			RequiredABI: 3,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V3.RestrictPaths()
			},
			WantOpenErr:     syscall.EACCES,
			WantReadDirErr:  syscall.EACCES,
			WantCreateErr:   syscall.EACCES,
			WantMkdirErr:    syscall.EACCES,
			WantUnlinkErr:   syscall.EACCES,
			WantMkfifoErr:   syscall.EACCES,
			WantReferErr:    exdevBefore5198,
			WantTruncateErr: syscall.EACCES,
		},
	} {
		t.Run(tt.Name, func(t *testing.T) {
			RunInSubprocess(t, func() {
				RequireLandlockABI(t, tt.RequiredABI)

				dir := TempDir(t)
				fpath := filepath.Join(dir, "lolcat.txt")
				MustWriteFile(t, fpath)
				renameMeFpath := filepath.Join(dir, "renameme.txt")
				MustWriteFile(t, renameMeFpath)
				dstDirPath := filepath.Join(dir, "dst")
				MustMkdir(t, dstDirPath)

				err := tt.EnableLandlock(dir, fpath)
				if err != nil {
					t.Fatalf("Enabling Landlock: %v", err)
				}

				if err := openForRead(fpath); !errEqual(err, tt.WantOpenErr) {
					t.Errorf("openForRead(%q) = «%v», want «%v»", fpath, err, tt.WantOpenErr)
				}

				if _, err := os.ReadDir(dir); !errEqual(err, tt.WantReadDirErr) {
					t.Errorf("os.ReadDir(%q) = «%v», want «%v»", dir, err, tt.WantReadDirErr)
				}

				if err := openForWrite(fpath); !errEqual(err, tt.WantCreateErr) {
					t.Errorf("os.Create(%q) = «%v», want «%v»", fpath, err, tt.WantCreateErr)
				}

				if err := os.Truncate(fpath, 3); !errEqual(err, tt.WantTruncateErr) {
					t.Errorf("os.Truncate(%q, ...) = «%v», want «%v»", fpath, err, tt.WantTruncateErr)
				}

				subdirPath := filepath.Join(dir, "subdir")
				if err := os.Mkdir(subdirPath, 0600); !errEqual(err, tt.WantMkdirErr) {
					t.Errorf("os.Mkdir(%q) = «%v», want «%v»", subdirPath, err, tt.WantMkdirErr)
				}

				if err := os.Remove(fpath); !errEqual(err, tt.WantUnlinkErr) {
					t.Errorf("os.Remove(%q) = «%v», want «%v»", fpath, err, tt.WantUnlinkErr)
				}

				fifoPath := filepath.Join(dir, "fifo")
				if err := unix.Mkfifo(fifoPath, 0600); !errEqual(err, tt.WantMkfifoErr) {
					t.Errorf("os.Mkfifo(%q, ...) = «%v», want «%v»", fifoPath, err, tt.WantMkfifoErr)
				}

				dstFpath := filepath.Join(dstDirPath, "target.txt")
				if err := os.Rename(renameMeFpath, dstFpath); !errEqual(err, tt.WantReferErr) {
					t.Errorf("os.Rename(%q, %q) = «%v», want «%v»", renameMeFpath, dstFpath, err, tt.WantReferErr)
				}
			})
		})
	}
}

func errEqual(got, want error) bool {
	if got == nil && want == nil {
		return true
	}
	return errors.Is(got, want)
}

func openForRead(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return nil
}

func openForWrite(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return nil
}

func OSRelease(t testing.TB) (major, minor, patch int) {
	t.Helper()

	var buf unix.Utsname
	if err := unix.Uname(&buf); err != nil {
		t.Fatalf("Uname: %v", err)
	}
	release := string(buf.Release[:bytes.IndexByte(buf.Release[:], 0)])
	release, _, _ = strings.Cut(release, "-")
	release, _, _ = strings.Cut(release, "+")

	parts := strings.SplitN(release, ".", 4)
	if len(parts) < 3 {
		t.Fatalf("Invalid release format %q", release)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		t.Fatalf("strconv.Atoi(%q): %v", parts[0], err)
	}
	minor, err = strconv.Atoi(parts[1])
	if err != nil {
		t.Fatalf("strconv.Atoi(%q): %v", parts[1], err)
	}
	patch, err = strconv.Atoi(parts[2])
	if err != nil {
		t.Fatalf("strconv.Atoi(%q): %v", parts[2], err)
	}
	return major, minor, patch
}
