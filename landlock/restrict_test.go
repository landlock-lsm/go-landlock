package landlock_test

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
	"golang.org/x/sys/unix"
)

func TestRestrictPaths(t *testing.T) {
	for _, tt := range []struct {
		Name           string
		EnableLandlock func(dir, fpath string) error
		RequiredABI    int
		WantOpenErr    error
		WantReadDirErr error
		WantCreateErr  error
		WantMkdirErr   error
		WantUnlinkErr  error
		WantMkfifoErr  error
		WantReferErr   error
	}{
		{
			Name:        "EverythingForbidden",
			RequiredABI: 1,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths()
			},
			WantOpenErr:    syscall.EACCES,
			WantReadDirErr: syscall.EACCES,
			WantCreateErr:  syscall.EACCES,
			WantMkdirErr:   syscall.EACCES,
			WantUnlinkErr:  syscall.EACCES,
			WantMkfifoErr:  syscall.EACCES,
			WantReferErr:   syscall.EXDEV,
		},
		{
			Name:        "ROFilesPermissionsOnFile",
			RequiredABI: 1,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths(landlock.ROFiles(fpath))
			},
			WantOpenErr:    nil,
			WantReadDirErr: syscall.EACCES,
			WantCreateErr:  syscall.EACCES,
			WantMkdirErr:   syscall.EACCES,
			WantUnlinkErr:  syscall.EACCES,
			WantMkfifoErr:  syscall.EACCES,
			WantReferErr:   syscall.EXDEV,
		},
		{
			Name:        "RWFilesPermissionsOnFile",
			RequiredABI: 1,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths(landlock.RWFiles(fpath))
			},
			WantOpenErr:    nil,
			WantReadDirErr: syscall.EACCES,
			WantCreateErr:  nil,
			WantMkdirErr:   syscall.EACCES,
			WantUnlinkErr:  syscall.EACCES,
			WantMkfifoErr:  syscall.EACCES,
			WantReferErr:   syscall.EXDEV,
		},
		{
			Name:        "ROFilesPermissionsOnDir",
			RequiredABI: 1,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths(landlock.ROFiles(dir))
			},
			WantOpenErr:    nil,
			WantReadDirErr: syscall.EACCES,
			WantCreateErr:  syscall.EACCES,
			WantMkdirErr:   syscall.EACCES,
			WantUnlinkErr:  syscall.EACCES,
			WantMkfifoErr:  syscall.EACCES,
			WantReferErr:   syscall.EXDEV,
		},
		{
			Name:        "RWFilesPermissionsOnDir",
			RequiredABI: 1,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths(landlock.RWFiles(dir))
			},
			WantOpenErr:    nil,
			WantReadDirErr: syscall.EACCES,
			WantCreateErr:  nil,
			WantMkdirErr:   syscall.EACCES,
			WantUnlinkErr:  syscall.EACCES,
			WantMkfifoErr:  syscall.EACCES,
			WantReferErr:   syscall.EXDEV,
		},
		{
			Name:        "RODirsPermissionsOnDir",
			RequiredABI: 1,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths(landlock.RODirs(dir))
			},
			WantOpenErr:    nil,
			WantReadDirErr: nil,
			WantCreateErr:  syscall.EACCES,
			WantMkdirErr:   syscall.EACCES,
			WantUnlinkErr:  syscall.EACCES,
			WantMkfifoErr:  syscall.EACCES,
			WantReferErr:   syscall.EXDEV,
		},
		{
			Name:        "RWDirsPermissionsOnDir",
			RequiredABI: 1,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths(landlock.RWDirs(dir))
			},
			WantOpenErr:    nil,
			WantReadDirErr: nil,
			WantCreateErr:  nil,
			WantMkdirErr:   nil,
			WantUnlinkErr:  nil,
			WantMkfifoErr:  nil,
			WantReferErr:   syscall.EXDEV,
		},
		{
			Name:        "RWDirsWithRefer",
			RequiredABI: 2,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V2.RestrictPaths(landlock.RWDirs(dir).WithRefer())
			},
			WantOpenErr:    nil,
			WantReadDirErr: nil,
			WantCreateErr:  nil,
			WantMkdirErr:   nil,
			WantUnlinkErr:  nil,
			WantMkfifoErr:  nil,
			WantReferErr:   nil,
		},
		{
			Name:        "RWDirsWithoutRefer",
			RequiredABI: 2,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V2.RestrictPaths(landlock.RWDirs(dir) /* without refer */)
			},
			WantOpenErr:    nil,
			WantReadDirErr: nil,
			WantCreateErr:  nil,
			WantMkdirErr:   nil,
			WantUnlinkErr:  nil,
			WantMkfifoErr:  nil,
			WantReferErr:   syscall.EXDEV,
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
