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
		WantOpenErr    error
		WantReadDirErr error
		WantCreateErr  error
		WantMkdirErr   error
		WantUnlinkErr  error
		WantMkfifoErr  error
	}{
		{
			Name: "EverythingForbidden",
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths()
			},
			WantOpenErr:    syscall.EACCES,
			WantReadDirErr: syscall.EACCES,
			WantCreateErr:  syscall.EACCES,
			WantMkdirErr:   syscall.EACCES,
			WantUnlinkErr:  syscall.EACCES,
			WantMkfifoErr:  syscall.EACCES,
		},
		{
			Name: "ROFilesPermissionsOnFile",
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths(landlock.ROFiles(fpath))
			},
			WantOpenErr:    nil,
			WantReadDirErr: syscall.EACCES,
			WantCreateErr:  syscall.EACCES,
			WantMkdirErr:   syscall.EACCES,
			WantUnlinkErr:  syscall.EACCES,
			WantMkfifoErr:  syscall.EACCES,
		},
		{
			Name: "RWFilesPermissionsOnFile",
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths(landlock.RWFiles(fpath))
			},
			WantOpenErr:    nil,
			WantReadDirErr: syscall.EACCES,
			WantCreateErr:  nil,
			WantMkdirErr:   syscall.EACCES,
			WantUnlinkErr:  syscall.EACCES,
			WantMkfifoErr:  syscall.EACCES,
		},
		{
			Name: "ROFilesPermissionsOnDir",
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths(landlock.ROFiles(dir))
			},
			WantOpenErr:    nil,
			WantReadDirErr: syscall.EACCES,
			WantCreateErr:  syscall.EACCES,
			WantMkdirErr:   syscall.EACCES,
			WantUnlinkErr:  syscall.EACCES,
			WantMkfifoErr:  syscall.EACCES,
		},
		{
			Name: "RWFilesPermissionsOnDir",
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths(landlock.RWFiles(dir))
			},
			WantOpenErr:    nil,
			WantReadDirErr: syscall.EACCES,
			WantCreateErr:  nil,
			WantMkdirErr:   syscall.EACCES,
			WantUnlinkErr:  syscall.EACCES,
			WantMkfifoErr:  syscall.EACCES,
		},
		{
			Name: "RODirsPermissionsOnDir",
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths(landlock.RODirs(dir))
			},
			WantOpenErr:    nil,
			WantReadDirErr: nil,
			WantCreateErr:  syscall.EACCES,
			WantMkdirErr:   syscall.EACCES,
			WantUnlinkErr:  syscall.EACCES,
			WantMkfifoErr:  syscall.EACCES,
		},
		{
			Name: "RWDirsPermissionsOnDir",
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths(landlock.RWDirs(dir))
			},
			WantOpenErr:    nil,
			WantReadDirErr: nil,
			WantCreateErr:  nil,
			WantMkdirErr:   nil,
			WantUnlinkErr:  nil,
			WantMkfifoErr:  nil,
		},
	} {
		t.Run(tt.Name, func(t *testing.T) {
			RunInSubprocess(t, func() {
				RequireLandlockABI(t, 1)

				dir := TempDir(t)
				fpath := filepath.Join(dir, "lolcat.txt")
				MustWriteFile(t, fpath)

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

				subdirpath := filepath.Join(dir, "subdir")
				if err := os.Mkdir(subdirpath, 0600); !errEqual(err, tt.WantMkdirErr) {
					t.Errorf("os.Mkdir(%q) = «%v», want «%v»", subdirpath, err, tt.WantMkdirErr)
				}

				if err := os.Remove(fpath); !errEqual(err, tt.WantUnlinkErr) {
					t.Errorf("os.Remove(%q) = «%v», want «%v»", fpath, err, tt.WantUnlinkErr)
				}

				fifopath := filepath.Join(dir, "fifo")
				if err := unix.Mkfifo(fifopath, 0600); !errEqual(err, tt.WantMkfifoErr) {
					t.Errorf("os.Mkfifo(%q, ...) = «%v», want «%v»", fifopath, err, tt.WantMkfifoErr)
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
