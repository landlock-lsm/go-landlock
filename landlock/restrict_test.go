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

func TestNoPermissions(t *testing.T) {
	RequireLandlockABI(t, 1)
	RunInSubprocess(t, func() {
		dir := TempDir(t)
		fpath := filepath.Join(dir, "lolcat.txt")
		MustWriteFile(t, fpath)

		must(t, landlock.V1.RestrictPaths()) // no permissions

		assertEacces(t, openForRead(fpath), "os.Open()")
		assertEacces(t, readDir(dir), "os.ReadDir()")
		assertEacces(t, openForWrite(fpath+".2"), "os.Create()")
		assertEacces(t, os.Mkdir(filepath.Join(dir, "subdir"), 0600), "mkdir")
		assertEacces(t, os.Remove(fpath), "unlink")
		assertEacces(t, unix.Mkfifo(filepath.Join(dir, "fifo"), 0600), "mkfifo")
	})
}

func TestFileReadPermissionsOnFile(t *testing.T) {
	RequireLandlockABI(t, 1)
	RunInSubprocess(t, func() {
		dir := TempDir(t)
		fpath := filepath.Join(dir, "lolcat.txt")
		MustWriteFile(t, fpath)

		must(t, landlock.V1.RestrictPaths(landlock.ROFiles(fpath)))

		assertOK(t, openForRead(fpath), "os.Open()")
		assertEacces(t, readDir(dir), "os.ReadDir()")
		assertEacces(t, openForWrite(fpath+".2"), "os.Create()")
		assertEacces(t, os.Mkdir(filepath.Join(dir, "subdir"), 0600), "mkdir")
		assertEacces(t, os.Remove(fpath), "unlink")
		assertEacces(t, unix.Mkfifo(filepath.Join(dir, "fifo"), 0600), "mkfifo")
	})
}

func TestFileReadPermissionsOnDir(t *testing.T) {
	RequireLandlockABI(t, 1)
	RunInSubprocess(t, func() {
		dir := TempDir(t)
		fpath := filepath.Join(dir, "lolcat.txt")
		MustWriteFile(t, fpath)

		must(t, landlock.V1.RestrictPaths(landlock.ROFiles(dir)))

		assertOK(t, openForRead(fpath), "os.Open()")
		assertEacces(t, readDir(dir), "os.ReadDir()")
		assertEacces(t, openForWrite(fpath+".2"), "os.Create()")
		assertEacces(t, os.Mkdir(filepath.Join(dir, "subdir"), 0600), "mkdir")
		assertEacces(t, os.Remove(fpath), "unlink")
		assertEacces(t, unix.Mkfifo(filepath.Join(dir, "fifo"), 0600), "mkfifo")
	})
}

func TestDirReadPermissionsOnDir(t *testing.T) {
	RequireLandlockABI(t, 1)
	RunInSubprocess(t, func() {
		dir := TempDir(t)
		fpath := filepath.Join(dir, "lolcat.txt")
		MustWriteFile(t, fpath)

		must(t, landlock.V1.RestrictPaths(landlock.RODirs(dir)))

		assertOK(t, openForRead(fpath), "os.Open()")
		assertOK(t, readDir(dir), "os.ReadDir()")
		assertEacces(t, openForWrite(fpath+".2"), "os.Create()")
		assertEacces(t, os.Mkdir(filepath.Join(dir, "subdir"), 0600), "mkdir")
		assertEacces(t, os.Remove(fpath), "unlink")
		assertEacces(t, unix.Mkfifo(filepath.Join(dir, "fifo"), 0600), "mkfifo")
	})
}

func TestReadWritePermissionsOnDir(t *testing.T) {
	RequireLandlockABI(t, 1)
	RunInSubprocess(t, func() {
		dir := TempDir(t)
		fpath := filepath.Join(dir, "lolcat.txt")
		MustWriteFile(t, fpath)

		must(t, landlock.V1.RestrictPaths(landlock.RWDirs(dir)))

		assertOK(t, openForRead(fpath), "os.Open()")
		assertOK(t, readDir(dir), "os.ReadDir()")
		assertOK(t, openForWrite(fpath+".2"), "os.Create()")
		assertOK(t, os.Mkdir(filepath.Join(dir, "subdir"), 0600), "mkdir")
		assertOK(t, os.Remove(fpath), "unlink")
		assertOK(t, unix.Mkfifo(filepath.Join(dir, "fifo"), 0600), "mkfifo")
	})
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

func readDir(path string) error {
	_, err := os.ReadDir(path)
	return err
}

func assertOK(t testing.TB, e error, msg string) {
	t.Helper()
	if e != nil {
		t.Errorf("%v: want success, got: %v", msg, e)
	}
}

func assertErr(t testing.TB, e error, want error, msg string) {
	t.Helper()
	if !errors.Is(e, want) {
		t.Errorf("%s; got %v, want %v", msg, want, e)
	}
}

func assertEacces(t testing.TB, e error, msg string) {
	t.Helper()
	assertErr(t, e, syscall.EACCES, msg)
}

func must(t testing.TB, e error) {
	t.Helper()
	if e != nil {
		t.Fatalf("Landlock error: %v", e)
	}
}
