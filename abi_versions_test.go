package golandlock

import (
	"testing"

	ll "github.com/gnoack/golandlock/syscall"
)

func TestAbiVersionsIncrementing(t *testing.T) {
	for i, abiInfo := range abiInfos {
		if i != abiInfo.version {
			t.Errorf("Expected ABI version %d at index %d, got version %d", i, i, abiInfo.version)
		}
	}
}

func TestSupportedAccessFS(t *testing.T) {
	got := abiInfos[1].supportedAccessFS
	want := AccessFSSet(ll.AccessFSWriteFile | ll.AccessFSRemoveDir | ll.AccessFSRemoveFile | ll.AccessFSMakeChar | ll.AccessFSMakeDir | ll.AccessFSMakeReg | ll.AccessFSMakeSock | ll.AccessFSMakeFifo | ll.AccessFSMakeBlock | ll.AccessFSMakeSym | ll.AccessFSExecute | ll.AccessFSReadFile | ll.AccessFSReadDir)

	if got != want {
		t.Errorf("V1 supported access FS: got %x, want %x", got, want)
	}
}
