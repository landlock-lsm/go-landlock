package landlock

import (
	"testing"
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
	want := supportedAccessFS

	if got != want {
		t.Errorf("V1 supported access FS: got %x, want %x", got, want)
	}
}
