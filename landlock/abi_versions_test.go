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
	got := abiInfos[5].supportedAccessFS
	want := supportedAccessFS

	if got != want {
		t.Errorf("V3 supported access FS: got %v, want %v", got, want)
	}
}
