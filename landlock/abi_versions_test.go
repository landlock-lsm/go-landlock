package landlock

import (
	"testing"
)

func TestABIVersionsIncrementing(t *testing.T) {
	for i, abiInfo := range abiInfos {
		if i != abiInfo.version {
			t.Errorf("abiInfos[%d].version = %d, want %d", i, abiInfo.version, i)
		}
	}
}

func TestSupportedAccessFS(t *testing.T) {
	got := abiInfos[10].supportedAccessFS
	want := supportedAccessFS

	if got != want {
		t.Errorf("V10 supported access FS: got %v, want %v", got, want)
	}
}

func TestSupportedAccessNet(t *testing.T) {
	got := abiInfos[10].supportedAccessNet
	want := supportedAccessNet

	if got != want {
		t.Errorf("V10 supported access Net: got %v, want %v", got, want)
	}
}
