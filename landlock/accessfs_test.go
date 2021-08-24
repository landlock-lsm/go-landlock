package landlock

import (
	"testing"

	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

func TestSubset(t *testing.T) {
	for _, tc := range []struct {
		a, b AccessFSSet
		want bool
	}{
		{0b00110011, 0b01111011, true},
		{0b00000001, 0b00000000, false},
		{0b01000000, 0b00011001, false},
		{0b00010001, 0b00011001, true},
		{0b00011001, 0b00011001, true},
	} {
		got := tc.a.isSubset(tc.b)
		if got != tc.want {
			t.Errorf("flagSubset(0b%b, 0b%b) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestPrettyPrint(t *testing.T) {
	for _, tc := range []struct {
		a    AccessFSSet
		want string
	}{
		{a: 0, want: "∅"},
		{a: 0b1111111111111, want: "{Execute,WriteFile,ReadFile,ReadDir,RemoveDir,RemoveFile,MakeChar,MakeDir,MakeReg,MakeSock,MakeFifo,MakeBlock,MakeSym}"},
		{a: 0b1111100000000, want: "{MakeReg,MakeSock,MakeFifo,MakeBlock,MakeSym}"},
		{a: 0b0000011111111, want: "{Execute,WriteFile,ReadFile,ReadDir,RemoveDir,RemoveFile,MakeChar,MakeDir}"},
		{a: ll.AccessFSExecute, want: "{Execute}"},
		{a: ll.AccessFSWriteFile, want: "{WriteFile}"},
		{a: ll.AccessFSReadFile, want: "{ReadFile}"},
		{a: ll.AccessFSReadDir, want: "{ReadDir}"},
		{a: ll.AccessFSRemoveDir, want: "{RemoveDir}"},
		{a: ll.AccessFSRemoveFile, want: "{RemoveFile}"},
		{a: ll.AccessFSMakeChar, want: "{MakeChar}"},
		{a: ll.AccessFSMakeDir, want: "{MakeDir}"},
		{a: ll.AccessFSMakeReg, want: "{MakeReg}"},
		{a: ll.AccessFSMakeSock, want: "{MakeSock}"},
		{a: ll.AccessFSMakeFifo, want: "{MakeFifo}"},
		{a: ll.AccessFSMakeBlock, want: "{MakeBlock}"},
		{a: ll.AccessFSMakeSym, want: "{MakeSym}"},
	} {
		got := tc.a.String()
		if got != tc.want {
			t.Errorf("AccessFSSet(%08x).String() = %q, want %q", uint64(tc.a), got, tc.want)
		}
	}
}
