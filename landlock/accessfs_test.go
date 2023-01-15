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
		{a: 0b1111111111111, want: "{execute,write_file,read_file,read_dir,remove_dir,remove_file,make_char,make_dir,make_reg,make_sock,make_fifo,make_block,make_sym}"},
		{a: 0b1111100000000, want: "{make_reg,make_sock,make_fifo,make_block,make_sym}"},
		{a: 0b0000011111111, want: "{execute,write_file,read_file,read_dir,remove_dir,remove_file,make_char,make_dir}"},
		{a: ll.AccessFSExecute, want: "{execute}"},
		{a: ll.AccessFSWriteFile, want: "{write_file}"},
		{a: ll.AccessFSReadFile, want: "{read_file}"},
		{a: ll.AccessFSReadDir, want: "{read_dir}"},
		{a: ll.AccessFSRemoveDir, want: "{remove_dir}"},
		{a: ll.AccessFSRemoveFile, want: "{remove_file}"},
		{a: ll.AccessFSMakeChar, want: "{make_char}"},
		{a: ll.AccessFSMakeDir, want: "{make_dir}"},
		{a: ll.AccessFSMakeReg, want: "{make_reg}"},
		{a: ll.AccessFSMakeSock, want: "{make_sock}"},
		{a: ll.AccessFSMakeFifo, want: "{make_fifo}"},
		{a: ll.AccessFSMakeBlock, want: "{make_block}"},
		{a: ll.AccessFSMakeSym, want: "{make_sym}"},
		{a: ll.AccessFSRefer, want: "{refer}"},
		{a: ll.AccessFSTruncate, want: "{truncate}"},
		{a: ll.AccessFSReadFile | 1<<63, want: "{read_file,1<<63}"},
	} {
		got := tc.a.String()
		if got != tc.want {
			t.Errorf("AccessFSSet(%08x).String() = %q, want %q", uint64(tc.a), got, tc.want)
		}
	}
}

func TestValid(t *testing.T) {
	for _, a := range []AccessFSSet{
		ll.AccessFSExecute, ll.AccessFSMakeDir, ll.AccessFSMakeSym, ll.AccessFSRefer,
	} {
		gotIsValid := a.valid()
		if !gotIsValid {
			t.Errorf("%v.valid() = false, want true", a)
		}
	}
}
