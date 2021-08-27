package landlock

import "strings"

// AccessFSSet is a set of Landlockable file system access operations.
type AccessFSSet uint64

func (a AccessFSSet) String() string {
	if a.isEmpty() {
		return "∅"
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, n := range []string{
		"Execute",
		"WriteFile",
		"ReadFile",
		"ReadDir",
		"RemoveDir",
		"RemoveFile",
		"MakeChar",
		"MakeDir",
		"MakeReg",
		"MakeSock",
		"MakeFifo",
		"MakeBlock",
		"MakeSym",
	} {
		if a&(1<<i) == 0 {
			continue
		}
		if b.Len() > 1 {
			b.WriteByte(',')
		}
		b.WriteString(n)
	}
	b.WriteByte('}')
	return b.String()
}

func (a AccessFSSet) isSubset(b AccessFSSet) bool {
	return a&b == a
}

func (a AccessFSSet) intersect(b AccessFSSet) AccessFSSet {
	return a & b
}

func (a AccessFSSet) isEmpty() bool {
	return a == 0
}
