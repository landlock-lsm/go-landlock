package landlock

// restrictFlagsSet is a set of logging directives.
type restrictFlagsSet uint32

var flagNames = []string{
	"log_same_exec_off",
	"log_new_exec_on",
	"log_subdomains_off",
}

func (a restrictFlagsSet) String() string {
	if a == 0 {
		// When no flag is set, logging will be done for the
		// program execution only, as long as the kernel
		// supports it. Otherwise, no logging is done.
		return "∅"
	}
	return accessSetString(uint64(a), flagNames)
}

func (a restrictFlagsSet) isSubset(b restrictFlagsSet) bool {
	return a&b == a
}

func (a restrictFlagsSet) intersect(b restrictFlagsSet) restrictFlagsSet {
	return a & b
}
