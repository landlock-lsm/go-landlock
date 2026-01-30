package landlock

// LoggingSet is a set of logging directives.
type LoggingSet uint64

var loggingNames = []string{
	"same_exec_off",
	"new_exec_on",
	"subdomains_off",
}

var supportedLogging = LoggingSet((1 << len(loggingNames)) - 1)

func (a LoggingSet) String() string {
	return accessSetString(uint64(a), loggingNames)
}

func (a LoggingSet) isSubset(b LoggingSet) bool {
	return a&b == a
}

func (a LoggingSet) intersect(b LoggingSet) LoggingSet {
	return a & b
}

func (a LoggingSet) isEmpty() bool {
	return a == 0
}

func (a LoggingSet) valid() bool {
	return a.isSubset(supportedLogging)
}
