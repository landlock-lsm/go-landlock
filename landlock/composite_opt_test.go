package landlock

import (
	"fmt"
	"testing"
)

func TestCompositeRuleString(t *testing.T) {
	got := fmt.Sprintf("%v", CompositeRule(RODirs("/usr"), BindTCP(8080)))
	want := "REQUIRE {execute,read_file,read_dir} for paths [/usr], ALLOW {bind_tcp} on port 8080"
	if got != want {
		t.Errorf("CompositeRule(…) = %q, want %q", got, want)
	}
}
