package golandlock

import "testing"

func TestFlagSubset(t *testing.T) {
	for _, tc := range []struct {
		a, b uint64
		want bool
	}{
		{0b00110011, 0b01111011, true},
		{0b00000001, 0b00000000, false},
		{0b01000000, 0b00011001, false},
		{0b00010001, 0b00011001, true},
		{0b00011001, 0b00011001, true},
	} {
		got := flagSubset(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("flagSubset(0b%b, 0b%b) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
