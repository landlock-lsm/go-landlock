package landlock

import (
	"testing"
)

func TestDowngrade(t *testing.T) {
	for _, tc := range []struct {
		Name string

		Handled      AccessFSSet
		Requested    AccessFSSet
		SupportedABI int

		WantHandled   AccessFSSet
		WantRequested AccessFSSet
	}{
		{
			Name:          "RestrictHandledToSupported",
			SupportedABI:  1,
			Handled:       0b1111,
			Requested:     0b111111,
			WantHandled:   0b1111,
			WantRequested: 0b1111,
		},
		{
			Name:          "RestrictPathAccessToHandled",
			SupportedABI:  1,
			Handled:       0b1,
			Requested:     0b11,
			WantHandled:   0b1,
			WantRequested: 0b1,
		},
		{
			Name:          "DowngradeToV0IfKernelDoesNotSupportV1",
			SupportedABI:  0,
			Handled:       0b1,
			Requested:     0b11,
			WantHandled:   0b0,
			WantRequested: 0b0,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			abi := abiInfos[tc.SupportedABI]

			opts := []PathOpt{PathAccess(tc.Requested, "foo")}
			gotHandled, gotOpts := downgrade(tc.Handled, opts, abi)

			if len(gotOpts) != 1 {
				t.Fatalf("wrong number of opts returned: got %d, want 1", len(gotOpts))
			}
			gotRequested := gotOpts[0].accessFS

			if gotHandled != tc.WantHandled || gotRequested != tc.WantRequested {
				t.Errorf(
					"Unexpected result\ndowngrade(%v, %v, ABIv%d)\n        = %v, %v\n     want %v, %v",
					tc.Handled, tc.Requested, tc.SupportedABI,
					gotHandled, gotRequested,
					tc.WantHandled, tc.WantRequested,
				)
			}
		})
	}
}
