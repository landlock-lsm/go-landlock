package landlock

import (
	"testing"

	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

func TestDowngrade(t *testing.T) {
	for _, tc := range []struct {
		Name string

		Handled      AccessFSSet
		Requested    AccessFSSet
		SupportedABI int

		WantHandled   AccessFSSet
		WantRequested AccessFSSet

		WantFallbackToV0 bool
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
		{
			Name:          "ReferSupportedOnV2",
			SupportedABI:  2,
			Handled:       ll.AccessFSRefer | ll.AccessFSReadFile,
			Requested:     ll.AccessFSRefer | ll.AccessFSReadFile,
			WantHandled:   ll.AccessFSRefer | ll.AccessFSReadFile,
			WantRequested: ll.AccessFSRefer | ll.AccessFSReadFile,
		},
		{
			Name:             "ReferNotSupportedOnV1",
			SupportedABI:     1,
			Handled:          ll.AccessFSRefer | ll.AccessFSReadFile,
			Requested:        ll.AccessFSRefer | ll.AccessFSReadFile,
			WantFallbackToV0: true,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			abi := abiInfos[tc.SupportedABI]

			rules := []Rule{PathAccess(tc.Requested, "foo")}
			cfg := Config{handledAccessFS: tc.Handled}
			gotCfg, gotRules := downgrade(cfg, rules, abi)

			if tc.WantFallbackToV0 {
				if gotCfg != v0 {
					t.Errorf(
						"downgrade(%v, %v, ABIv%d) = %v, %v; want fallback to V0",
						cfg, tc.Requested, tc.SupportedABI,
						gotCfg, gotRules,
					)
				}
				return
			}

			if len(gotRules) != 1 {
				t.Fatalf("wrong number of rules returned: got %d, want 1", len(gotRules))
			}
			gotRequested := gotRules[0].(FSRule).accessFS
			gotHandled := gotCfg.handledAccessFS

			if gotHandled != tc.WantHandled || gotRequested != tc.WantRequested {
				t.Errorf(
					"Unexpected result\ndowngrade(%v, %v, ABIv%d)\n        = %v, %v\n     want %v, %v",
					cfg, tc.Requested, tc.SupportedABI,
					gotCfg, gotRequested,
					Config{handledAccessFS: tc.WantHandled}, tc.WantRequested,
				)
			}
		})
	}
}
