//go:build linux

package landlock

import (
	"slices"
	"testing"

	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

func rulesEqual(a, b Rule) bool {
	switch a := a.(type) {
	case FSRule:
		b, ok := b.(FSRule)
		return ok && a.accessFS == b.accessFS && slices.Equal(a.paths, b.paths)
	case NetRule:
		b, ok := b.(NetRule)
		return ok && a == b
	default:
		return false
	}
}

func TestDowngrade(t *testing.T) {
	for _, tc := range []struct {
		name         string
		cfg          Config
		rules        []Rule
		supportedABI int
		wantCfg      Config
		wantRules    []Rule // nil means V0 fallback expected
	}{
		// FS access downgrade scenarios
		{
			name:         "RestrictHandledToSupported",
			cfg:          Config{handledAccessFS: 0b1111},
			rules:        []Rule{PathAccess(0b111111, "foo")},
			supportedABI: 1,
			wantCfg:      Config{handledAccessFS: 0b1111},
			wantRules:    []Rule{PathAccess(0b1111, "foo")},
		},
		{
			name:         "RestrictPathAccessToHandled",
			cfg:          Config{handledAccessFS: 0b1},
			rules:        []Rule{PathAccess(0b11, "foo")},
			supportedABI: 1,
			wantCfg:      Config{handledAccessFS: 0b1},
			wantRules:    []Rule{PathAccess(0b1, "foo")},
		},
		{
			name:         "DowngradeToEmptyOnV0",
			cfg:          Config{handledAccessFS: 0b1},
			rules:        []Rule{PathAccess(0b11, "foo")},
			supportedABI: 0,
			wantCfg:      Config{},
			wantRules:    []Rule{PathAccess(0, "foo")},
		},
		{
			name:         "ReferSupportedOnV2",
			cfg:          Config{handledAccessFS: ll.AccessFSRefer | ll.AccessFSReadFile},
			rules:        []Rule{PathAccess(ll.AccessFSRefer|ll.AccessFSReadFile, "foo")},
			supportedABI: 2,
			wantCfg:      Config{handledAccessFS: ll.AccessFSRefer | ll.AccessFSReadFile},
			wantRules:    []Rule{PathAccess(ll.AccessFSRefer|ll.AccessFSReadFile, "foo")},
		},
		{
			name:         "ReferNotSupportedOnV1FallsBackToV0",
			cfg:          Config{handledAccessFS: ll.AccessFSRefer | ll.AccessFSReadFile},
			rules:        []Rule{PathAccess(ll.AccessFSRefer|ll.AccessFSReadFile, "foo")},
			supportedABI: 1,
			wantCfg:      v0,
			wantRules:    nil,
		},
		// Network downgrade
		{
			name: "NetworkDowngradeRemovesNet",
			cfg: Config{
				handledAccessFS:  ll.AccessFSWriteFile,
				handledAccessNet: ll.AccessNetConnectTCP,
			},
			rules:        []Rule{ConnectTCP(53)},
			supportedABI: 3,
			wantCfg:      Config{handledAccessFS: ll.AccessFSWriteFile},
			wantRules:    []Rule{NetRule{access: 0, port: 53}},
		},
		// Scoped downgrade
		{
			name:         "ScopedDowngrade",
			cfg:          Config{scoped: ll.ScopeAbstractUnixSocket},
			supportedABI: 5,
			wantCfg:      Config{},
			wantRules:    nil,
		},
		// Flags downgrade
		{
			name:         "FlagsDowngrade",
			cfg:          Config{scoped: ll.ScopeAbstractUnixSocket, flags: ll.FlagRestrictSelfLogNewExecOn},
			supportedABI: 6,
			wantCfg:      Config{scoped: ll.ScopeAbstractUnixSocket},
			wantRules:    nil,
		},
		// Noop - downgrading an ABI's own config is a no-op
		{
			name:         "NoopV0",
			cfg:          abiInfos[0].asConfig(),
			supportedABI: 0,
			wantCfg:      abiInfos[0].asConfig(),
			wantRules:    nil,
		},
		{
			name:         "NoopV1",
			cfg:          abiInfos[1].asConfig(),
			supportedABI: 1,
			wantCfg:      abiInfos[1].asConfig(),
			wantRules:    nil,
		},
		{
			name:         "NoopV2",
			cfg:          abiInfos[2].asConfig(),
			supportedABI: 2,
			wantCfg:      abiInfos[2].asConfig(),
			wantRules:    nil,
		},
		{
			name:         "NoopV3",
			cfg:          abiInfos[3].asConfig(),
			supportedABI: 3,
			wantCfg:      abiInfos[3].asConfig(),
			wantRules:    nil,
		},
		{
			name:         "NoopV4",
			cfg:          abiInfos[4].asConfig(),
			supportedABI: 4,
			wantCfg:      abiInfos[4].asConfig(),
			wantRules:    nil,
		},
		{
			name:         "NoopV5",
			cfg:          abiInfos[5].asConfig(),
			supportedABI: 5,
			wantCfg:      abiInfos[5].asConfig(),
			wantRules:    nil,
		},
		{
			name:         "NoopV6",
			cfg:          abiInfos[6].asConfig(),
			supportedABI: 6,
			wantCfg:      abiInfos[6].asConfig(),
			wantRules:    nil,
		},
		{
			name:         "NoopV7",
			cfg:          abiInfos[7].asConfig(),
			supportedABI: 7,
			wantCfg:      abiInfos[7].asConfig(),
			wantRules:    nil,
		},
		// Multi-field scenarios
		{
			name: "AllFieldsDowngradeToV4",
			cfg: Config{
				handledAccessFS:  (1 << 16) - 1,
				handledAccessNet: (1 << 2) - 1,
				scoped:           (1 << 2) - 1,
				flags:            (1 << 3) - 1,
			},
			rules:        []Rule{PathAccess(ll.AccessFSReadFile, "foo"), ConnectTCP(80)},
			supportedABI: 4,
			wantCfg: Config{
				handledAccessFS:  (1 << 15) - 1,
				handledAccessNet: (1 << 2) - 1,
			},
			wantRules: []Rule{
				PathAccess(ll.AccessFSReadFile, "foo"),
				ConnectTCP(80),
			},
		},
		{
			name: "AllFieldsDowngradeToV6DropsFlags",
			cfg: Config{
				handledAccessFS:  ll.AccessFSReadFile,
				handledAccessNet: ll.AccessNetConnectTCP,
				scoped:           ll.ScopeAbstractUnixSocket,
				flags:            ll.FlagRestrictSelfLogNewExecOn,
			},
			rules:        []Rule{PathAccess(ll.AccessFSReadFile, "foo")},
			supportedABI: 6,
			wantCfg: Config{
				handledAccessFS:  ll.AccessFSReadFile,
				handledAccessNet: ll.AccessNetConnectTCP,
				scoped:           ll.ScopeAbstractUnixSocket,
			},
			wantRules: []Rule{PathAccess(ll.AccessFSReadFile, "foo")},
		},
		// Refer in rule but not in config on V2+ kernel
		// The refer check looks at the downgraded config, not the ABI.
		// If the config doesn't handle refer, the rule triggers v0 fallback
		// even on a V2+ kernel.
		{
			name:         "ReferInRuleButNotInConfigOnV2FallsBackToV0",
			cfg:          Config{handledAccessFS: ll.AccessFSReadFile},
			rules:        []Rule{PathAccess(ll.AccessFSRefer|ll.AccessFSReadFile, "foo")},
			supportedABI: 2,
			wantCfg:      v0,
			wantRules:    nil,
		},
		// Empty rules list
		{
			name:         "EmptyRules",
			cfg:          Config{handledAccessFS: ll.AccessFSReadFile},
			supportedABI: 1,
			wantCfg:      Config{handledAccessFS: ll.AccessFSReadFile},
			wantRules:    []Rule{},
		},
		// BindTCP rule downgrade
		{
			name: "BindTCPDowngrade",
			cfg: Config{
				handledAccessFS:  ll.AccessFSReadFile,
				handledAccessNet: ll.AccessNetBindTCP,
			},
			rules:        []Rule{BindTCP(8080)},
			supportedABI: 3,
			wantCfg:      Config{handledAccessFS: ll.AccessFSReadFile},
			wantRules:    []Rule{NetRule{access: 0, port: 8080}},
		},
		// V3→V2 boundary: truncate stripped
		{
			name:         "TruncateStrippedOnV2",
			cfg:          Config{handledAccessFS: ll.AccessFSTruncate | ll.AccessFSReadFile},
			rules:        []Rule{PathAccess(ll.AccessFSTruncate|ll.AccessFSReadFile, "foo")},
			supportedABI: 2,
			wantCfg:      Config{handledAccessFS: ll.AccessFSReadFile},
			wantRules:    []Rule{PathAccess(ll.AccessFSReadFile, "foo")},
		},
		// V5→V4 boundary: IoctlDev stripped
		{
			name:         "IoctlDevStrippedOnV4",
			cfg:          Config{handledAccessFS: ll.AccessFSIoctlDev | ll.AccessFSReadFile},
			rules:        []Rule{PathAccess(ll.AccessFSIoctlDev|ll.AccessFSReadFile, "foo")},
			supportedABI: 4,
			wantCfg:      Config{handledAccessFS: ll.AccessFSReadFile},
			wantRules:    []Rule{PathAccess(ll.AccessFSReadFile, "foo")},
		},
		{
			name: "FSAndNetAndScopeDowngradeToV5DropsScope",
			cfg: Config{
				handledAccessFS:  ll.AccessFSReadFile | ll.AccessFSIoctlDev,
				handledAccessNet: ll.AccessNetBindTCP,
				scoped:           ll.ScopeSignal,
			},
			supportedABI: 5,
			wantCfg: Config{
				handledAccessFS:  ll.AccessFSReadFile | ll.AccessFSIoctlDev,
				handledAccessNet: ll.AccessNetBindTCP,
			},
			wantRules: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotCfg, gotRules := downgrade(tc.cfg, tc.rules, abiInfos[tc.supportedABI])

			gotCfg.bestEffort = false // ignored for comparison
			if gotCfg != tc.wantCfg {
				t.Errorf("config: got %v, want %v", gotCfg, tc.wantCfg)
			}

			if len(gotRules) != len(tc.wantRules) {
				t.Fatalf("rules count: got %d, want %d", len(gotRules), len(tc.wantRules))
			}
			for i := range gotRules {
				if !rulesEqual(gotRules[i], tc.wantRules[i]) {
					t.Errorf("rule %d: got %v, want %v", i, gotRules[i], tc.wantRules[i])
				}
			}
		})
	}
}
