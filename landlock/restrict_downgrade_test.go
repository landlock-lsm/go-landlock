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
	case QuietFSRule:
		b, ok := b.(QuietFSRule)
		return ok && slices.Equal(a.paths, b.paths) && a.ignoreMissing == b.ignoreMissing
	case NetRule:
		b, ok := b.(NetRule)
		return ok && a == b
	case QuietNetRule:
		b, ok := b.(QuietNetRule)
		return ok && slices.Equal(a.ports, b.ports)
	case *compositeRule:
		b, ok := b.(*compositeRule)
		if !ok || len(a.rules) != len(b.rules) {
			return false
		}
		for i := range a.rules {
			if !rulesEqual(a.rules[i], b.rules[i]) {
				return false
			}
		}
		return true
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
			cfg:          Config{HandledAccessFS: 0b1111},
			rules:        []Rule{PathAccess(0b111111, "foo")},
			supportedABI: 1,
			wantCfg:      Config{HandledAccessFS: 0b1111},
			wantRules:    []Rule{PathAccess(0b1111, "foo")},
		},
		{
			name:         "RestrictPathAccessToHandled",
			cfg:          Config{HandledAccessFS: 0b1},
			rules:        []Rule{PathAccess(0b11, "foo")},
			supportedABI: 1,
			wantCfg:      Config{HandledAccessFS: 0b1},
			wantRules:    []Rule{PathAccess(0b1, "foo")},
		},
		{
			name:         "DowngradeToEmptyOnV0",
			cfg:          Config{HandledAccessFS: 0b1},
			rules:        []Rule{PathAccess(0b11, "foo")},
			supportedABI: 0,
			wantCfg:      Config{},
			wantRules:    []Rule{PathAccess(0, "foo")},
		},
		{
			name:         "ReferSupportedOnV2",
			cfg:          Config{HandledAccessFS: ll.AccessFSRefer | ll.AccessFSReadFile},
			rules:        []Rule{PathAccess(ll.AccessFSRefer|ll.AccessFSReadFile, "foo")},
			supportedABI: 2,
			wantCfg:      Config{HandledAccessFS: ll.AccessFSRefer | ll.AccessFSReadFile},
			wantRules:    []Rule{PathAccess(ll.AccessFSRefer|ll.AccessFSReadFile, "foo")},
		},
		{
			name:         "ReferNotSupportedOnV1FallsBackToV0",
			cfg:          Config{HandledAccessFS: ll.AccessFSRefer | ll.AccessFSReadFile},
			rules:        []Rule{PathAccess(ll.AccessFSRefer|ll.AccessFSReadFile, "foo")},
			supportedABI: 1,
			wantCfg:      v0,
			wantRules:    nil,
		},
		// Network downgrade
		{
			name: "NetworkDowngradeRemovesNet",
			cfg: Config{
				HandledAccessFS:  ll.AccessFSWriteFile,
				HandledAccessNet: ll.AccessNetConnectTCP,
			},
			rules:        []Rule{ConnectTCP(53)},
			supportedABI: 3,
			wantCfg:      Config{HandledAccessFS: ll.AccessFSWriteFile},
			wantRules:    []Rule{NetRule{access: 0, port: 53}},
		},
		// Scoped downgrade
		{
			name:         "ScopedDowngrade",
			cfg:          Config{Scoped: ll.ScopeAbstractUnixSocket},
			supportedABI: 5,
			wantCfg:      Config{},
			wantRules:    nil,
		},
		// Flags downgrade
		{
			name:         "FlagsDowngrade",
			cfg:          Config{Scoped: ll.ScopeAbstractUnixSocket, flags: ll.FlagRestrictSelfLogNewExecOn},
			supportedABI: 6,
			wantCfg:      Config{Scoped: ll.ScopeAbstractUnixSocket},
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
				HandledAccessFS:  (1 << 16) - 1,
				HandledAccessNet: (1 << 2) - 1,
				Scoped:           (1 << 2) - 1,
				flags:            (1 << 3) - 1,
			},
			rules:        []Rule{PathAccess(ll.AccessFSReadFile, "foo"), ConnectTCP(80)},
			supportedABI: 4,
			wantCfg: Config{
				HandledAccessFS:  (1 << 15) - 1,
				HandledAccessNet: (1 << 2) - 1,
			},
			wantRules: []Rule{
				PathAccess(ll.AccessFSReadFile, "foo"),
				ConnectTCP(80),
			},
		},
		{
			name: "AllFieldsDowngradeToV6DropsFlags",
			cfg: Config{
				HandledAccessFS:  ll.AccessFSReadFile,
				HandledAccessNet: ll.AccessNetConnectTCP,
				Scoped:           ll.ScopeAbstractUnixSocket,
				flags:            ll.FlagRestrictSelfLogNewExecOn,
			},
			rules:        []Rule{PathAccess(ll.AccessFSReadFile, "foo")},
			supportedABI: 6,
			wantCfg: Config{
				HandledAccessFS:  ll.AccessFSReadFile,
				HandledAccessNet: ll.AccessNetConnectTCP,
				Scoped:           ll.ScopeAbstractUnixSocket,
			},
			wantRules: []Rule{PathAccess(ll.AccessFSReadFile, "foo")},
		},
		// Refer in rule but not in config on V2+ kernel
		// The refer check looks at the downgraded config, not the ABI.
		// If the config doesn't handle refer, the rule triggers v0 fallback
		// even on a V2+ kernel.
		{
			name:         "ReferInRuleButNotInConfigOnV2FallsBackToV0",
			cfg:          Config{HandledAccessFS: ll.AccessFSReadFile},
			rules:        []Rule{PathAccess(ll.AccessFSRefer|ll.AccessFSReadFile, "foo")},
			supportedABI: 2,
			wantCfg:      v0,
			wantRules:    nil,
		},
		// Empty rules list
		{
			name:         "EmptyRules",
			cfg:          Config{HandledAccessFS: ll.AccessFSReadFile},
			supportedABI: 1,
			wantCfg:      Config{HandledAccessFS: ll.AccessFSReadFile},
			wantRules:    []Rule{},
		},
		// BindTCP rule downgrade
		{
			name: "BindTCPDowngrade",
			cfg: Config{
				HandledAccessFS:  ll.AccessFSReadFile,
				HandledAccessNet: ll.AccessNetBindTCP,
			},
			rules:        []Rule{BindTCP(8080)},
			supportedABI: 3,
			wantCfg:      Config{HandledAccessFS: ll.AccessFSReadFile},
			wantRules:    []Rule{NetRule{access: 0, port: 8080}},
		},
		// V10→V9 boundary: UDP access rights stripped
		{
			name: "UDPStrippedOnV9",
			cfg: Config{
				HandledAccessNet: ll.AccessNetBindTCP | ll.AccessNetBindUDP | ll.AccessNetConnectSendUDP,
			},
			rules:        []Rule{BindTCP(8080), BindUDP(0), ConnectSendUDP(53)},
			supportedABI: 9,
			wantCfg:      Config{HandledAccessNet: ll.AccessNetBindTCP},
			wantRules: []Rule{
				BindTCP(8080),
				NetRule{access: 0, port: 0},
				NetRule{access: 0, port: 53},
			},
		},
		{
			name: "UDPKeptOnV10",
			cfg: Config{
				HandledAccessNet: ll.AccessNetBindUDP | ll.AccessNetConnectSendUDP,
			},
			rules:        []Rule{BindUDP(0), ConnectSendUDP(53)},
			supportedABI: 10,
			wantCfg:      Config{HandledAccessNet: ll.AccessNetBindUDP | ll.AccessNetConnectSendUDP},
			wantRules:    []Rule{BindUDP(0), ConnectSendUDP(53)},
		},
		// V3→V2 boundary: truncate stripped
		{
			name:         "TruncateStrippedOnV2",
			cfg:          Config{HandledAccessFS: ll.AccessFSTruncate | ll.AccessFSReadFile},
			rules:        []Rule{PathAccess(ll.AccessFSTruncate|ll.AccessFSReadFile, "foo")},
			supportedABI: 2,
			wantCfg:      Config{HandledAccessFS: ll.AccessFSReadFile},
			wantRules:    []Rule{PathAccess(ll.AccessFSReadFile, "foo")},
		},
		// V5→V4 boundary: IoctlDev stripped
		{
			name:         "IoctlDevStrippedOnV4",
			cfg:          Config{HandledAccessFS: ll.AccessFSIoctlDev | ll.AccessFSReadFile},
			rules:        []Rule{PathAccess(ll.AccessFSIoctlDev|ll.AccessFSReadFile, "foo")},
			supportedABI: 4,
			wantCfg:      Config{HandledAccessFS: ll.AccessFSReadFile},
			wantRules:    []Rule{PathAccess(ll.AccessFSReadFile, "foo")},
		},
		{
			name: "FSAndNetAndScopeDowngradeToV5DropsScope",
			cfg: Config{
				HandledAccessFS:  ll.AccessFSReadFile | ll.AccessFSIoctlDev,
				HandledAccessNet: ll.AccessNetBindTCP,
				Scoped:           ll.ScopeSignal,
			},
			supportedABI: 5,
			wantCfg: Config{
				HandledAccessFS:  ll.AccessFSReadFile | ll.AccessFSIoctlDev,
				HandledAccessNet: ll.AccessNetBindTCP,
			},
			wantRules: nil,
		},
		// Composite rule scenarios
		{
			name: "CompositeDowngradeSucceeds",
			cfg: Config{
				HandledAccessFS:  ll.AccessFSReadFile | ll.AccessFSWriteFile,
				HandledAccessNet: ll.AccessNetConnectTCP,
			},
			rules: []Rule{
				CompositeRule(
					PathAccess(ll.AccessFSReadFile, "foo"),
					ConnectTCP(80),
				),
			},
			supportedABI: 4,
			wantCfg: Config{
				HandledAccessFS:  ll.AccessFSReadFile | ll.AccessFSWriteFile,
				HandledAccessNet: ll.AccessNetConnectTCP,
			},
			wantRules: []Rule{
				CompositeRule(
					PathAccess(ll.AccessFSReadFile, "foo"),
					ConnectTCP(80),
				),
			},
		},
		{
			name: "CompositeSubRuleDowngraded",
			cfg: Config{
				HandledAccessFS:  ll.AccessFSReadFile,
				HandledAccessNet: ll.AccessNetConnectTCP,
			},
			rules: []Rule{
				CompositeRule(
					PathAccess(ll.AccessFSReadFile|ll.AccessFSWriteFile, "foo"),
					ConnectTCP(80),
				),
			},
			supportedABI: 4,
			wantCfg: Config{
				HandledAccessFS:  ll.AccessFSReadFile,
				HandledAccessNet: ll.AccessNetConnectTCP,
			},
			wantRules: []Rule{
				CompositeRule(
					PathAccess(ll.AccessFSReadFile, "foo"),
					ConnectTCP(80),
				),
			},
		},
		// Quieting scenarios
		{
			name:         "QuietingIsKeptOnV10",
			cfg:          Config{HandledAccessFS: ll.AccessFSReadFile, quietAll: true},
			rules:        []Rule{QuietPaths("foo")},
			supportedABI: 10,
			wantCfg:      Config{HandledAccessFS: ll.AccessFSReadFile, quietAll: true},
			wantRules:    []Rule{QuietPaths("foo")},
		},
		{
			// The rule itself stays as it is: It turns into a
			// no-op when it is added to the ruleset, because
			// the downgraded Config has no quiet access rights.
			name:         "QuietingIsDroppedFromConfigBelowV10",
			cfg:          Config{HandledAccessFS: ll.AccessFSReadFile, quietAll: true},
			rules:        []Rule{QuietPaths("foo")},
			supportedABI: 9,
			wantCfg:      Config{HandledAccessFS: ll.AccessFSReadFile},
			wantRules:    []Rule{QuietPaths("foo")},
		},
		{
			name:         "QuietPortsAreKeptOnV10",
			cfg:          Config{HandledAccessNet: ll.AccessNetConnectTCP, quietAll: true},
			rules:        []Rule{QuietPorts(53)},
			supportedABI: 10,
			wantCfg:      Config{HandledAccessNet: ll.AccessNetConnectTCP, quietAll: true},
			wantRules:    []Rule{QuietPorts(53)},
		},
		{
			name:         "QuietPortsAreDroppedFromConfigBelowV10",
			cfg:          Config{HandledAccessNet: ll.AccessNetConnectTCP, quietAll: true},
			rules:        []Rule{QuietPorts(53)},
			supportedABI: 9,
			wantCfg:      Config{HandledAccessNet: ll.AccessNetConnectTCP},
			wantRules:    []Rule{QuietPorts(53)},
		},
		{
			name: "CompositeWithReferFallsBackToV0",
			cfg:  Config{HandledAccessFS: ll.AccessFSReadFile},
			rules: []Rule{
				CompositeRule(
					PathAccess(ll.AccessFSReadFile, "ok"),
					PathAccess(ll.AccessFSRefer|ll.AccessFSReadFile, "bad"),
				),
			},
			supportedABI: 2,
			wantCfg:      v0,
			wantRules:    nil,
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
