package landlock

type restrictOpt interface {
	// compatibleWithConfig is true if the given option is
	// compatible with the configuration c.
	compatibleWithConfig(c Config) bool

	// downgrade returns downgraded option for "best effort" mode,
	// under the assumption that the kernel only supports c.
	//
	// It establishes that:
	//
	//   - opt.accessFS ⊆ handledAccessFS
	//
	// If the option is unsupportable under the given Config at
	// all, ok is false. This happens when c represents a Landlock
	// V1 system but the option wants to grant the refer right on
	// a path. "Refer" operations are always forbidden under
	// Landlock V1.
	downgrade(c Config) (out restrictOpt, ok bool)

	// addToRuleset applies the option to the given rulesetFD.
	//
	// This may return errors such as "file not found" depending
	// on the option type.
	addToRuleset(rulesetFD int, c Config) error
}
