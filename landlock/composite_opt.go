package landlock

type compositeRule struct {
	rules []Rule
}

func (c *compositeRule) compatibleWithConfig(cfg Config) bool {
	for _, r := range c.rules {
		if !r.compatibleWithConfig(cfg) {
			return false
		}
	}
	return true
}

func (c *compositeRule) downgrade(cfg Config) (out Rule, ok bool) {
	cr := new(compositeRule)
	for _, r := range c.rules {
		r, ok := r.downgrade(cfg)
		if !ok {
			return nil, false
		}
		cr.rules = append(cr.rules, r)
	}
	return cr, true
}

func (c *compositeRule) addToRuleset(rulesetFD int, cfg Config) error {
	for _, r := range c.rules {
		err := r.addToRuleset(rulesetFD, cfg)
		if err != nil {
			return err
		}
	}
	return nil
}

// CompositeRule returns a rule composed of sub-rules.
//
// A composite rule passed to [Restrict] behaves the same as passing
// all sub-rules individually.  Composite rules are not strictly
// necessary in Go-Landlock, but useful for building libraries of
// re-usable Landlock rules.
func CompositeRule(rules ...Rule) Rule {
	return &compositeRule{rules: rules}
}
