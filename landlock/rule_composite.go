package landlock

import "fmt"

type RuleGroup struct {
	rules []Rule
}

// GroupRules groups the given rules into a single Rule value.
// The result behaves the same in a Landlock restriction call
// as listing all of the individual rules separately.
func GroupRules(rules ...Rule) RuleGroup {
	return RuleGroup{rules: rules}
}

func (g RuleGroup) compatibleWithConfig(c Config) bool {
	for _, r := range g.rules {
		if !r.compatibleWithConfig(c) {
			return false
		}
	}
	return true
}

func (g RuleGroup) downgrade(c Config) (out Rule, ok bool) {
	rs := make([]Rule, 0, len(g.rules))
	for _, r := range g.rules {
		r, ok := r.downgrade(c)
		if !ok {
			return GroupRules(), false
		}
		rs = append(rs, r)
	}
	return GroupRules(rs...), true
}

func (g RuleGroup) addToRuleset(rulesetFD int, c Config) error {
	for _, r := range g.rules {
		err := r.addToRuleset(rulesetFD, c)
		if err != nil {
			return err
		}
	}
	return nil
}

func (g RuleGroup) String() string {
	return fmt.Sprintf("rules: %v", g.rules)
}
