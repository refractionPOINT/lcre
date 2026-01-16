package heuristics

import "github.com/maxime/lcre/internal/heuristics/rules"

// DefaultEngine is the global engine with all default rules
var DefaultEngine = NewEngine()

// RegisterDefaultRules registers all built-in rules with the default engine
func RegisterDefaultRules() {
	// Packer detection rules
	DefaultEngine.AddRule(rules.NewPackerSectionsRule())
	DefaultEngine.AddRule(rules.NewHighEntropyRule())

	// Suspicious imports rules
	DefaultEngine.AddRule(rules.NewProcessInjectionRule())
	DefaultEngine.AddRule(rules.NewAntiDebugRule())
	DefaultEngine.AddRule(rules.NewPersistenceRule())
	DefaultEngine.AddRule(rules.NewCryptoRule())

	// String-based rules
	DefaultEngine.AddRule(rules.NewNetworkIOCsRule())
	DefaultEngine.AddRule(rules.NewSuspiciousPathsRule())

	// Section anomaly rules
	DefaultEngine.AddRule(rules.NewTinyTextRule())
}

func init() {
	RegisterDefaultRules()
}
