package heuristics

import "github.com/maxime/lcre/internal/heuristics/rules"

// DefaultEngine is the global engine with all default rules
var DefaultEngine = NewEngine()

// RegisterDefaultRules registers all built-in rules with the default engine
func RegisterDefaultRules() {
	// Packer detection rules
	DefaultEngine.AddRule(rules.NewPackerSectionsRule())
	DefaultEngine.AddRule(rules.NewHighEntropyRule())
	DefaultEngine.AddRule(rules.NewMinimalImportsRule())

	// Suspicious imports rules
	DefaultEngine.AddRule(rules.NewProcessInjectionRule())
	DefaultEngine.AddRule(rules.NewAntiDebugRule())
	DefaultEngine.AddRule(rules.NewPersistenceRule())
	DefaultEngine.AddRule(rules.NewCryptoRule())
	DefaultEngine.AddRule(rules.NewDiskAccessRule())

	// String-based rules
	DefaultEngine.AddRule(rules.NewNetworkIOCsRule())
	DefaultEngine.AddRule(rules.NewSuspiciousPathsRule())
	DefaultEngine.AddRule(rules.NewSuspiciousStringsRule())

	// Section/PE anomaly rules
	DefaultEngine.AddRule(rules.NewTinyTextRule())
	DefaultEngine.AddRule(rules.NewEntryPointAnomalyRule())
	DefaultEngine.AddRule(rules.NewRWXSectionRule())
	DefaultEngine.AddRule(rules.NewTimestampAnomalyRule())
	DefaultEngine.AddRule(rules.NewSectionCountAnomalyRule())
	DefaultEngine.AddRule(rules.NewMetadataMismatchRule())

	// YARA-based rules
	DefaultEngine.AddRule(rules.NewYARARule())
	DefaultEngine.AddRule(rules.NewYARARuleLightweight())
}

func init() {
	RegisterDefaultRules()
}
