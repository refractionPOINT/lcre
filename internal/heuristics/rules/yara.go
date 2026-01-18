package rules

import (
	"context"
	"fmt"

	"github.com/maxime/lcre/internal/model"
	"github.com/maxime/lcre/internal/yara"
)

// YARARule runs YARA signature detection
type YARARule struct {
	scanner   *yara.Scanner
	rulesPath string
}

// NewYARARule creates a new YARA detection rule
func NewYARARule() *YARARule {
	return &YARARule{
		scanner: yara.NewScanner(),
	}
}

// SetRulesPath sets a custom rules path for the YARA scanner
func (r *YARARule) SetRulesPath(path string) {
	r.rulesPath = path
	r.scanner.SetRulesFile(path)
}

func (r *YARARule) ID() string              { return "YARA001" }
func (r *YARARule) Name() string            { return "YARA Signature Match" }
func (r *YARARule) Category() model.Category { return model.CategoryAnomaly }
func (r *YARARule) Severity() model.Severity { return model.SeverityCritical }

func (r *YARARule) Description() string {
	return "Binary matches known malware YARA signatures"
}

func (r *YARARule) Evaluate(ctx context.Context, result *model.AnalysisResult) (bool, []string) {
	if !r.scanner.Available() {
		// YARA not available, skip silently
		return false, nil
	}

	// Write embedded rules if no custom path set
	if r.rulesPath == "" {
		rulesPath, err := yara.WriteEmbeddedRules()
		if err != nil {
			return false, nil
		}
		r.scanner.SetRulesFile(rulesPath)
	}

	// Run YARA scan
	scanResult, err := r.scanner.Scan(ctx, result.Metadata.Path)
	if err != nil {
		return false, nil
	}

	if scanResult.Error != "" || len(scanResult.Matches) == 0 {
		return false, nil
	}

	// Build evidence from matches
	var evidence []string
	for _, match := range scanResult.Matches {
		desc := fmt.Sprintf("YARA rule '%s' matched", match.Rule)
		if len(match.Tags) > 0 {
			desc += fmt.Sprintf(" [tags: %v]", match.Tags)
		}
		evidence = append(evidence, desc)

		// Add string match details (limit to first 3)
		for i, s := range match.Strings {
			if i >= 3 {
				evidence = append(evidence, fmt.Sprintf("  ... and %d more string matches", len(match.Strings)-3))
				break
			}
			evidence = append(evidence, fmt.Sprintf("  - %s", s))
		}
	}

	return true, evidence
}

// YARARuleLight is a lightweight version that works without the yara binary
// by checking for specific patterns in strings that YARA rules would match
type YARARuleLight struct{}

func NewYARARuleLightweight() *YARARuleLight { return &YARARuleLight{} }

func (r *YARARuleLight) ID() string              { return "YARA002" }
func (r *YARARuleLight) Name() string            { return "Malware Family Patterns" }
func (r *YARARuleLight) Category() model.Category { return model.CategoryAnomaly }
func (r *YARARuleLight) Severity() model.Severity { return model.SeverityHigh }

func (r *YARARuleLight) Description() string {
	return "Binary matches patterns associated with known malware families"
}

// Malware family patterns (lightweight detection)
var malwareFamilyPatterns = map[string][]string{
	"Locky": {
		".locky", ".zepto", ".odin", ".thor", ".aesir",
		"_HELP_instructions", "All of your files were protected",
	},
	"Petya": {
		"PETYA", "petya", "GoldenEye", "\\\\.\\PhysicalDrive",
		"Your important files are encrypted", "wowsmith123456",
	},
	"Stuxnet": {
		"b:\\myrtus\\src", "\\driver\\mrxcls", "\\driver\\mrxnet",
		"MRXCLS.SYS", "MRXNET.SYS", "S7OTBXDX", "tasksche.exe",
	},
	"WannaCry": {
		"WanaCrypt0r", "WannaCry", "WANACRY", "WNcry@2ol7",
		"@Please_Read_Me@.txt", ".WNCRY", "MsWinZonesCacheCounterMutexA",
	},
	"Ryuk": {
		"RYUK", "RyukReadMe", ".RYK", "balance of shadow universe",
	},
	"Emotet": {
		"BCryptGenRandom", "BCryptEncrypt",
	},
	"CobaltStrike": {
		"beacon.dll", "ReflectiveLoader", "metsrv", "meterpreter",
	},
}

func (r *YARARuleLight) Evaluate(ctx context.Context, result *model.AnalysisResult) (bool, []string) {
	// Check for string matches against malware family patterns
	familyMatches := make(map[string][]string)

	for _, s := range result.Strings {
		for family, patterns := range malwareFamilyPatterns {
			for _, pattern := range patterns {
				if containsIgnoreCase(s.Value, pattern) {
					familyMatches[family] = append(familyMatches[family], pattern)
				}
			}
		}
	}

	// Also check section names for packer indicators
	packerPatterns := map[string]string{
		"UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX",
		".vmp0": "VMProtect", ".vmp1": "VMProtect",
		".themida": "Themida", ".aspack": "ASPack",
	}

	for _, sec := range result.Sections {
		if packer, ok := packerPatterns[sec.Name]; ok {
			familyMatches[packer] = append(familyMatches[packer], fmt.Sprintf("section: %s", sec.Name))
		}
	}

	// Build evidence - only report if we have multiple matches for a family
	var evidence []string
	for family, matches := range familyMatches {
		if len(matches) >= 2 {
			evidence = append(evidence, fmt.Sprintf("Matches %s malware patterns: %v", family, matches))
		}
	}

	return len(evidence) > 0, evidence
}

func containsIgnoreCase(s, substr string) bool {
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		found := true
		for j := 0; j < len(substr); j++ {
			sc := s[i+j]
			pc := substr[j]
			// Simple case-insensitive comparison for ASCII
			if sc >= 'A' && sc <= 'Z' {
				sc += 32
			}
			if pc >= 'A' && pc <= 'Z' {
				pc += 32
			}
			if sc != pc {
				found = false
				break
			}
		}
		if found {
			return true
		}
	}
	return false
}
