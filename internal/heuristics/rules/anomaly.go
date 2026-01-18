package rules

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/maxime/lcre/internal/model"
)

// PE section characteristics for anomaly detection
const (
	IMAGE_SCN_MEM_EXECUTE = 0x20000000
	IMAGE_SCN_MEM_READ    = 0x40000000
	IMAGE_SCN_MEM_WRITE   = 0x80000000
)

// EntryPointAnomalyRule detects entry points outside expected sections
type EntryPointAnomalyRule struct{}

func NewEntryPointAnomalyRule() *EntryPointAnomalyRule { return &EntryPointAnomalyRule{} }

func (r *EntryPointAnomalyRule) ID() string              { return "ANOMALY001" }
func (r *EntryPointAnomalyRule) Name() string            { return "Entry Point Anomaly" }
func (r *EntryPointAnomalyRule) Category() model.Category { return model.CategoryAnomaly }
func (r *EntryPointAnomalyRule) Severity() model.Severity { return model.SeverityMedium }

func (r *EntryPointAnomalyRule) Description() string {
	return "Binary has entry point outside standard code sections"
}

func (r *EntryPointAnomalyRule) Evaluate(ctx context.Context, result *model.AnalysisResult) (bool, []string) {
	if result.Metadata.Format != model.FormatPE || result.PEInfo == nil {
		return false, nil
	}

	// Standard code section names
	standardCodeSections := map[string]bool{
		".text":   true,
		"CODE":    true,
		".code":   true,
		"__text":  true,
	}

	epSection := result.PEInfo.EntryPointSection
	if epSection == "" {
		return true, []string{"Entry point is not within any section (possibly in headers)"}
	}

	// Check if entry point is in a standard section
	if !standardCodeSections[epSection] {
		// Check if it's a known packer section (those are handled by packer rules)
		packerSections := map[string]bool{
			"UPX0": true, "UPX1": true, ".vmp0": true, ".vmp1": true,
			".themida": true, ".aspack": true, ".petite": true,
		}
		if packerSections[epSection] {
			return false, nil // Let packer rules handle this
		}

		return true, []string{fmt.Sprintf("Entry point in unusual section: %s (expected .text or CODE)", epSection)}
	}

	return false, nil
}

// RWXSectionRule detects sections with Read-Write-Execute permissions
type RWXSectionRule struct{}

func NewRWXSectionRule() *RWXSectionRule { return &RWXSectionRule{} }

func (r *RWXSectionRule) ID() string              { return "ANOMALY002" }
func (r *RWXSectionRule) Name() string            { return "RWX Section" }
func (r *RWXSectionRule) Category() model.Category { return model.CategoryAnomaly }
func (r *RWXSectionRule) Severity() model.Severity { return model.SeverityHigh }

func (r *RWXSectionRule) Description() string {
	return "Binary has section with Read-Write-Execute permissions (common in packed/shellcode)"
}

func (r *RWXSectionRule) Evaluate(ctx context.Context, result *model.AnalysisResult) (bool, []string) {
	if result.Metadata.Format != model.FormatPE {
		return false, nil
	}

	var evidence []string
	for _, sec := range result.Sections {
		// Check if section has RWX permissions
		isRWX := (sec.Characteristics&IMAGE_SCN_MEM_READ != 0) &&
			(sec.Characteristics&IMAGE_SCN_MEM_WRITE != 0) &&
			(sec.Characteristics&IMAGE_SCN_MEM_EXECUTE != 0)

		if isRWX {
			evidence = append(evidence, fmt.Sprintf("Section %s has RWX permissions (0x%08X)", sec.Name, sec.Characteristics))
		}
	}

	return len(evidence) > 0, evidence
}

// TimestampAnomalyRule detects suspicious PE timestamps
type TimestampAnomalyRule struct{}

func NewTimestampAnomalyRule() *TimestampAnomalyRule { return &TimestampAnomalyRule{} }

func (r *TimestampAnomalyRule) ID() string              { return "ANOMALY003" }
func (r *TimestampAnomalyRule) Name() string            { return "Timestamp Anomaly" }
func (r *TimestampAnomalyRule) Category() model.Category { return model.CategoryAnomaly }
func (r *TimestampAnomalyRule) Severity() model.Severity { return model.SeverityLow }

func (r *TimestampAnomalyRule) Description() string {
	return "Binary has suspicious compilation timestamp"
}

func (r *TimestampAnomalyRule) Evaluate(ctx context.Context, result *model.AnalysisResult) (bool, []string) {
	if result.Metadata.Format != model.FormatPE {
		return false, nil
	}

	ts := result.Metadata.Timestamp
	var evidence []string

	// Check for null timestamp
	if ts == 0 {
		evidence = append(evidence, "Timestamp is null (possibly stripped)")
	}

	// Check for future timestamp
	if ts > time.Now().Unix() {
		evidence = append(evidence, fmt.Sprintf("Timestamp is in the future: %s", time.Unix(ts, 0).Format(time.RFC3339)))
	}

	// Check for very old timestamp (before Windows 95)
	if ts > 0 && ts < 807926400 { // July 1, 1995
		evidence = append(evidence, fmt.Sprintf("Timestamp is suspiciously old: %s", time.Unix(ts, 0).Format(time.RFC3339)))
	}

	// Check for well-known fake timestamps used by malware
	fakeTimestamps := map[int64]string{
		0x2A425E19: "Delphi default timestamp (borland)",
		0x5B02A252: "Common malware timestamp",
	}
	if name, ok := fakeTimestamps[ts]; ok {
		evidence = append(evidence, fmt.Sprintf("Known fake timestamp: %s", name))
	}

	return len(evidence) > 0, evidence
}

// SectionCountAnomalyRule detects unusual number of sections
type SectionCountAnomalyRule struct{}

func NewSectionCountAnomalyRule() *SectionCountAnomalyRule { return &SectionCountAnomalyRule{} }

func (r *SectionCountAnomalyRule) ID() string              { return "ANOMALY004" }
func (r *SectionCountAnomalyRule) Name() string            { return "Section Count Anomaly" }
func (r *SectionCountAnomalyRule) Category() model.Category { return model.CategoryAnomaly }
func (r *SectionCountAnomalyRule) Severity() model.Severity { return model.SeverityLow }

func (r *SectionCountAnomalyRule) Description() string {
	return "Binary has unusual number of sections"
}

func (r *SectionCountAnomalyRule) Evaluate(ctx context.Context, result *model.AnalysisResult) (bool, []string) {
	if result.Metadata.Format != model.FormatPE {
		return false, nil
	}

	count := len(result.Sections)
	var evidence []string

	// Very few sections (1) or too many (>15) is unusual
	if count == 1 {
		evidence = append(evidence, "Binary has only 1 section (unusual)")
	} else if count > 15 {
		evidence = append(evidence, fmt.Sprintf("Binary has %d sections (unusually high)", count))
	}

	return len(evidence) > 0, evidence
}

// SuspiciousStringsRule detects ransomware/malware specific strings
type SuspiciousStringsRule struct{}

func NewSuspiciousStringsRule() *SuspiciousStringsRule { return &SuspiciousStringsRule{} }

func (r *SuspiciousStringsRule) ID() string              { return "STRING003" }
func (r *SuspiciousStringsRule) Name() string            { return "Suspicious Strings" }
func (r *SuspiciousStringsRule) Category() model.Category { return model.CategoryAnomaly }
func (r *SuspiciousStringsRule) Severity() model.Severity { return model.SeverityHigh }

func (r *SuspiciousStringsRule) Description() string {
	return "Binary contains strings commonly found in ransomware or malware"
}

// Suspicious string patterns
var ransomwareStrings = []string{
	"your files have been encrypted",
	"your important files",
	"all your files",
	"bitcoin",
	"btc wallet",
	"ransom",
	"decrypt",
	"pay to",
	"restore your files",
	"locked",
	".onion",
	"tor browser",
	"private key",
	"encryption key",
}

var malwareStrings = []string{
	"keylogger",
	"screenshot",
	"webcam",
	"clipboard",
	"password",
	"credential",
	"steal",
	"inject",
	"hook",
	"shell",
	"payload",
	"dropper",
	"loader",
	"c2",
	"c&c",
	"command and control",
	"botnet",
}

func (r *SuspiciousStringsRule) Evaluate(ctx context.Context, result *model.AnalysisResult) (bool, []string) {
	var evidence []string
	foundRansomware := make(map[string]bool)
	foundMalware := make(map[string]bool)

	for _, s := range result.Strings {
		strLower := strings.ToLower(s.Value)

		// Check ransomware strings
		for _, pattern := range ransomwareStrings {
			if strings.Contains(strLower, pattern) && !foundRansomware[pattern] {
				foundRansomware[pattern] = true
				evidence = append(evidence, fmt.Sprintf("Ransomware indicator: %q found in string", pattern))
			}
		}

		// Check malware strings
		for _, pattern := range malwareStrings {
			if strings.Contains(strLower, pattern) && !foundMalware[pattern] {
				foundMalware[pattern] = true
				evidence = append(evidence, fmt.Sprintf("Malware indicator: %q found in string", pattern))
			}
		}
	}

	// Only trigger if we have multiple indicators
	if len(foundRansomware) >= 2 || len(foundMalware) >= 2 {
		return true, evidence
	}

	return false, nil
}

// MetadataMismatchRule detects mismatches between claimed and actual binary attributes
type MetadataMismatchRule struct{}

func NewMetadataMismatchRule() *MetadataMismatchRule { return &MetadataMismatchRule{} }

func (r *MetadataMismatchRule) ID() string              { return "ANOMALY005" }
func (r *MetadataMismatchRule) Name() string            { return "Metadata Mismatch" }
func (r *MetadataMismatchRule) Category() model.Category { return model.CategoryEvasion }
func (r *MetadataMismatchRule) Severity() model.Severity { return model.SeverityMedium }

func (r *MetadataMismatchRule) Description() string {
	return "Binary metadata suggests masquerading as legitimate software"
}

// Known legitimate software names that are commonly impersonated
var impersonatedSoftware = []string{
	"microsoft",
	"windows",
	"adobe",
	"google",
	"chrome",
	"firefox",
	"java",
	"oracle",
	"vmware",
	"nvidia",
	"intel",
	"ibm",
	"apple",
	"cisco",
	"symantec",
	"mcafee",
	"kaspersky",
	"avast",
	"avg",
}

func (r *MetadataMismatchRule) Evaluate(ctx context.Context, result *model.AnalysisResult) (bool, []string) {
	var evidence []string
	claimedVendor := ""

	// Look for version info strings that claim to be from major vendors
	for _, s := range result.Strings {
		strLower := strings.ToLower(s.Value)
		for _, vendor := range impersonatedSoftware {
			if strings.Contains(strLower, vendor+" corporation") ||
				strings.Contains(strLower, vendor+" inc") ||
				strings.Contains(strLower, vendor+", inc") ||
				strings.Contains(strLower, "copyright "+vendor) {
				claimedVendor = vendor
				break
			}
		}
		if claimedVendor != "" {
			break
		}
	}

	// If binary claims to be from a major vendor but is unsigned, flag it
	if claimedVendor != "" && !result.Metadata.IsSigned {
		evidence = append(evidence, fmt.Sprintf("Claims to be from %s but binary is unsigned", claimedVendor))
	}

	// Check for version strings claiming to be system files
	systemFileIndicators := []string{
		"system32",
		"svchost",
		"csrss",
		"lsass",
		"services",
		"dllhost",
		"conhost",
	}

	for _, s := range result.Strings {
		strLower := strings.ToLower(s.Value)
		for _, indicator := range systemFileIndicators {
			if strings.Contains(strLower, indicator) && strings.Contains(strLower, "microsoft") {
				// This is suspicious if the binary has unusual characteristics
				if len(result.Imports) < 10 {
					evidence = append(evidence, fmt.Sprintf("Claims system file association (%s) but has minimal imports", indicator))
				}
			}
		}
	}

	return len(evidence) > 0, evidence
}
