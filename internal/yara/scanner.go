package yara

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Match represents a YARA rule match
type Match struct {
	Rule        string   `json:"rule"`
	Namespace   string   `json:"namespace,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Description string   `json:"description,omitempty"`
	Strings     []string `json:"strings,omitempty"`
}

// ScanResult contains YARA scan results
type ScanResult struct {
	Matches   []Match `json:"matches"`
	Available bool    `json:"yara_available"`
	Error     string  `json:"error,omitempty"`
}

// Scanner provides YARA scanning capabilities
type Scanner struct {
	yaraPath  string
	rulesDir  string
	rulesFile string
}

// NewScanner creates a new YARA scanner
func NewScanner() *Scanner {
	return &Scanner{}
}

// SetRulesDir sets the directory containing YARA rules
func (s *Scanner) SetRulesDir(dir string) {
	s.rulesDir = dir
}

// SetRulesFile sets a specific rules file to use
func (s *Scanner) SetRulesFile(file string) {
	s.rulesFile = file
}

// Available checks if the yara command-line tool is available
func (s *Scanner) Available() bool {
	path, err := exec.LookPath("yara")
	if err != nil {
		return false
	}
	s.yaraPath = path
	return true
}

// Scan scans a file using YARA rules
func (s *Scanner) Scan(ctx context.Context, filePath string) (*ScanResult, error) {
	result := &ScanResult{
		Available: s.Available(),
		Matches:   []Match{},
	}

	if !result.Available {
		result.Error = "yara command not found in PATH"
		return result, nil
	}

	// Determine rules to use
	rulesArg := s.rulesFile
	if rulesArg == "" && s.rulesDir != "" {
		// If directory specified, find all .yar files
		rulesArg = s.rulesDir
	}

	if rulesArg == "" {
		// Try to use embedded rules
		embeddedRules := GetEmbeddedRulesPath()
		if embeddedRules != "" {
			rulesArg = embeddedRules
		} else {
			result.Error = "no YARA rules specified and no embedded rules available"
			return result, nil
		}
	}

	// Build yara command
	args := []string{
		"-s",           // Print matching strings
		"-m",           // Print metadata
		rulesArg,
		filePath,
	}

	cmd := exec.CommandContext(ctx, s.yaraPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// yara returns non-zero if no matches found, which is fine
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 {
				// No matches - this is not an error
				return result, nil
			}
		}
		// Check stderr for actual errors
		if stderr.Len() > 0 {
			result.Error = strings.TrimSpace(stderr.String())
			return result, nil
		}
	}

	// Parse output
	result.Matches = parseYaraOutput(stdout.String())
	return result, nil
}

// ScanWithRules scans a file using provided rule content directly
func (s *Scanner) ScanWithRules(ctx context.Context, filePath string, rules string) (*ScanResult, error) {
	result := &ScanResult{
		Available: s.Available(),
		Matches:   []Match{},
	}

	if !result.Available {
		result.Error = "yara command not found in PATH"
		return result, nil
	}

	// Create a temporary file for rules
	tmpFile := filepath.Join("/tmp", fmt.Sprintf("lcre_yara_%d.yar", ctx.Value("scan_id")))
	// Note: In production, use os.CreateTemp

	// Build yara command with stdin rules
	args := []string{
		"-s",           // Print matching strings
		"-m",           // Print metadata
		"/dev/stdin",   // Read rules from stdin
		filePath,
	}

	cmd := exec.CommandContext(ctx, s.yaraPath, args...)
	cmd.Stdin = strings.NewReader(rules)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	_ = tmpFile // unused for now

	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 {
				return result, nil
			}
		}
		if stderr.Len() > 0 {
			result.Error = strings.TrimSpace(stderr.String())
			return result, nil
		}
	}

	result.Matches = parseYaraOutput(stdout.String())
	return result, nil
}

// parseYaraOutput parses YARA command output into Match structures
func parseYaraOutput(output string) []Match {
	var matches []Match
	currentMatch := (*Match)(nil)

	// YARA output format:
	// RuleName [tags] file_path
	// 0x offset:$string_id: matched_data
	rulePattern := regexp.MustCompile(`^(\w+)\s*(?:\[(.*?)\])?\s+(.+)$`)
	stringPattern := regexp.MustCompile(`^0x[0-9a-fA-F]+:\$(\w+):\s*(.*)$`)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()

		// Check if this is a rule match line
		if ruleMatch := rulePattern.FindStringSubmatch(line); ruleMatch != nil {
			if currentMatch != nil {
				matches = append(matches, *currentMatch)
			}
			currentMatch = &Match{
				Rule: ruleMatch[1],
			}
			if ruleMatch[2] != "" {
				currentMatch.Tags = strings.Split(ruleMatch[2], ",")
				for i, tag := range currentMatch.Tags {
					currentMatch.Tags[i] = strings.TrimSpace(tag)
				}
			}
		} else if currentMatch != nil {
			// Check if this is a string match line
			if stringMatch := stringPattern.FindStringSubmatch(line); stringMatch != nil {
				currentMatch.Strings = append(currentMatch.Strings, fmt.Sprintf("$%s: %s", stringMatch[1], stringMatch[2]))
			}
		}
	}

	if currentMatch != nil {
		matches = append(matches, *currentMatch)
	}

	return matches
}

// GetEmbeddedRulesPath returns the path to embedded rules if available
// In a real implementation, this would write embedded rules to a temp file
func GetEmbeddedRulesPath() string {
	// For now, return empty - embedded rules will be handled differently
	return ""
}
