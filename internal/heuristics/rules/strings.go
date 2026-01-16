package rules

import (
	"context"
	"regexp"
	"strings"

	"github.com/maxime/lcre/internal/model"
)

// Regex patterns for network IOCs
var (
	urlPattern    = regexp.MustCompile(`https?://[^\s"'<>]+`)
	ipPattern     = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
	domainPattern = regexp.MustCompile(`\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b`)
)

// Suspicious paths
var suspiciousPaths = []string{
	// Linux
	"/proc/self",
	"/proc/",
	"/etc/passwd",
	"/etc/shadow",
	"/tmp/",
	"/var/tmp/",

	// Windows
	"\\AppData\\Local\\Temp",
	"\\AppData\\Roaming",
	"\\Windows\\Temp",
	"CurrentVersion\\Run",
	"CurrentVersion\\RunOnce",
	"Services\\",
	"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",

	// macOS
	"/Library/LaunchAgents",
	"/Library/LaunchDaemons",
	"~/Library/LaunchAgents",
}

// NetworkIOCsRule detects network indicators in strings
type NetworkIOCsRule struct{}

func NewNetworkIOCsRule() *NetworkIOCsRule { return &NetworkIOCsRule{} }

func (r *NetworkIOCsRule) ID() string              { return "STRING001" }
func (r *NetworkIOCsRule) Name() string            { return "Network IOCs" }
func (r *NetworkIOCsRule) Category() model.Category { return model.CategoryNetwork }
func (r *NetworkIOCsRule) Severity() model.Severity { return model.SeverityMedium }

func (r *NetworkIOCsRule) Description() string {
	return "Binary contains URLs, IPs, or domain names in strings"
}

func (r *NetworkIOCsRule) Evaluate(ctx context.Context, result *model.AnalysisResult) (bool, []string) {
	var evidence []string
	seen := make(map[string]bool)

	for _, str := range result.Strings {
		// Check for URLs
		if urls := urlPattern.FindAllString(str.Value, -1); len(urls) > 0 {
			for _, url := range urls {
				if !seen[url] && !isWhitelistedURL(url) {
					seen[url] = true
					evidence = append(evidence, "URL: "+url)
				}
			}
		}

		// Check for IPs
		if ips := ipPattern.FindAllString(str.Value, -1); len(ips) > 0 {
			for _, ip := range ips {
				if !seen[ip] && !isWhitelistedIP(ip) {
					seen[ip] = true
					evidence = append(evidence, "IP: "+ip)
				}
			}
		}
	}

	// Limit evidence to avoid overwhelming output
	if len(evidence) > 20 {
		evidence = evidence[:20]
		evidence = append(evidence, "... and more")
	}

	return len(evidence) > 0, evidence
}

// SuspiciousPathsRule detects suspicious file paths in strings
type SuspiciousPathsRule struct{}

func NewSuspiciousPathsRule() *SuspiciousPathsRule { return &SuspiciousPathsRule{} }

func (r *SuspiciousPathsRule) ID() string              { return "STRING002" }
func (r *SuspiciousPathsRule) Name() string            { return "Suspicious Paths" }
func (r *SuspiciousPathsRule) Category() model.Category { return model.CategoryEvasion }
func (r *SuspiciousPathsRule) Severity() model.Severity { return model.SeverityLow }

func (r *SuspiciousPathsRule) Description() string {
	return "Binary contains references to suspicious file system paths"
}

func (r *SuspiciousPathsRule) Evaluate(ctx context.Context, result *model.AnalysisResult) (bool, []string) {
	var evidence []string
	seen := make(map[string]bool)

	for _, str := range result.Strings {
		for _, path := range suspiciousPaths {
			if strings.Contains(str.Value, path) {
				if !seen[path] {
					seen[path] = true
					evidence = append(evidence, "Path reference: "+path)
				}
			}
		}
	}

	return len(evidence) > 0, evidence
}

// isWhitelistedURL checks if a URL is a known safe URL
func isWhitelistedURL(url string) bool {
	whitelisted := []string{
		"microsoft.com",
		"windows.com",
		"apple.com",
		"google.com",
		"schema.org",
		"w3.org",
	}

	for _, safe := range whitelisted {
		if strings.Contains(url, safe) {
			return true
		}
	}
	return false
}

// isWhitelistedIP checks if an IP is a known safe IP
func isWhitelistedIP(ip string) bool {
	// Skip common non-threatening IPs
	whitelisted := []string{
		"0.0.0.0",
		"127.0.0.1",
		"255.255.255.255",
		"192.168.", // Local network
		"10.",      // Local network
		"172.16.",  // Local network
	}

	for _, safe := range whitelisted {
		if strings.HasPrefix(ip, safe) {
			return true
		}
	}
	return false
}
