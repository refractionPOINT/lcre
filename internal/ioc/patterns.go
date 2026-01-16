package ioc

import (
	"net"
	"regexp"
	"strings"
)

// Patterns contains regex patterns for IOC extraction
type Patterns struct {
	url      *regexp.Regexp
	ip       *regexp.Regexp
	domain   *regexp.Regexp
	email    *regexp.Regexp
	winPath  *regexp.Regexp
	unixPath *regexp.Regexp
	registry *regexp.Regexp
}

// NewPatterns creates patterns for IOC extraction
func NewPatterns() *Patterns {
	return &Patterns{
		url: regexp.MustCompile(`https?://[^\s"'<>\x00-\x1f]+`),
		ip: regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
		domain: regexp.MustCompile(`\b([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b`),
		email: regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
		winPath: regexp.MustCompile(`[A-Za-z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*[^\\\/:*?"<>|\r\n]*`),
		unixPath: regexp.MustCompile(`/(?:[^/\x00\n]+/)*[^/\x00\n]+`),
		registry: regexp.MustCompile(`(?i)(HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s"']+`),
	}
}

// FindURLs extracts URLs from text
func (p *Patterns) FindURLs(text string) []string {
	return p.url.FindAllString(text, -1)
}

// FindIPs extracts IP addresses from text
func (p *Patterns) FindIPs(text string) []string {
	return p.ip.FindAllString(text, -1)
}

// FindDomains extracts domain names from text
func (p *Patterns) FindDomains(text string) []string {
	return p.domain.FindAllString(text, -1)
}

// FindEmails extracts email addresses from text
func (p *Patterns) FindEmails(text string) []string {
	return p.email.FindAllString(text, -1)
}

// FindWindowsPaths extracts Windows file paths from text
func (p *Patterns) FindWindowsPaths(text string) []string {
	paths := p.winPath.FindAllString(text, -1)
	// Filter out short paths that are likely false positives
	var result []string
	for _, path := range paths {
		if len(path) > 5 {
			result = append(result, path)
		}
	}
	return result
}

// FindUnixPaths extracts Unix file paths from text
func (p *Patterns) FindUnixPaths(text string) []string {
	paths := p.unixPath.FindAllString(text, -1)
	// Filter out common false positives
	var result []string
	for _, path := range paths {
		if len(path) > 3 && isSuspiciousPath(path) {
			result = append(result, path)
		}
	}
	return result
}

// FindRegistryKeys extracts Windows registry keys from text
func (p *Patterns) FindRegistryKeys(text string) []string {
	return p.registry.FindAllString(text, -1)
}

// IsPrivateIP checks if an IP is a private/reserved address
func (p *Patterns) IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check for private ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"224.0.0.0/4",
		"240.0.0.0/4",
	}

	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// IsValidDomain checks if a domain is likely valid and not a false positive
func (p *Patterns) IsValidDomain(domain string) bool {
	// Must have at least one dot
	if !strings.Contains(domain, ".") {
		return false
	}

	// Check TLD validity (basic check)
	parts := strings.Split(domain, ".")
	tld := parts[len(parts)-1]

	// Filter out common false positives
	invalidTLDs := map[string]bool{
		"dll": true, "exe": true, "sys": true, "tmp": true,
		"log": true, "txt": true, "dat": true, "bin": true,
		"0": true, "1": true, "2": true,
	}

	if invalidTLDs[strings.ToLower(tld)] {
		return false
	}

	// Filter out version-like patterns (e.g., "1.2.3")
	if len(parts) >= 2 {
		allNumeric := true
		for _, part := range parts {
			for _, c := range part {
				if c < '0' || c > '9' {
					allNumeric = false
					break
				}
			}
		}
		if allNumeric {
			return false
		}
	}

	return len(domain) > 4 && len(tld) >= 2
}

// isSuspiciousPath checks if a Unix path is potentially suspicious
func isSuspiciousPath(path string) bool {
	suspicious := []string{
		"/tmp/",
		"/var/tmp/",
		"/dev/shm/",
		"/proc/",
		"/etc/passwd",
		"/etc/shadow",
		"/etc/crontab",
		"/root/",
		"/.ssh/",
		"/home/",
		"/Library/",
		"/Applications/",
	}

	for _, sus := range suspicious {
		if strings.Contains(path, sus) {
			return true
		}
	}

	return false
}
