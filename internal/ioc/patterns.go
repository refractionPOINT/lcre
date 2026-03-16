package ioc

import (
	"net"
	"regexp"
	"strings"
)

// Patterns contains regex patterns for IOC extraction
type Patterns struct {
	url             *regexp.Regexp
	ip              *regexp.Regexp
	domain          *regexp.Regexp
	email           *regexp.Regexp
	winPath         *regexp.Regexp
	unixPath        *regexp.Regexp
	registry        *regexp.Regexp
	privateNetworks []*net.IPNet
}

// NewPatterns creates patterns for IOC extraction
func NewPatterns() *Patterns {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"224.0.0.0/4",
		"240.0.0.0/4",
	}
	networks := make([]*net.IPNet, 0, len(privateRanges))
	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		networks = append(networks, network)
	}

	return &Patterns{
		url:             regexp.MustCompile(`https?://[^\s"'<>\x00-\x1f]+`),
		ip:              regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
		domain:          regexp.MustCompile(`\b([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b`),
		email:           regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
		winPath:         regexp.MustCompile(`[A-Za-z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*[^\\\/:*?"<>|\r\n]*`),
		unixPath:        regexp.MustCompile(`/(?:[^/\x00\n]+/)*[^/\x00\n]+`),
		registry:        regexp.MustCompile(`(?i)(HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s"']+`),
		privateNetworks: networks,
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

	for _, network := range p.privateNetworks {
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

	// Filter out common false positives from file extensions and binary artifacts
	invalidTLDs := map[string]bool{
		"dll": true, "exe": true, "sys": true, "tmp": true,
		"log": true, "txt": true, "dat": true, "bin": true,
		"cfg": true, "ini": true, "bak": true, "old": true,
		"png": true, "jpg": true, "gif": true, "bmp": true, "ico": true,
		"xml": true, "csv": true, "json": true, "yaml": true, "yml": true,
		"zip": true, "rar": true, "gz": true, "tar": true,
		"pdb": true, "obj": true, "lib": true, "exp": true,
		"class": true, "jar": true, "pyc": true, "pyo": true,
		"app": true, "ipa": true, "apk": true, "deb": true, "rpm": true,
		"lo": true, "la": true, "so": true, "dylib": true, "o": true,
		"conf": true, "plt": true, "part": true,
		"rs": true, "go": true, "c": true, "h": true, "cpp": true,
		"0": true, "1": true, "2": true,
	}

	if invalidTLDs[strings.ToLower(tld)] {
		return false
	}

	// Filter out .NET/Java namespace prefixes (e.g., System.IO, Microsoft.CSharp).
	// Also handles corrupted metadata where a junk byte precedes the namespace
	// (e.g., "3System.Resources" or "lSystem.Resources").
	lower := strings.ToLower(domain)
	namespacePrefixes := []string{
		"system.", "microsoft.", "windows.", "mscorlib.",
		"java.", "javax.", "org.apache.", "com.google.",
		"org.xml.", "org.w3c.",
	}
	for _, prefix := range namespacePrefixes {
		if strings.HasPrefix(lower, prefix) || strings.Contains(lower, prefix) {
			return false
		}
	}

	// Filter out strings that look like qualified code identifiers:
	// if the majority of segments start with uppercase, it's likely a
	// namespace/class reference rather than a real domain.
	if looksLikeCodeIdentifier(domain) {
		return false
	}

	// Filter out very short first labels (e.g., "H.aRX", "6.DLI") — real
	// domains rarely have single-character labels except well-known ones.
	if len(parts[0]) <= 1 && len(parts) == 2 {
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

// looksLikeCodeIdentifier detects patterns like "Foo.Bar", "MyApp.Properties"
// that are code identifiers rather than domains. Real domains use lowercase;
// code identifiers typically have PascalCase segments.
func looksLikeCodeIdentifier(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	pascalCount := 0
	for _, part := range parts {
		if len(part) > 0 && part[0] >= 'A' && part[0] <= 'Z' {
			pascalCount++
		}
	}
	// If the majority of segments start with uppercase, it's likely a code
	// identifier (e.g., "Rtxtjown.Properties.Resources.resources" has 3/4).
	// For 2-part names, one PascalCase segment is enough (e.g., "Webcam.webcam").
	if len(parts) == 2 {
		return pascalCount >= 1
	}
	return pascalCount*2 >= len(parts) && pascalCount >= 2
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
