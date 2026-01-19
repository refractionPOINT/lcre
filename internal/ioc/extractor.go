package ioc

import (
	"github.com/refractionPOINT/lcre/internal/model"
)

// Extractor extracts IOCs from binary analysis results
type Extractor struct {
	patterns *Patterns
}

// NewExtractor creates a new IOC extractor
func NewExtractor() *Extractor {
	return &Extractor{
		patterns: NewPatterns(),
	}
}

// ExtractFromStrings extracts IOCs from extracted strings
func (e *Extractor) ExtractFromStrings(strings []model.ExtractedString) *model.IOCResult {
	result := &model.IOCResult{}

	seen := make(map[string]bool)

	for _, str := range strings {
		// Extract URLs
		for _, url := range e.patterns.FindURLs(str.Value) {
			if !seen[url] {
				seen[url] = true
				result.AddIOC(model.IOC{
					Type:   model.IOCURL,
					Value:  url,
					Offset: str.Offset,
				})
			}
		}

		// Extract IPs
		for _, ip := range e.patterns.FindIPs(str.Value) {
			if !seen[ip] && !e.patterns.IsPrivateIP(ip) {
				seen[ip] = true
				result.AddIOC(model.IOC{
					Type:   model.IOCIP,
					Value:  ip,
					Offset: str.Offset,
				})
			}
		}

		// Extract domains
		for _, domain := range e.patterns.FindDomains(str.Value) {
			if !seen[domain] && e.patterns.IsValidDomain(domain) {
				seen[domain] = true
				result.AddIOC(model.IOC{
					Type:   model.IOCDomain,
					Value:  domain,
					Offset: str.Offset,
				})
			}
		}

		// Extract emails
		for _, email := range e.patterns.FindEmails(str.Value) {
			if !seen[email] {
				seen[email] = true
				result.AddIOC(model.IOC{
					Type:   model.IOCEmail,
					Value:  email,
					Offset: str.Offset,
				})
			}
		}

		// Extract Windows paths
		for _, path := range e.patterns.FindWindowsPaths(str.Value) {
			if !seen[path] {
				seen[path] = true
				result.AddIOC(model.IOC{
					Type:   model.IOCPath,
					Value:  path,
					Offset: str.Offset,
				})
			}
		}

		// Extract Unix paths
		for _, path := range e.patterns.FindUnixPaths(str.Value) {
			if !seen[path] {
				seen[path] = true
				result.AddIOC(model.IOC{
					Type:   model.IOCPath,
					Value:  path,
					Offset: str.Offset,
				})
			}
		}

		// Extract registry keys
		for _, key := range e.patterns.FindRegistryKeys(str.Value) {
			if !seen[key] {
				seen[key] = true
				result.AddIOC(model.IOC{
					Type:   model.IOCRegistry,
					Value:  key,
					Offset: str.Offset,
				})
			}
		}
	}

	return result
}
