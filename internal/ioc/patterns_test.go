package ioc

import (
	"testing"
)

func TestFindURLs(t *testing.T) {
	p := NewPatterns()

	tests := []struct {
		input    string
		expected []string
	}{
		{
			input:    "Visit http://example.com for more",
			expected: []string{"http://example.com"},
		},
		{
			input:    "Secure: https://secure.example.com/path?query=1",
			expected: []string{"https://secure.example.com/path?query=1"},
		},
		{
			input:    "Multiple: http://a.com and https://b.com",
			expected: []string{"http://a.com", "https://b.com"},
		},
		{
			input:    "No URLs here",
			expected: nil,
		},
	}

	for _, tt := range tests {
		result := p.FindURLs(tt.input)
		if len(result) != len(tt.expected) {
			t.Errorf("FindURLs(%q): got %d URLs, expected %d", tt.input, len(result), len(tt.expected))
			continue
		}
		for i, url := range result {
			if url != tt.expected[i] {
				t.Errorf("FindURLs(%q)[%d]: got %q, expected %q", tt.input, i, url, tt.expected[i])
			}
		}
	}
}

func TestFindIPs(t *testing.T) {
	p := NewPatterns()

	tests := []struct {
		input    string
		expected []string
	}{
		{
			input:    "Connect to 192.168.1.1",
			expected: []string{"192.168.1.1"},
		},
		{
			input:    "Server 10.0.0.1 and client 10.0.0.2",
			expected: []string{"10.0.0.1", "10.0.0.2"},
		},
		{
			input:    "Invalid: 999.999.999.999",
			expected: nil,
		},
		{
			input:    "Edge cases: 0.0.0.0 and 255.255.255.255",
			expected: []string{"0.0.0.0", "255.255.255.255"},
		},
	}

	for _, tt := range tests {
		result := p.FindIPs(tt.input)
		if len(result) != len(tt.expected) {
			t.Errorf("FindIPs(%q): got %d IPs, expected %d", tt.input, len(result), len(tt.expected))
			continue
		}
		for i, ip := range result {
			if ip != tt.expected[i] {
				t.Errorf("FindIPs(%q)[%d]: got %q, expected %q", tt.input, i, ip, tt.expected[i])
			}
		}
	}
}

func TestIsPrivateIP(t *testing.T) {
	p := NewPatterns()

	tests := []struct {
		ip       string
		expected bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"127.0.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"203.0.113.1", false},
	}

	for _, tt := range tests {
		result := p.IsPrivateIP(tt.ip)
		if result != tt.expected {
			t.Errorf("IsPrivateIP(%q): got %v, expected %v", tt.ip, result, tt.expected)
		}
	}
}

func TestIsValidDomain(t *testing.T) {
	p := NewPatterns()

	tests := []struct {
		domain   string
		expected bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"example.co.uk", true},
		{"nodot", false},
		{"file.exe", false},
		{"lib.dll", false},
		{"1.2.3", false},
	}

	for _, tt := range tests {
		result := p.IsValidDomain(tt.domain)
		if result != tt.expected {
			t.Errorf("IsValidDomain(%q): got %v, expected %v", tt.domain, result, tt.expected)
		}
	}
}

func TestFindRegistryKeys(t *testing.T) {
	p := NewPatterns()

	tests := []struct {
		input    string
		expected int
	}{
		{
			input:    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft",
			expected: 1,
		},
		{
			input:    "HKLM\\Software\\Test and HKCU\\Software\\Test2",
			expected: 2,
		},
		{
			input:    "No registry keys here",
			expected: 0,
		},
	}

	for _, tt := range tests {
		result := p.FindRegistryKeys(tt.input)
		if len(result) != tt.expected {
			t.Errorf("FindRegistryKeys(%q): got %d, expected %d", tt.input, len(result), tt.expected)
		}
	}
}

func TestFindWindowsPaths(t *testing.T) {
	p := NewPatterns()

	tests := []struct {
		input    string
		expected int
	}{
		{
			input:    "C:\\Windows\\System32\\cmd.exe",
			expected: 1,
		},
		{
			input:    "D:\\Users\\Admin\\Desktop\\file.txt",
			expected: 1,
		},
		{
			input:    "Unix path: /usr/bin/bash",
			expected: 0,
		},
	}

	for _, tt := range tests {
		result := p.FindWindowsPaths(tt.input)
		if len(result) != tt.expected {
			t.Errorf("FindWindowsPaths(%q): got %d, expected %d", tt.input, len(result), tt.expected)
		}
	}
}
