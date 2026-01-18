package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/maxime/lcre/internal/backend"
	_ "github.com/maxime/lcre/internal/backend/native"
)

func TestValidateBinaryPath_Comprehensive(t *testing.T) {
	tempDir := t.TempDir()

	// Create a regular file
	regularFile := filepath.Join(tempDir, "regular")
	os.WriteFile(regularFile, []byte("content"), 0644)

	// Create a symlink
	symlinkPath := filepath.Join(tempDir, "symlink")
	os.Symlink(regularFile, symlinkPath)

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"regular file", regularFile, false},
		{"symlink to file", symlinkPath, false},
		{"non-existent", filepath.Join(tempDir, "nonexistent"), true},
		{"directory", tempDir, true},
		{"empty path", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBinaryPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateBinaryPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestTriageFlags(t *testing.T) {
	// Verify default flag values
	cmd := triageCmd

	// Check default flag values
	stringsFlag := cmd.Flags().Lookup("strings")
	if stringsFlag == nil {
		t.Error("--strings flag not found")
	}
	if stringsFlag.DefValue != "true" {
		t.Errorf("--strings default = %q, want %q", stringsFlag.DefValue, "true")
	}

	yaraFlag := cmd.Flags().Lookup("yara")
	if yaraFlag == nil {
		t.Error("--yara flag not found")
	}
	if yaraFlag.DefValue != "true" {
		t.Errorf("--yara default = %q, want %q", yaraFlag.DefValue, "true")
	}

	minStrLenFlag := cmd.Flags().Lookup("min-string-len")
	if minStrLenFlag == nil {
		t.Error("--min-string-len flag not found")
	}
	if minStrLenFlag.DefValue != "4" {
		t.Errorf("--min-string-len default = %q, want %q", minStrLenFlag.DefValue, "4")
	}
}

func TestNativeBackendAnalysis(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	binaryPath := findSystemBinaryForTriage(t)

	b, err := backend.DefaultRegistry.Get("native")
	if err != nil {
		t.Fatalf("Failed to get native backend: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	opts := backend.AnalysisOptions{
		Timeout:         30 * time.Second,
		IncludeStrings:  true,
		MinStringLength: 4,
		MaxStrings:      1000,
	}

	result, err := b.Analyze(ctx, binaryPath, opts)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	// Verify metadata
	if result.Metadata.Size == 0 {
		t.Error("Metadata.Size should be set")
	}
	if result.Metadata.Format == "" {
		t.Error("Metadata.Format should be detected")
	}
	if result.Metadata.Arch == "" {
		t.Error("Metadata.Arch should be detected")
	}

	t.Logf("Analyzed %s: format=%s, arch=%s, size=%d",
		binaryPath, result.Metadata.Format, result.Metadata.Arch, result.Metadata.Size)
	t.Logf("Found %d sections, %d imports, %d exports, %d strings",
		len(result.Sections), len(result.Imports), len(result.Exports), len(result.Strings))
}

func TestNativeBackendWithOptions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	binaryPath := findSystemBinaryForTriage(t)

	b, err := backend.DefaultRegistry.Get("native")
	if err != nil {
		t.Fatalf("Failed to get native backend: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("with strings disabled", func(t *testing.T) {
		opts := backend.AnalysisOptions{
			Timeout:        30 * time.Second,
			IncludeStrings: false,
		}

		result, err := b.Analyze(ctx, binaryPath, opts)
		if err != nil {
			t.Fatalf("Analyze() error = %v", err)
		}

		// Should still have metadata and sections
		if result.Metadata.Size == 0 {
			t.Error("Metadata.Size should be set")
		}
		// Strings may or may not be included depending on implementation
	})

	t.Run("with deep analysis", func(t *testing.T) {
		opts := backend.AnalysisOptions{
			Timeout:        30 * time.Second,
			IncludeStrings: true,
			DeepAnalysis:   true,
		}

		result, err := b.Analyze(ctx, binaryPath, opts)
		if err != nil {
			t.Fatalf("Analyze() error = %v", err)
		}

		if result.Metadata.Size == 0 {
			t.Error("Metadata.Size should be set")
		}
	})
}

func TestOutputResults_JSON(t *testing.T) {
	// Save original format
	originalFormat := outputFormat
	defer func() { outputFormat = originalFormat }()

	outputFormat = "json"

	// Test with simple struct
	testData := struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}{
		Name:  "test",
		Value: 42,
	}

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := outputResults(testData)

	w.Close()
	os.Stdout = old

	if err != nil {
		t.Errorf("outputResults() error = %v", err)
	}

	// Read and verify output
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	result := string(buf[:n])

	if !containsSubstring(result, "name") || !containsSubstring(result, "test") {
		t.Errorf("outputResults() JSON output missing expected fields: %s", result)
	}
}

func TestOutputResults_UnknownFormat(t *testing.T) {
	// Save original format
	originalFormat := outputFormat
	defer func() { outputFormat = originalFormat }()

	outputFormat = "invalid_format"

	err := outputResults(struct{}{})
	if err == nil {
		t.Error("outputResults() should error on unknown format")
	}
}

func TestBackendRegistry(t *testing.T) {
	// Test that native backend is registered
	b, err := backend.DefaultRegistry.Get("native")
	if err != nil {
		t.Errorf("Failed to get native backend: %v", err)
	}
	if b == nil {
		t.Error("Native backend should not be nil")
	}

	// Test that ghidra backend exists (may not be available)
	_, err = backend.DefaultRegistry.Get("ghidra")
	// Don't fail if ghidra not available, just log
	if err != nil {
		t.Logf("Ghidra backend not available: %v", err)
	}
}

func TestBackendAvailability(t *testing.T) {
	b, err := backend.DefaultRegistry.Get("native")
	if err != nil {
		t.Fatalf("Failed to get native backend: %v", err)
	}

	avail, reason := b.Available()
	if !avail {
		t.Errorf("Native backend should be available, but got: %s", reason)
	}

	name := b.Name()
	if name != "native" {
		t.Errorf("Backend name = %q, want %q", name, "native")
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := backend.DefaultOptions()

	if opts.Timeout == 0 {
		t.Error("DefaultOptions().Timeout should be set")
	}
}

// Helper function
func findSystemBinaryForTriage(t *testing.T) string {
	t.Helper()
	candidates := []string{"/bin/true", "/bin/ls", "/bin/cat", "/usr/bin/true", "/usr/bin/ls"}
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	t.Skip("No suitable system binary found for integration test")
	return ""
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
