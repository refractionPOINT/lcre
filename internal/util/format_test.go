package util

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/refractionPOINT/lcre/internal/model"
)

func TestDetectFormatFromBytes(t *testing.T) {
	tests := []struct {
		name     string
		header   []byte
		expected model.BinaryFormat
	}{
		{
			name:     "PE format",
			header:   []byte{0x4D, 0x5A, 0x90, 0x00}, // MZ header
			expected: model.FormatPE,
		},
		{
			name:     "ELF format",
			header:   []byte{0x7F, 0x45, 0x4C, 0x46}, // \x7FELF
			expected: model.FormatELF,
		},
		{
			name:     "Mach-O 64-bit",
			header:   []byte{0xFE, 0xED, 0xFA, 0xCF},
			expected: model.FormatMachO,
		},
		{
			name:     "Mach-O 32-bit",
			header:   []byte{0xFE, 0xED, 0xFA, 0xCE},
			expected: model.FormatMachO,
		},
		{
			name:     "Mach-O universal",
			header:   []byte{0xCA, 0xFE, 0xBA, 0xBE},
			expected: model.FormatMachO,
		},
		{
			name:     "Unknown format",
			header:   []byte{0x00, 0x01, 0x02, 0x03},
			expected: model.FormatUnknown,
		},
		{
			name:     "Empty header",
			header:   []byte{},
			expected: model.FormatUnknown,
		},
		{
			name:     "Short header",
			header:   []byte{0x4D}, // Only one byte
			expected: model.FormatUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectFormatFromBytes(tt.header)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestDetectFormat(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test PE file
	peFile := filepath.Join(tmpDir, "test.exe")
	peHeader := []byte{0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00}
	if err := os.WriteFile(peFile, peHeader, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	format, err := DetectFormat(peFile)
	if err != nil {
		t.Fatalf("DetectFormat failed: %v", err)
	}
	if format != model.FormatPE {
		t.Errorf("expected PE format, got %s", format)
	}
}

func TestFileSize(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.bin")
	data := make([]byte, 1024)
	if err := os.WriteFile(testFile, data, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	size, err := FileSize(testFile)
	if err != nil {
		t.Fatalf("FileSize failed: %v", err)
	}
	if size != 1024 {
		t.Errorf("expected size 1024, got %d", size)
	}
}

func TestFileExists(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.bin")

	if FileExists(testFile) {
		t.Error("FileExists should return false for nonexistent file")
	}

	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	if !FileExists(testFile) {
		t.Error("FileExists should return true for existing file")
	}
}
