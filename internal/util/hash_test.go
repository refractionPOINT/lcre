package util

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHashBytes(t *testing.T) {
	data := []byte("hello world")
	hashes := HashBytes(data)

	// Expected values for "hello world"
	expectedMD5 := "5eb63bbbe01eeed093cb22bb8f5acdc3"
	expectedSHA1 := "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
	expectedSHA256 := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

	if hashes.MD5 != expectedMD5 {
		t.Errorf("MD5: expected %s, got %s", expectedMD5, hashes.MD5)
	}
	if hashes.SHA1 != expectedSHA1 {
		t.Errorf("SHA1: expected %s, got %s", expectedSHA1, hashes.SHA1)
	}
	if hashes.SHA256 != expectedSHA256 {
		t.Errorf("SHA256: expected %s, got %s", expectedSHA256, hashes.SHA256)
	}
}

func TestHashFile(t *testing.T) {
	// Create temp file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")

	if err := os.WriteFile(tmpFile, []byte("hello world"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	hashes, err := HashFile(tmpFile)
	if err != nil {
		t.Fatalf("HashFile failed: %v", err)
	}

	expectedMD5 := "5eb63bbbe01eeed093cb22bb8f5acdc3"
	if hashes.MD5 != expectedMD5 {
		t.Errorf("MD5: expected %s, got %s", expectedMD5, hashes.MD5)
	}
}

func TestHashFileNotFound(t *testing.T) {
	_, err := HashFile("/nonexistent/file")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}
