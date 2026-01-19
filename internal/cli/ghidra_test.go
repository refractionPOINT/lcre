package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/refractionPOINT/lcre/internal/backend/ghidra"
)

func TestGhidraBackendCreation(t *testing.T) {
	// Test that ghidra backend can be created with all options
	opts := ghidra.Options{
		GhidraPath:    "/fake/path",
		Decompile:     true,
		DecompiledDir: "/fake/decompiled",
	}

	b := ghidra.New(opts)
	if b == nil {
		t.Fatal("ghidra.New() returned nil")
	}

	if b.Name() != "ghidra" {
		t.Errorf("Backend name = %q, want %q", b.Name(), "ghidra")
	}

	caps := b.Capabilities()
	if !caps.Decompile {
		t.Error("Ghidra backend should support decompilation")
	}
	if !caps.CallGraph {
		t.Error("Ghidra backend should support call graph")
	}
}

func TestGhidraBackendDecompiledDirSetter(t *testing.T) {
	b := ghidra.New(ghidra.Options{})

	tempDir := t.TempDir()
	b.SetDecompiledDir(tempDir)

	// Verify the setter works by checking capabilities still work
	// (we can't directly access opts, but the setter should not panic)
	caps := b.Capabilities()
	if !caps.Decompile {
		t.Error("Capabilities should still report decompile support")
	}
}

func TestGhidraScriptsExist(t *testing.T) {
	// Find the scripts directory
	scriptPaths := []string{
		"scripts/ghidra",
		"../../../scripts/ghidra",
	}

	// Also check relative to the working directory
	cwd, _ := os.Getwd()
	for i := 0; i < 5; i++ {
		scriptPaths = append(scriptPaths, filepath.Join(cwd, "scripts/ghidra"))
		cwd = filepath.Dir(cwd)
	}

	var scriptDir string
	for _, path := range scriptPaths {
		if _, err := os.Stat(path); err == nil {
			scriptDir = path
			break
		}
	}

	if scriptDir == "" {
		t.Skip("scripts/ghidra directory not found - skipping script existence check")
	}

	// Required scripts that must exist
	requiredScripts := []string{
		"ExportAnalysis.java",
	}

	for _, script := range requiredScripts {
		scriptPath := filepath.Join(scriptDir, script)
		if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
			t.Errorf("Required Ghidra script %s not found at %s", script, scriptPath)
		}
	}
}
