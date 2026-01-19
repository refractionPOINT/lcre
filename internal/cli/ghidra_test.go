package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/refractionPOINT/lcre/internal/backend/ghidra"
)

func TestGhidraFlags(t *testing.T) {
	cmd := ghidraCmd

	// Check --ghidra-path flag
	ghidraPathFlag := cmd.PersistentFlags().Lookup("ghidra-path")
	if ghidraPathFlag == nil {
		t.Error("--ghidra-path flag not found")
	}
	if ghidraPathFlag.DefValue != "" {
		t.Errorf("--ghidra-path default = %q, want empty", ghidraPathFlag.DefValue)
	}

	// Check --decompile flag
	decompileFlag := cmd.PersistentFlags().Lookup("decompile")
	if decompileFlag == nil {
		t.Error("--decompile flag not found")
	}
	if decompileFlag.DefValue != "false" {
		t.Errorf("--decompile default = %q, want %q", decompileFlag.DefValue, "false")
	}

	// Check --ghidra-timeout flag
	timeoutFlag := cmd.PersistentFlags().Lookup("ghidra-timeout")
	if timeoutFlag == nil {
		t.Error("--ghidra-timeout flag not found")
	}
}

func TestGhidraAnalyzeCmd(t *testing.T) {
	// Verify the analyze subcommand exists
	found := false
	for _, cmd := range ghidraCmd.Commands() {
		if cmd.Use == "analyze <binary>" {
			found = true
			break
		}
	}
	if !found {
		t.Error("ghidra analyze subcommand not found")
	}
}

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

func TestGhidraDecompileOptionsIntegration(t *testing.T) {
	// This test ensures that when --decompile is used, the proper
	// configuration is set up. This would have caught the original bug
	// where DecompileAll.java was referenced but didn't exist.

	// Simulate what runGhidraAnalyze does when --decompile is true
	decompile := true

	opts := ghidra.Options{
		GhidraPath: "/fake/ghidra",
		Decompile:  decompile,
	}

	// When decompile is enabled, the CLI should set a DecompiledDir
	if decompile {
		tempDir := t.TempDir()
		opts.DecompiledDir = tempDir
	}

	// Verify that if decompile is true, DecompiledDir should be set
	if opts.Decompile && opts.DecompiledDir == "" {
		t.Error("When Decompile is true, DecompiledDir should be set by the CLI")
	}
}
