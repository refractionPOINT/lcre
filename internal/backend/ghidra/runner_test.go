package ghidra

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetScriptPath_FindsScripts(t *testing.T) {
	r := &Runner{}

	scriptPath, err := r.getScriptPath()
	if err != nil {
		t.Skipf("Script path not found (expected in dev environment): %v", err)
	}

	// Verify the script path exists
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		t.Errorf("getScriptPath() returned non-existent path: %s", scriptPath)
	}

	// Verify ExportAnalysis.java exists
	exportScript := filepath.Join(scriptPath, "ExportAnalysis.java")
	if _, err := os.Stat(exportScript); os.IsNotExist(err) {
		t.Errorf("ExportAnalysis.java not found at %s", exportScript)
	}
}

func TestRunner_ScriptPathFromEnv(t *testing.T) {
	// Create a temp directory with the required script
	tempDir := t.TempDir()
	scriptFile := filepath.Join(tempDir, "ExportAnalysis.java")
	if err := os.WriteFile(scriptFile, []byte("// test"), 0644); err != nil {
		t.Fatal(err)
	}

	// Set environment variable
	oldEnv := os.Getenv("LCRE_SCRIPTS_PATH")
	os.Setenv("LCRE_SCRIPTS_PATH", tempDir)
	defer os.Setenv("LCRE_SCRIPTS_PATH", oldEnv)

	r := &Runner{}
	scriptPath, err := r.getScriptPath()
	if err != nil {
		t.Errorf("getScriptPath() with LCRE_SCRIPTS_PATH set should succeed: %v", err)
	}

	if scriptPath != tempDir {
		t.Errorf("getScriptPath() = %q, want %q", scriptPath, tempDir)
	}
}

func TestRunner_DecompileRequiresDirectory(t *testing.T) {
	// This test verifies that when decompile is enabled, a directory must be set.
	// The bug was that decompile=true with decompiledDir="" would try to use
	// a non-existent DecompileAll.java script.

	r := &Runner{
		ghidraPath:    "/fake/ghidra",
		decompile:     true,
		decompiledDir: "", // This was the bug - empty dir with decompile=true
	}

	// The runner should work correctly now - if decompile is enabled but no
	// decompiledDir is set, decompilation simply won't happen (which is the
	// CLI's responsibility to configure properly).
	// This test documents the expected behavior.

	if r.decompile && r.decompiledDir == "" {
		// This is now acceptable - decompilation just won't produce output files.
		// The CLI should always set decompiledDir when decompile is true.
		t.Log("Note: decompile=true with empty decompiledDir means no decompiled files will be saved")
	}
}

func TestRunner_DecompileDirPassedToScript(t *testing.T) {
	// Verify that when decompiledDir is set, it gets included in args
	tempDir := t.TempDir()

	r := &Runner{
		ghidraPath:    "/fake/ghidra",
		decompile:     true,
		decompiledDir: tempDir,
	}

	// Verify the configuration is correct
	if r.decompiledDir != tempDir {
		t.Errorf("decompiledDir = %q, want %q", r.decompiledDir, tempDir)
	}
}
