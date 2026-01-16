package ghidra

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/maxime/lcre/internal/model"
	"github.com/maxime/lcre/internal/util"
	"github.com/maxime/lcre/internal/workspace"
)

// Runner executes Ghidra headless analysis
type Runner struct {
	ghidraPath    string
	timeout       time.Duration
	decompile     bool
	decompiledDir string // Optional: directory to store decompiled functions
}

// Run executes Ghidra analysis on the binary
func (r *Runner) Run(ctx context.Context, binaryPath string) (*model.AnalysisResult, error) {
	// Create workspace for Ghidra project and output
	ws, err := workspace.New("lcre-ghidra-")
	if err != nil {
		return nil, fmt.Errorf("failed to create workspace: %w", err)
	}
	defer ws.Cleanup()

	// Create project directory
	projectDir, err := ws.SubDir("project")
	if err != nil {
		return nil, fmt.Errorf("failed to create project dir: %w", err)
	}

	outputFile := ws.Path("analysis.json")

	// Get script path
	scriptPath, err := r.getScriptPath()
	if err != nil {
		return nil, err
	}

	// Build command
	analyzeHeadless := r.getAnalyzeHeadless()

	// Build script args - output file and optional decompiled directory
	scriptArgs := outputFile
	if r.decompiledDir != "" {
		scriptArgs = outputFile + " " + r.decompiledDir
	}

	args := []string{
		projectDir,
		"LCREProject",
		"-import", binaryPath,
		"-scriptPath", scriptPath,
		"-postScript", "ExportAnalysis.java", scriptArgs,
		"-deleteProject", // Clean up project after analysis
	}

	if r.decompile && r.decompiledDir == "" {
		args = append(args, "-postScript", "DecompileAll.java")
	}

	cmd := exec.CommandContext(ctx, analyzeHeadless, args...)
	cmd.Stdout = os.Stderr // Ghidra outputs to stdout, redirect to stderr
	cmd.Stderr = os.Stderr

	// Run analysis
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("Ghidra analysis timed out after %v", r.timeout)
		}
		return nil, fmt.Errorf("Ghidra analysis failed: %w", err)
	}

	// Parse results
	parser := &Parser{}
	result, err := parser.ParseFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Ghidra output: %w", err)
	}

	// Add metadata that Ghidra doesn't provide
	hashes, err := util.HashFile(binaryPath)
	if err == nil {
		result.Metadata.MD5 = hashes.MD5
		result.Metadata.SHA1 = hashes.SHA1
		result.Metadata.SHA256 = hashes.SHA256
	}

	size, err := util.FileSize(binaryPath)
	if err == nil {
		result.Metadata.Size = size
	}

	result.Metadata.Path = binaryPath
	result.Metadata.Name = filepath.Base(binaryPath)

	return result, nil
}

// getAnalyzeHeadless returns the path to analyzeHeadless
func (r *Runner) getAnalyzeHeadless() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(r.ghidraPath, "support", "analyzeHeadless.bat")
	}
	return filepath.Join(r.ghidraPath, "support", "analyzeHeadless")
}

// getScriptPath returns the path to our Ghidra scripts
func (r *Runner) getScriptPath() (string, error) {
	// First check if scripts are in the expected location relative to the binary
	execPath, err := os.Executable()
	if err == nil {
		scriptPath := filepath.Join(filepath.Dir(execPath), "..", "scripts", "ghidra")
		if _, err := os.Stat(filepath.Join(scriptPath, "ExportAnalysis.java")); err == nil {
			return scriptPath, nil
		}
	}

	// Check in current working directory
	cwd, err := os.Getwd()
	if err == nil {
		scriptPath := filepath.Join(cwd, "scripts", "ghidra")
		if _, err := os.Stat(filepath.Join(scriptPath, "ExportAnalysis.java")); err == nil {
			return scriptPath, nil
		}
	}

	// Check for LCRE_SCRIPTS_PATH environment variable
	if envPath := os.Getenv("LCRE_SCRIPTS_PATH"); envPath != "" {
		if _, err := os.Stat(filepath.Join(envPath, "ExportAnalysis.java")); err == nil {
			return envPath, nil
		}
	}

	return "", fmt.Errorf("ExportAnalysis.java script not found. Set LCRE_SCRIPTS_PATH or ensure scripts/ghidra directory exists")
}
