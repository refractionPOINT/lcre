package ghidra

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/refractionPOINT/lcre/internal/backend"
	"github.com/refractionPOINT/lcre/internal/model"
)

// Options configures the Ghidra backend
type Options struct {
	GhidraPath    string
	Timeout       time.Duration
	Decompile     bool
	ScriptPath    string
	DecompiledDir string // Directory to store decompiled function files
}

// Backend implements Ghidra-based binary analysis
type Backend struct {
	opts Options
}

// New creates a new Ghidra backend
func New(opts Options) *Backend {
	return &Backend{opts: opts}
}

// Name returns the backend name
func (b *Backend) Name() string {
	return "ghidra"
}

// Capabilities returns what this backend can do
func (b *Backend) Capabilities() backend.Capabilities {
	return backend.Capabilities{
		ParseHeaders:   true,
		ParseImports:   true,
		ParseExports:   true,
		ExtractStrings: true,
		CalcEntropy:    false, // Ghidra doesn't provide entropy directly
		Decompile:      true,
		CallGraph:      true,
		CrossRefs:      true,
	}
}

// Available checks if Ghidra is available
func (b *Backend) Available() (bool, string) {
	ghidraPath := b.getGhidraPath()
	if ghidraPath == "" {
		return false, "GHIDRA_HOME not set and --ghidra-path not provided"
	}

	// Check for analyzeHeadless
	analyzeHeadless := filepath.Join(ghidraPath, "support", "analyzeHeadless")
	if _, err := os.Stat(analyzeHeadless); os.IsNotExist(err) {
		// Try Windows variant
		analyzeHeadless = filepath.Join(ghidraPath, "support", "analyzeHeadless.bat")
		if _, err := os.Stat(analyzeHeadless); os.IsNotExist(err) {
			return false, "analyzeHeadless not found in " + ghidraPath
		}
	}

	return true, "Ghidra available at " + ghidraPath
}

// getGhidraPath returns the Ghidra installation path
func (b *Backend) getGhidraPath() string {
	if b.opts.GhidraPath != "" {
		return b.opts.GhidraPath
	}
	return os.Getenv("GHIDRA_HOME")
}

// Analyze performs analysis using Ghidra headless
func (b *Backend) Analyze(ctx context.Context, path string, opts backend.AnalysisOptions) (*model.AnalysisResult, error) {
	start := time.Now()

	runner := &Runner{
		ghidraPath:    b.getGhidraPath(),
		timeout:       b.opts.Timeout,
		decompile:     b.opts.Decompile,
		decompiledDir: b.opts.DecompiledDir,
	}

	result, err := runner.Run(ctx, path)
	if err != nil {
		return nil, err
	}

	result.Backend = b.Name()
	result.Duration = time.Since(start).Seconds()
	result.Timestamp = start

	return result, nil
}

// SetDecompiledDir sets the directory for storing decompiled functions.
func (b *Backend) SetDecompiledDir(dir string) {
	b.opts.DecompiledDir = dir
}

// Register registers this backend with the default registry.
func Register() {
	backend.DefaultRegistry.Register(New(Options{
		Timeout: 5 * time.Minute,
	}))
}

func init() {
	Register()
}
