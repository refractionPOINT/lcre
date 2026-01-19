package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/refractionPOINT/lcre/internal/backend"
	"github.com/refractionPOINT/lcre/internal/backend/ghidra"
	"github.com/refractionPOINT/lcre/internal/output"
	"github.com/refractionPOINT/lcre/internal/yara"
)

var (
	ghidraPath     string
	ghidraDecompile bool
	ghidraTimeout  time.Duration
)

var ghidraCmd = &cobra.Command{
	Use:   "ghidra",
	Short: "Deep analysis using Ghidra headless",
	Long:  `Performs deep binary analysis using Ghidra headless mode.`,
}

var ghidraAnalyzeCmd = &cobra.Command{
	Use:   "analyze <binary>",
	Short: "Analyze a binary using Ghidra",
	Long: `Analyzes a binary using Ghidra headless mode for deep analysis.

This provides:
- Full function listing with decompilation
- Call graph analysis
- Cross-references
- String references
- Detailed import/export analysis`,
	Args: cobra.ExactArgs(1),
	RunE: runGhidraAnalyze,
}

func init() {
	ghidraCmd.PersistentFlags().StringVar(&ghidraPath, "ghidra-path", "", "Path to Ghidra installation (or set GHIDRA_HOME)")
	ghidraCmd.PersistentFlags().BoolVar(&ghidraDecompile, "decompile", false, "Include decompiled code (slower)")
	ghidraCmd.PersistentFlags().DurationVar(&ghidraTimeout, "ghidra-timeout", 5*time.Minute, "Ghidra analysis timeout")

	ghidraCmd.AddCommand(ghidraAnalyzeCmd)
	rootCmd.AddCommand(ghidraCmd)
}

func runGhidraAnalyze(cmd *cobra.Command, args []string) error {
	binaryPath := args[0]

	if err := validateBinaryPath(binaryPath); err != nil {
		return err
	}

	// Create options for Ghidra backend
	opts := ghidra.Options{
		GhidraPath: ghidraPath,
		Timeout:    ghidraTimeout,
		Decompile:  ghidraDecompile,
	}

	// If decompile is enabled, create a temp directory for decompiled files
	if ghidraDecompile {
		decompiledDir, err := os.MkdirTemp("", "lcre-decompiled-")
		if err != nil {
			return fmt.Errorf("failed to create temp directory for decompiled files: %w", err)
		}
		defer os.RemoveAll(decompiledDir)
		opts.DecompiledDir = decompiledDir
	}

	// Create Ghidra backend
	b := ghidra.New(opts)

	// Check availability
	available, reason := b.Available()
	if !available {
		return fmt.Errorf("Ghidra not available: %s", reason)
	}

	// Register the backend
	backend.DefaultRegistry.Register(b)

	ctx, cancel := context.WithTimeout(context.Background(), ghidraTimeout)
	defer cancel()

	analysisOpts := backend.AnalysisOptions{
		Timeout:         ghidraTimeout,
		IncludeStrings:  true,
		MinStringLength: 4,
		MaxStrings:      50000,
		DeepAnalysis:    true,
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Analyzing %s with Ghidra (this may take a while)...\n", binaryPath)
	}

	result, err := b.Analyze(ctx, binaryPath, analysisOpts)
	if err != nil {
		return fmt.Errorf("Ghidra analysis failed: %w", err)
	}

	// Run YARA scan
	scanner := yara.NewScanner()
	yaraResult, err := scanner.Scan(ctx, binaryPath)
	if err != nil {
		result.AddError(fmt.Sprintf("YARA scan failed: %v", err))
	} else {
		result.YARA = yaraResult
	}

	// Output results
	switch outputFormat {
	case "json":
		writer := output.NewJSONWriter(true)
		return writer.Write(os.Stdout, result)
	case "md":
		writer := output.NewMarkdownWriter()
		return writer.Write(os.Stdout, result)
	default:
		return fmt.Errorf("unknown output format: %s", outputFormat)
	}
}
