package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/refractionPOINT/lcre/internal/backend"
	_ "github.com/refractionPOINT/lcre/internal/backend/native" // Register native backend
	"github.com/refractionPOINT/lcre/internal/output"
	"github.com/refractionPOINT/lcre/internal/yara"
)

var (
	triageStrings    bool
	triageYARA       bool
	triageMinStrLen  int
	triageMaxStrings int
)

var triageCmd = &cobra.Command{
	Use:   "triage <binary>",
	Short: "Fast binary triage using native parsing",
	Long: `Performs fast static analysis on a binary using native Go parsing.

This command provides quick triage information including:
- File metadata and hashes
- Section information with entropy
- Import/export tables
- Extracted strings (optional)
- YARA scan results (optional)`,
	Args: cobra.ExactArgs(1),
	RunE: runTriage,
}

func init() {
	triageCmd.Flags().BoolVar(&triageStrings, "strings", true, "Extract strings from binary")
	triageCmd.Flags().BoolVar(&triageYARA, "yara", true, "Run YARA scan")
	triageCmd.Flags().IntVar(&triageMinStrLen, "min-string-len", 4, "Minimum string length to extract")
	triageCmd.Flags().IntVar(&triageMaxStrings, "max-strings", 10000, "Maximum strings to extract")
	rootCmd.AddCommand(triageCmd)
}

func runTriage(cmd *cobra.Command, args []string) error {
	binaryPath := args[0]

	if err := validateBinaryPath(binaryPath); err != nil {
		return err
	}

	// Get the native backend
	b, err := backend.DefaultRegistry.Get("native")
	if err != nil {
		return fmt.Errorf("native backend not available: %w", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Configure analysis options
	opts := backend.AnalysisOptions{
		Timeout:         timeout,
		IncludeStrings:  triageStrings,
		MinStringLength: triageMinStrLen,
		MaxStrings:      triageMaxStrings,
	}

	// Run analysis
	if verbose {
		fmt.Fprintf(os.Stderr, "Analyzing %s...\n", binaryPath)
	}

	result, err := b.Analyze(ctx, binaryPath, opts)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	// Run YARA scan if enabled
	if triageYARA {
		scanner := yara.NewScanner()
		yaraResult, err := scanner.Scan(ctx, binaryPath)
		if err != nil {
			result.AddError(fmt.Sprintf("YARA scan failed: %v", err))
		} else {
			result.YARA = yaraResult
		}
	}

	// Output results
	return outputResults(result)
}

func outputResults(result interface{}) error {
	switch outputFormat {
	case "json":
		writer := output.NewJSONWriter(true)
		return writer.Write(os.Stdout, result)
	case "md":
		// For analysis results
		if ar, ok := result.(*struct{}); ok {
			_ = ar
		}
		// Fall back to JSON for non-analysis types
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	default:
		return fmt.Errorf("unknown output format: %s", outputFormat)
	}
}
