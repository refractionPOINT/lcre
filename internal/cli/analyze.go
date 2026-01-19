package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/refractionPOINT/lcre/internal/backend"
	_ "github.com/refractionPOINT/lcre/internal/backend/native" // Register native backend
	"github.com/refractionPOINT/lcre/internal/ioc"
	"github.com/refractionPOINT/lcre/internal/model"
	"github.com/refractionPOINT/lcre/internal/output"
	"github.com/refractionPOINT/lcre/internal/yara"
)

var (
	analyzeStrings    bool
	analyzeYARA       bool
	analyzeIOCs       bool
	analyzeMinStrLen  int
	analyzeMaxStrings int
)

// AnalyzeReport contains all analysis results when IOCs are included
type AnalyzeReport struct {
	Analysis *model.AnalysisResult `json:"analysis"`
	IOCs     *model.IOCResult      `json:"iocs,omitempty"`
}

var analyzeCmd = &cobra.Command{
	Use:   "analyze <binary>",
	Short: "Analyze a binary file",
	Long: `Performs static analysis on a binary using native Go parsing.

This command provides:
- File metadata and hashes
- Section information with entropy
- Import/export tables
- Extracted strings (optional)
- YARA scan results (optional)
- IOC extraction (optional)

For deep analysis with function extraction and decompilation,
use 'lcre query functions <binary>' or 'lcre query decompile <binary> <func>'.`,
	Args: cobra.ExactArgs(1),
	RunE: runAnalyze,
}

func init() {
	analyzeCmd.Flags().BoolVar(&analyzeStrings, "strings", true, "Extract strings from binary")
	analyzeCmd.Flags().BoolVar(&analyzeYARA, "yara", true, "Run YARA scan")
	analyzeCmd.Flags().BoolVar(&analyzeIOCs, "iocs", false, "Extract IOCs from strings")
	analyzeCmd.Flags().IntVar(&analyzeMinStrLen, "min-string-len", 4, "Minimum string length to extract")
	analyzeCmd.Flags().IntVar(&analyzeMaxStrings, "max-strings", 10000, "Maximum strings to extract")
	rootCmd.AddCommand(analyzeCmd)
}

func runAnalyze(cmd *cobra.Command, args []string) error {
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
		IncludeStrings:  analyzeStrings,
		MinStringLength: analyzeMinStrLen,
		MaxStrings:      analyzeMaxStrings,
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
	if analyzeYARA {
		if verbose {
			fmt.Fprintf(os.Stderr, "Running YARA scan...\n")
		}
		scanner := yara.NewScanner()
		yaraResult, err := scanner.Scan(ctx, binaryPath)
		if err != nil {
			result.AddError(fmt.Sprintf("YARA scan failed: %v", err))
		} else {
			result.YARA = yaraResult
		}
	}

	// Extract IOCs if enabled
	var iocResult *model.IOCResult
	if analyzeIOCs && len(result.Strings) > 0 {
		if verbose {
			fmt.Fprintf(os.Stderr, "Extracting IOCs...\n")
		}
		extractor := ioc.NewExtractor()
		iocResult = extractor.ExtractFromStrings(result.Strings)
	}

	// Output results
	if analyzeIOCs {
		report := &AnalyzeReport{
			Analysis: result,
			IOCs:     iocResult,
		}
		return outputResults(report)
	}
	return outputResults(result)
}

func outputResults(result any) error {
	switch outputFormat {
	case "json":
		writer := output.NewJSONWriter(true)
		return writer.Write(os.Stdout, result)
	case "md":
		// For AnalysisResult, use markdown writer
		if ar, ok := result.(*model.AnalysisResult); ok {
			writer := output.NewMarkdownWriter()
			return writer.Write(os.Stdout, ar)
		}
		// For AnalyzeReport, use markdown for analysis part
		if rpt, ok := result.(*AnalyzeReport); ok {
			writer := output.NewMarkdownWriter()
			return writer.Write(os.Stdout, rpt.Analysis)
		}
		// Fall back to JSON for other types
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	default:
		return fmt.Errorf("unknown output format: %s", outputFormat)
	}
}
