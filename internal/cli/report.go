package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/refractionPOINT/lcre/internal/backend"
	_ "github.com/refractionPOINT/lcre/internal/backend/native"
	"github.com/refractionPOINT/lcre/internal/ioc"
	"github.com/refractionPOINT/lcre/internal/model"
	"github.com/refractionPOINT/lcre/internal/output"
	"github.com/refractionPOINT/lcre/internal/yara"
)

// FullReport contains all analysis results
type FullReport struct {
	Analysis   *model.AnalysisResult `json:"analysis"`
	IOCs       *model.IOCResult      `json:"iocs"`
}

var reportCmd = &cobra.Command{
	Use:   "report <binary>",
	Short: "Generate a comprehensive analysis report",
	Long: `Generates a comprehensive analysis report including:
- Full binary metadata and hashes
- Section analysis with entropy
- Import/export tables
- Extracted strings
- YARA scan results
- IOC extraction`,
	Args: cobra.ExactArgs(1),
	RunE: runReport,
}

func init() {
	rootCmd.AddCommand(reportCmd)
}

func runReport(cmd *cobra.Command, args []string) error {
	binaryPath := args[0]

	if err := validateBinaryPath(binaryPath); err != nil {
		return err
	}

	// Get the native backend
	b, err := backend.DefaultRegistry.Get("native")
	if err != nil {
		return fmt.Errorf("native backend not available: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	opts := backend.AnalysisOptions{
		Timeout:         timeout,
		IncludeStrings:  true,
		MinStringLength: 4,
		MaxStrings:      50000,
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Analyzing %s...\n", binaryPath)
	}

	result, err := b.Analyze(ctx, binaryPath, opts)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	// Run YARA scan
	if verbose {
		fmt.Fprintf(os.Stderr, "Running YARA scan...\n")
	}
	scanner := yara.NewScanner()
	yaraResult, scanErr := scanner.Scan(ctx, binaryPath)
	if scanErr != nil {
		result.AddError(fmt.Sprintf("YARA scan failed: %v", scanErr))
	} else {
		result.YARA = yaraResult
	}

	// Extract IOCs
	if verbose {
		fmt.Fprintf(os.Stderr, "Extracting IOCs...\n")
	}
	extractor := ioc.NewExtractor()
	iocResult := extractor.ExtractFromStrings(result.Strings)

	report := &FullReport{
		Analysis: result,
		IOCs:     iocResult,
	}

	// Output results
	switch outputFormat {
	case "json":
		writer := output.NewJSONWriter(true)
		return writer.Write(os.Stdout, report)
	case "md":
		writer := output.NewMarkdownWriter()
		return writer.Write(os.Stdout, result)
	default:
		return fmt.Errorf("unknown output format: %s", outputFormat)
	}
}
