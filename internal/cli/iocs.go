package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/refractionPOINT/lcre/internal/backend"
	_ "github.com/refractionPOINT/lcre/internal/backend/native"
	"github.com/refractionPOINT/lcre/internal/ioc"
	"github.com/refractionPOINT/lcre/internal/output"
)

var iocsCmd = &cobra.Command{
	Use:   "iocs <binary>",
	Short: "Extract indicators of compromise from a binary",
	Long: `Extracts potential indicators of compromise (IOCs) from binary strings.

This includes:
- URLs and domains
- IP addresses
- File paths (Windows/Linux/macOS)
- Registry keys
- Email addresses`,
	Args: cobra.ExactArgs(1),
	RunE: runIOCs,
}

func init() {
	rootCmd.AddCommand(iocsCmd)
}

func runIOCs(cmd *cobra.Command, args []string) error {
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

	// Configure analysis options - we need strings
	opts := backend.AnalysisOptions{
		Timeout:         timeout,
		IncludeStrings:  true,
		MinStringLength: 4,
		MaxStrings:      50000, // Extract more strings for IOC analysis
	}

	// Run analysis
	if verbose {
		fmt.Fprintf(os.Stderr, "Extracting strings from %s...\n", binaryPath)
	}

	result, err := b.Analyze(ctx, binaryPath, opts)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	// Extract IOCs from strings
	if verbose {
		fmt.Fprintf(os.Stderr, "Searching for IOCs in %d strings...\n", len(result.Strings))
	}

	extractor := ioc.NewExtractor()
	iocResult := extractor.ExtractFromStrings(result.Strings)

	// Output results
	switch outputFormat {
	case "json":
		writer := output.NewJSONWriter(true)
		return writer.Write(os.Stdout, iocResult)
	case "md":
		writer := output.NewMarkdownWriter()
		return writer.WriteIOCs(os.Stdout, iocResult)
	default:
		return fmt.Errorf("unknown output format: %s", outputFormat)
	}
}
