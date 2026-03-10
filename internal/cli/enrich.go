package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/refractionPOINT/lcre/internal/cache"
	"github.com/refractionPOINT/lcre/internal/enrichment"
	_ "github.com/refractionPOINT/lcre/internal/enrichment" // register parsers
	"github.com/refractionPOINT/lcre/internal/model"
)

var (
	enrichTool  string
	enrichInput string
)

var enrichCmd = &cobra.Command{
	Use:   "enrich <binary>",
	Short: "Import external tool output into the analysis cache",
	Long: `Import output from external analysis tools (e.g., capa, diec, floss) into
the cached analysis for a binary.

This enables agent-mediated workflows where an AI agent runs tools on a
remote system (e.g., REMnux MCP) and feeds results back into LCRE.

Tools with dedicated parsers (capa, diec, floss) extract structured data
into queryable tables. Unknown tools have their raw JSON preserved and
can be retrieved via 'lcre query enrichment'.

Examples:
  lcre enrich sample.exe --tool capa --input capa_output.json
  lcre enrich sample.exe --tool diec --input diec_output.json
  lcre enrich sample.exe --tool floss --input floss_output.json
  lcre enrich sample.exe --tool peframe --input peframe_output.json`,
	Args: cobra.ExactArgs(1),
	RunE: runEnrich,
}

func init() {
	enrichCmd.Flags().StringVar(&enrichTool, "tool", "", "Tool name (e.g., capa, diec, floss)")
	enrichCmd.Flags().StringVar(&enrichInput, "input", "", "Path to tool output JSON file")
	enrichCmd.MarkFlagRequired("tool")
	enrichCmd.MarkFlagRequired("input")
	rootCmd.AddCommand(enrichCmd)
}

func runEnrich(cmd *cobra.Command, args []string) error {
	binaryPath := args[0]

	if err := validateBinaryPath(binaryPath); err != nil {
		return err
	}

	if _, err := os.Stat(enrichInput); err != nil {
		return fmt.Errorf("input file not found: %s", enrichInput)
	}

	// Ensure the binary has been analyzed first
	mgr, err := cache.NewManager()
	if err != nil {
		return err
	}

	exists, err := mgr.Exists(binaryPath)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("binary not yet analyzed. Run 'lcre analyze %s' first", binaryPath)
	}

	// Parse tool output
	toolName := strings.ToLower(enrichTool)
	if verbose {
		parser := enrichment.GetParser(toolName)
		if parser != nil {
			fmt.Fprintf(os.Stderr, "Parsing %s output with dedicated parser...\n", toolName)
		} else {
			fmt.Fprintf(os.Stderr, "No dedicated parser for %s, storing raw JSON...\n", toolName)
		}
	}

	result, err := enrichment.ParseToolOutput(toolName, enrichInput)
	if err != nil {
		return fmt.Errorf("failed to parse tool output: %w", err)
	}

	// Open cache and store results
	db, err := mgr.Open(binaryPath)
	if err != nil {
		return err
	}
	defer db.Close()

	// Clear previous enrichment for this tool
	if err := db.ClearEnrichment(toolName); err != nil {
		return fmt.Errorf("failed to clear previous enrichment: %w", err)
	}

	// Store raw enrichment
	if err := db.InsertEnrichment(model.Enrichment{
		Tool:      toolName,
		Timestamp: time.Now(),
		RawOutput: result.RawJSON,
	}); err != nil {
		return fmt.Errorf("failed to store enrichment: %w", err)
	}

	// Store structured data
	stored := []string{}

	if len(result.Capabilities) > 0 {
		if err := db.InsertCapabilities(result.Capabilities); err != nil {
			return fmt.Errorf("failed to store capabilities: %w", err)
		}
		stored = append(stored, fmt.Sprintf("%d capabilities", len(result.Capabilities)))
	}

	if len(result.Detections) > 0 {
		if err := db.InsertPackerDetections(result.Detections); err != nil {
			return fmt.Errorf("failed to store detections: %w", err)
		}
		stored = append(stored, fmt.Sprintf("%d packer/compiler detections", len(result.Detections)))
	}

	if len(result.Strings) > 0 {
		if err := db.InsertStrings(result.Strings); err != nil {
			return fmt.Errorf("failed to store strings: %w", err)
		}
		stored = append(stored, fmt.Sprintf("%d strings", len(result.Strings)))
	}

	// Summary
	if len(stored) > 0 {
		fmt.Fprintf(os.Stdout, "Enriched with %s: %s\n", toolName, strings.Join(stored, ", "))
	} else {
		fmt.Fprintf(os.Stdout, "Enriched with %s: raw JSON stored\n", toolName)
	}

	return nil
}
