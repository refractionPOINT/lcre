package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var enrichmentsCmd = &cobra.Command{
	Use:   "enrichments <binary>",
	Short: "List external tool enrichments",
	Long: `List all external tool enrichments stored for a binary.
Shows which tools have been imported and when.`,
	Args: cobra.ExactArgs(1),
	RunE: runQueryEnrichments,
}

var enrichmentCmd = &cobra.Command{
	Use:   "enrichment <binary> <tool>",
	Short: "Show raw output from an external tool enrichment",
	Long: `Retrieve the raw JSON output from a specific tool enrichment.
Use 'lcre query enrichments' to see available tools.`,
	Args: cobra.ExactArgs(2),
	RunE: runQueryEnrichment,
}

func init() {
	queryCmd.AddCommand(enrichmentsCmd)
	queryCmd.AddCommand(enrichmentCmd)
}

func runQueryEnrichments(cmd *cobra.Command, args []string) error {
	binaryPath := args[0]
	if err := validateBinaryPath(binaryPath); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	_, db, _, err := ensureAnalyzed(ctx, binaryPath, false)
	if err != nil {
		return err
	}
	defer db.Close()

	enrichments, err := db.QueryEnrichments("")
	if err != nil {
		return err
	}

	if len(enrichments) == 0 {
		fmt.Fprintln(os.Stdout, "No enrichments found. Use 'lcre enrich' to import tool output.")
		return nil
	}

	switch outputFormat {
	case "json":
		return outputJSON2(enrichments)
	default:
		fmt.Fprintln(os.Stdout, "# Enrichments")
		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, "| Tool | Timestamp | Data Size |")
		fmt.Fprintln(os.Stdout, "|------|-----------|-----------|")
		for _, e := range enrichments {
			fmt.Fprintf(os.Stdout, "| %s | %s | %s |\n",
				e.Tool,
				e.Timestamp.Format("2006-01-02 15:04:05"),
				humanSize(len(e.RawOutput)),
			)
		}
		return nil
	}
}

func runQueryEnrichment(cmd *cobra.Command, args []string) error {
	binaryPath := args[0]
	toolName := strings.ToLower(args[1])

	if err := validateBinaryPath(binaryPath); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	_, db, _, err := ensureAnalyzed(ctx, binaryPath, false)
	if err != nil {
		return err
	}
	defer db.Close()

	enrichments, err := db.QueryEnrichments(toolName)
	if err != nil {
		return err
	}

	if len(enrichments) == 0 {
		return fmt.Errorf("no enrichment found for tool: %s", toolName)
	}

	// Output the raw JSON, pretty-printed
	var raw interface{}
	if err := json.Unmarshal([]byte(enrichments[0].RawOutput), &raw); err != nil {
		// Not valid JSON — print as-is
		fmt.Fprintln(os.Stdout, enrichments[0].RawOutput)
		return nil
	}

	data, _ := json.MarshalIndent(raw, "", "  ")
	fmt.Fprintln(os.Stdout, string(data))
	return nil
}

func outputJSON2(v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func humanSize(bytes int) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
}
