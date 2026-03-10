package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var packerTypeFilter string

var packerCmd = &cobra.Command{
	Use:   "packer <binary>",
	Short: "Show packer/compiler detections (from diec enrichment)",
	Long: `Display packer, compiler, and linker detections from Detect It Easy or similar tools.
Requires prior enrichment: lcre enrich <binary> --tool diec --input <file>`,
	Args: cobra.ExactArgs(1),
	RunE: runQueryPacker,
}

func init() {
	packerCmd.Flags().StringVar(&packerTypeFilter, "type", "", "Filter by detection type (compiler, packer, linker, protector)")
	queryCmd.AddCommand(packerCmd)
}

func runQueryPacker(cmd *cobra.Command, args []string) error {
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

	detections, err := db.QueryPackerDetections(packerTypeFilter)
	if err != nil {
		return err
	}

	if len(detections) == 0 {
		fmt.Fprintln(os.Stdout, "No packer/compiler detections found. Enrich with diec first:")
		fmt.Fprintln(os.Stdout, "  lcre enrich <binary> --tool diec --input <diec_output.json>")
		return nil
	}

	switch outputFormat {
	case "json":
		data, _ := json.MarshalIndent(detections, "", "  ")
		fmt.Println(string(data))
		return nil
	default:
		fmt.Fprintf(os.Stdout, "# Packer/Compiler Detections (%d)\n\n", len(detections))
		fmt.Fprintln(os.Stdout, "| Type | Name | Version | Detail |")
		fmt.Fprintln(os.Stdout, "|------|------|---------|--------|")
		for _, d := range detections {
			version := d.Version
			if version == "" {
				version = "-"
			}
			detail := d.String
			if detail == "" {
				detail = "-"
			}
			fmt.Fprintf(os.Stdout, "| %s | %s | %s | %s |\n",
				d.Type, d.Name, version, detail)
		}
		return nil
	}
}
