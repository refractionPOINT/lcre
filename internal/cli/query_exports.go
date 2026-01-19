package cli

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	exportName string
)

var queryExportsCmd = &cobra.Command{
	Use:   "exports <binary>",
	Short: "List exports",
	Long:  "List exported functions from the binary, optionally filtered by name.",
	Args:  cobra.ExactArgs(1),
	RunE:  runQueryExports,
}

func init() {
	queryExportsCmd.Flags().StringVar(&exportName, "name", "", "Filter by export name (substring match)")
	queryCmd.AddCommand(queryExportsCmd)
}

type ExportsOutput struct {
	Exports []ExportInfo `json:"exports"`
	Count   int          `json:"count"`
}

type ExportInfo struct {
	Name    string `json:"name"`
	Ordinal int    `json:"ordinal,omitempty"`
	Address string `json:"address"`
}

func runQueryExports(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	binaryPath := args[0]
	absPath, err := filepath.Abs(binaryPath)
	if err != nil {
		return err
	}

	_, db, _, err := ensureAnalyzed(ctx, absPath, false)
	if err != nil {
		return err
	}
	defer db.Close()

	exports, err := db.QueryExports(exportName)
	if err != nil {
		return err
	}

	output := ExportsOutput{
		Exports: make([]ExportInfo, 0, len(exports)),
		Count:   len(exports),
	}

	for _, exp := range exports {
		output.Exports = append(output.Exports, ExportInfo{
			Name:    exp.Name,
			Ordinal: exp.Ordinal,
			Address: formatAddress(int64(exp.Address)),
		})
	}

	if outputFormat == "json" {
		outputJSON(output)
	} else {
		printExportsMarkdown(output)
	}

	return nil
}

func printExportsMarkdown(e ExportsOutput) {
	fmt.Printf("# Exports (%d)\n\n", e.Count)
	if e.Count == 0 {
		fmt.Println("No exports found.")
		return
	}

	fmt.Println("| Name | Ordinal | Address |")
	fmt.Println("|------|---------|---------|")
	for _, exp := range e.Exports {
		fmt.Printf("| %s | %d | %s |\n", exp.Name, exp.Ordinal, exp.Address)
	}
}
