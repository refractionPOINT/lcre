package cli

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	importLibrary  string
	importFunction string
)

var queryImportsCmd = &cobra.Command{
	Use:   "imports <binary>",
	Short: "List imports",
	Long:  "List imported functions from the binary, optionally filtered by library or function name.",
	Args:  cobra.ExactArgs(1),
	RunE:  runQueryImports,
}

func init() {
	queryImportsCmd.Flags().StringVar(&importLibrary, "library", "", "Filter by library name (substring match)")
	queryImportsCmd.Flags().StringVar(&importFunction, "function", "", "Filter by function name (substring match)")
	queryCmd.AddCommand(queryImportsCmd)
}

type ImportsOutput struct {
	Imports []ImportInfo `json:"imports"`
	Count   int          `json:"count"`
}

type ImportInfo struct {
	Library  string `json:"library"`
	Function string `json:"function"`
	Ordinal  int    `json:"ordinal,omitempty"`
	Address  string `json:"address,omitempty"`
}

func runQueryImports(cmd *cobra.Command, args []string) error {
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

	imports, err := db.QueryImports(importLibrary, importFunction)
	if err != nil {
		return err
	}

	output := ImportsOutput{
		Imports: make([]ImportInfo, 0, len(imports)),
		Count:   len(imports),
	}

	for _, imp := range imports {
		info := ImportInfo{
			Library:  imp.Library,
			Function: imp.Function,
			Ordinal:  imp.Ordinal,
		}
		if imp.Address > 0 {
			info.Address = formatAddress(int64(imp.Address))
		}
		output.Imports = append(output.Imports, info)
	}

	if outputFormat == "json" {
		outputJSON(output)
	} else {
		printImportsMarkdown(output)
	}

	return nil
}

func printImportsMarkdown(i ImportsOutput) {
	fmt.Printf("# Imports (%d)\n\n", i.Count)
	if i.Count == 0 {
		fmt.Println("No imports found.")
		return
	}

	// Group by library
	byLibrary := make(map[string][]ImportInfo)
	for _, imp := range i.Imports {
		byLibrary[imp.Library] = append(byLibrary[imp.Library], imp)
	}

	for lib, funcs := range byLibrary {
		fmt.Printf("## %s\n", lib)
		for _, f := range funcs {
			if f.Address != "" {
				fmt.Printf("- %s @ %s\n", f.Function, f.Address)
			} else {
				fmt.Printf("- %s\n", f.Function)
			}
		}
		fmt.Println()
	}
}
