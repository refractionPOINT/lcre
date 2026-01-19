package cli

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
)

var queryDecompileCmd = &cobra.Command{
	Use:   "decompile <binary> <function>",
	Short: "Decompile a function",
	Long: `Get the decompiled pseudocode for a function.
Automatically triggers Ghidra analysis on first query.`,
	Args: cobra.ExactArgs(2),
	RunE: runQueryDecompile,
}

func init() {
	queryCmd.AddCommand(queryDecompileCmd)
}

type DecompileOutput struct {
	Function   string `json:"function"`
	Address    string `json:"address"`
	Decompiled string `json:"decompiled"`
	Found      bool   `json:"found"`
	Available  bool   `json:"available"`
}

func runQueryDecompile(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	binaryPath := args[0]
	absPath, err := filepath.Abs(binaryPath)
	if err != nil {
		return err
	}

	funcNameOrAddr := args[1]

	// Force deep analysis for decompilation
	mgr, db, _, err := ensureAnalyzed(ctx, absPath, true)
	if err != nil {
		return err
	}
	defer db.Close()

	// Get the function
	f, err := db.GetFunction(funcNameOrAddr)
	if err != nil {
		return err
	}
	if f == nil {
		output := DecompileOutput{
			Function:  funcNameOrAddr,
			Found:     false,
			Available: false,
		}
		if outputFormat == "json" {
			outputJSON(output)
		} else {
			fmt.Printf("Function not found: %s\n", funcNameOrAddr)
		}
		return nil
	}

	// Check for cached decompilation
	decompiled, err := mgr.LoadDecompiledFunction(absPath, f.Name)
	if err != nil {
		return err
	}

	if decompiled == "" {
		// Try by address as well
		decompiled, _ = mgr.LoadDecompiledFunction(absPath, formatAddress(int64(f.Address)))
	}

	output := DecompileOutput{
		Function:   f.Name,
		Address:    formatAddress(int64(f.Address)),
		Decompiled: decompiled,
		Found:      true,
		Available:  decompiled != "",
	}

	if outputFormat == "json" {
		outputJSON(output)
	} else {
		if decompiled == "" {
			fmt.Printf("# Function: %s @ %s\n\n", f.Name, output.Address)
			fmt.Println("Decompiled code not available.")
			fmt.Println("Decompilation requires Ghidra to be installed and available.")
		} else {
			fmt.Printf("# Function: %s @ %s\n\n", f.Name, output.Address)
			fmt.Println("```c")
			fmt.Println(decompiled)
			fmt.Println("```")
		}
	}

	return nil
}
