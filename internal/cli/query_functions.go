package cli

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	funcName    string
	funcAddress int64
	funcLimit   int
)

var queryFunctionsCmd = &cobra.Command{
	Use:   "functions <binary>",
	Short: "List functions",
	Long:  "List functions in the binary. Requires deep analysis (--deep flag on first query).",
	Args:  cobra.ExactArgs(1),
	RunE:  runQueryFunctions,
}

var queryFunctionCmd = &cobra.Command{
	Use:   "function <binary> <name_or_address>",
	Short: "Get function details",
	Long:  "Get detailed information about a specific function by name or address.",
	Args:  cobra.ExactArgs(2),
	RunE:  runQueryFunction,
}

func init() {
	queryFunctionsCmd.Flags().StringVar(&funcName, "name", "", "Filter by function name (substring match)")
	queryFunctionsCmd.Flags().Int64Var(&funcAddress, "address", 0, "Filter by function address")
	queryFunctionsCmd.Flags().IntVar(&funcLimit, "limit", 100, "Maximum number of results")
	queryCmd.AddCommand(queryFunctionsCmd)
	queryCmd.AddCommand(queryFunctionCmd)
}

type FunctionsOutput struct {
	Functions []FunctionInfo `json:"functions"`
	Count     int            `json:"count"`
	HasDeep   bool           `json:"has_deep_analysis"`
}

type FunctionInfo struct {
	Name       string `json:"name"`
	Address    string `json:"address"`
	Size       uint64 `json:"size"`
	Signature  string `json:"signature,omitempty"`
	IsExternal bool   `json:"is_external"`
	IsThunk    bool   `json:"is_thunk"`
}

type FunctionDetailOutput struct {
	Function FunctionInfo   `json:"function"`
	Callers  []FunctionRef  `json:"callers,omitempty"`
	Callees  []FunctionRef  `json:"callees,omitempty"`
	Found    bool           `json:"found"`
}

type FunctionRef struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

func runQueryFunctions(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	binaryPath := args[0]
	absPath, err := filepath.Abs(binaryPath)
	if err != nil {
		return err
	}

	mgr, db, _, err := ensureAnalyzed(ctx, absPath, queryDeep)
	if err != nil {
		return err
	}
	defer db.Close()

	meta, err := mgr.LoadMetadata(absPath)
	if err != nil {
		return fmt.Errorf("load metadata: %w", err)
	}

	functions, err := db.QueryFunctions(funcName, funcAddress, funcLimit)
	if err != nil {
		return err
	}

	output := FunctionsOutput{
		Functions: make([]FunctionInfo, 0, len(functions)),
		Count:     len(functions),
		HasDeep:   meta.DeepAnalysis,
	}

	for _, f := range functions {
		output.Functions = append(output.Functions, FunctionInfo{
			Name:       f.Name,
			Address:    formatAddress(int64(f.Address)),
			Size:       f.Size,
			Signature:  f.Signature,
			IsExternal: f.IsExternal,
			IsThunk:    f.IsThunk,
		})
	}

	if outputFormat == "json" {
		outputJSON(output)
	} else {
		printFunctionsMarkdown(output)
	}

	return nil
}

func runQueryFunction(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	binaryPath := args[0]
	absPath, err := filepath.Abs(binaryPath)
	if err != nil {
		return err
	}

	nameOrAddr := args[1]

	_, db, _, err := ensureAnalyzed(ctx, absPath, queryDeep)
	if err != nil {
		return err
	}
	defer db.Close()

	f, err := db.GetFunction(nameOrAddr)
	if err != nil {
		return err
	}

	if f == nil {
		output := FunctionDetailOutput{Found: false}
		if outputFormat == "json" {
			outputJSON(output)
		} else {
			fmt.Printf("Function not found: %s\n", nameOrAddr)
		}
		return nil
	}

	// Get callers and callees
	callers, _ := db.GetCallers(int64(f.Address))
	callees, _ := db.GetCallees(int64(f.Address))

	output := FunctionDetailOutput{
		Found: true,
		Function: FunctionInfo{
			Name:       f.Name,
			Address:    formatAddress(int64(f.Address)),
			Size:       f.Size,
			Signature:  f.Signature,
			IsExternal: f.IsExternal,
			IsThunk:    f.IsThunk,
		},
		Callers: make([]FunctionRef, 0, len(callers)),
		Callees: make([]FunctionRef, 0, len(callees)),
	}

	for _, c := range callers {
		output.Callers = append(output.Callers, FunctionRef{
			Name:    c.Name,
			Address: formatAddress(int64(c.Address)),
		})
	}

	for _, c := range callees {
		output.Callees = append(output.Callees, FunctionRef{
			Name:    c.Name,
			Address: formatAddress(int64(c.Address)),
		})
	}

	if outputFormat == "json" {
		outputJSON(output)
	} else {
		printFunctionDetailMarkdown(output)
	}

	return nil
}

func printFunctionsMarkdown(f FunctionsOutput) {
	fmt.Printf("# Functions (%d)\n\n", f.Count)

	if !f.HasDeep {
		fmt.Println("_Note: Deep analysis not performed. Run with --deep flag for function details._")
		fmt.Println()
	}

	if f.Count == 0 {
		fmt.Println("No functions found.")
		return
	}

	fmt.Println("| Name | Address | Size | Type |")
	fmt.Println("|------|---------|------|------|")
	for _, fn := range f.Functions {
		typeStr := ""
		if fn.IsExternal {
			typeStr = "external"
		} else if fn.IsThunk {
			typeStr = "thunk"
		}
		fmt.Printf("| %s | %s | %d | %s |\n", fn.Name, fn.Address, fn.Size, typeStr)
	}
}

func printFunctionDetailMarkdown(f FunctionDetailOutput) {
	fn := f.Function
	fmt.Printf("# Function: %s\n\n", fn.Name)
	fmt.Printf("**Address:** %s\n", fn.Address)
	fmt.Printf("**Size:** %d bytes\n", fn.Size)
	if fn.Signature != "" {
		fmt.Printf("**Signature:** `%s`\n", fn.Signature)
	}
	if fn.IsExternal {
		fmt.Println("**Type:** External")
	} else if fn.IsThunk {
		fmt.Println("**Type:** Thunk")
	}

	if len(f.Callers) > 0 {
		fmt.Printf("\n## Callers (%d)\n", len(f.Callers))
		for _, c := range f.Callers {
			fmt.Printf("- %s @ %s\n", c.Name, c.Address)
		}
	}

	if len(f.Callees) > 0 {
		fmt.Printf("\n## Callees (%d)\n", len(f.Callees))
		for _, c := range f.Callees {
			fmt.Printf("- %s @ %s\n", c.Name, c.Address)
		}
	}
}
