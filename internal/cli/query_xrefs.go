package cli

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
)

var queryXrefsToCmd = &cobra.Command{
	Use:   "xrefs-to <binary> <address>",
	Short: "Find references to address",
	Long:  "Find all cross-references pointing to the specified address.",
	Args:  cobra.ExactArgs(2),
	RunE:  runQueryXrefsTo,
}

var queryXrefsFromCmd = &cobra.Command{
	Use:   "xrefs-from <binary> <address>",
	Short: "Find references from address",
	Long:  "Find all cross-references originating from the specified address.",
	Args:  cobra.ExactArgs(2),
	RunE:  runQueryXrefsFrom,
}

var queryCallersCmd = &cobra.Command{
	Use:   "callers <binary> <function>",
	Short: "Find function callers",
	Long:  "Find all functions that call the specified function.",
	Args:  cobra.ExactArgs(2),
	RunE:  runQueryCallers,
}

var queryCalleesCmd = &cobra.Command{
	Use:   "callees <binary> <function>",
	Short: "Find function callees",
	Long:  "Find all functions called by the specified function.",
	Args:  cobra.ExactArgs(2),
	RunE:  runQueryCallees,
}

func init() {
	queryCmd.AddCommand(queryXrefsToCmd)
	queryCmd.AddCommand(queryXrefsFromCmd)
	queryCmd.AddCommand(queryCallersCmd)
	queryCmd.AddCommand(queryCalleesCmd)
}

type XrefsOutput struct {
	Address    string     `json:"address"`
	Direction  string     `json:"direction"`
	References []XrefInfo `json:"references"`
	Count      int        `json:"count"`
}

type XrefInfo struct {
	From     string `json:"from"`
	To       string `json:"to"`
	FromFunc string `json:"from_function,omitempty"`
	Type     string `json:"type,omitempty"`
}

type CallersOutput struct {
	Function string        `json:"function"`
	Callers  []FunctionRef `json:"callers"`
	Count    int           `json:"count"`
}

type CalleesOutput struct {
	Function string        `json:"function"`
	Callees  []FunctionRef `json:"callees"`
	Count    int           `json:"count"`
}

func runQueryXrefsTo(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	binaryPath := args[0]
	absPath, err := filepath.Abs(binaryPath)
	if err != nil {
		return err
	}

	address := parseAddressArg(args[1])

	_, db, _, err := ensureAnalyzed(ctx, absPath, queryDeep)
	if err != nil {
		return err
	}
	defer db.Close()

	xrefs, err := db.GetXrefsTo(address)
	if err != nil {
		return err
	}

	output := XrefsOutput{
		Address:    formatAddress(address),
		Direction:  "to",
		References: make([]XrefInfo, 0, len(xrefs)),
		Count:      len(xrefs),
	}

	for _, x := range xrefs {
		output.References = append(output.References, XrefInfo{
			From:     formatAddress(x.From),
			To:       formatAddress(x.To),
			FromFunc: x.FromFunc,
			Type:     x.Type,
		})
	}

	if outputFormat == "json" {
		outputJSON(output)
	} else {
		fmt.Printf("# References TO %s (%d)\n\n", output.Address, output.Count)
		if output.Count == 0 {
			fmt.Println("No references found.")
		} else {
			for _, ref := range output.References {
				fmt.Printf("- %s", ref.From)
				if ref.FromFunc != "" {
					fmt.Printf(" (%s)", ref.FromFunc)
				}
				if ref.Type != "" {
					fmt.Printf(" [%s]", ref.Type)
				}
				fmt.Println()
			}
		}
	}

	return nil
}

func runQueryXrefsFrom(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	binaryPath := args[0]
	absPath, err := filepath.Abs(binaryPath)
	if err != nil {
		return err
	}

	address := parseAddressArg(args[1])

	_, db, _, err := ensureAnalyzed(ctx, absPath, queryDeep)
	if err != nil {
		return err
	}
	defer db.Close()

	xrefs, err := db.GetXrefsFrom(address)
	if err != nil {
		return err
	}

	output := XrefsOutput{
		Address:    formatAddress(address),
		Direction:  "from",
		References: make([]XrefInfo, 0, len(xrefs)),
		Count:      len(xrefs),
	}

	for _, x := range xrefs {
		output.References = append(output.References, XrefInfo{
			From: formatAddress(x.From),
			To:   formatAddress(x.To),
			Type: x.Type,
		})
	}

	if outputFormat == "json" {
		outputJSON(output)
	} else {
		fmt.Printf("# References FROM %s (%d)\n\n", output.Address, output.Count)
		if output.Count == 0 {
			fmt.Println("No references found.")
		} else {
			for _, ref := range output.References {
				fmt.Printf("- -> %s", ref.To)
				if ref.Type != "" {
					fmt.Printf(" [%s]", ref.Type)
				}
				fmt.Println()
			}
		}
	}

	return nil
}

func runQueryCallers(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	binaryPath := args[0]
	absPath, err := filepath.Abs(binaryPath)
	if err != nil {
		return err
	}

	funcNameOrAddr := args[1]

	_, db, _, err := ensureAnalyzed(ctx, absPath, queryDeep)
	if err != nil {
		return err
	}
	defer db.Close()

	// Get the function first
	f, err := db.GetFunction(funcNameOrAddr)
	if err != nil {
		return err
	}
	if f == nil {
		if outputFormat == "json" {
			fmt.Printf(`{"error": "function not found: %s"}`+"\n", funcNameOrAddr)
		} else {
			fmt.Printf("Function not found: %s\n", funcNameOrAddr)
		}
		return nil
	}

	callers, err := db.GetCallers(int64(f.Address))
	if err != nil {
		return err
	}

	output := CallersOutput{
		Function: f.Name,
		Callers:  make([]FunctionRef, 0, len(callers)),
		Count:    len(callers),
	}

	for _, c := range callers {
		output.Callers = append(output.Callers, FunctionRef{
			Name:    c.Name,
			Address: formatAddress(int64(c.Address)),
		})
	}

	if outputFormat == "json" {
		outputJSON(output)
	} else {
		fmt.Printf("# Callers of %s (%d)\n\n", output.Function, output.Count)
		if output.Count == 0 {
			fmt.Println("No callers found.")
		} else {
			for _, c := range output.Callers {
				fmt.Printf("- %s @ %s\n", c.Name, c.Address)
			}
		}
	}

	return nil
}

func runQueryCallees(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	binaryPath := args[0]
	absPath, err := filepath.Abs(binaryPath)
	if err != nil {
		return err
	}

	funcNameOrAddr := args[1]

	_, db, _, err := ensureAnalyzed(ctx, absPath, queryDeep)
	if err != nil {
		return err
	}
	defer db.Close()

	// Get the function first
	f, err := db.GetFunction(funcNameOrAddr)
	if err != nil {
		return err
	}
	if f == nil {
		if outputFormat == "json" {
			fmt.Printf(`{"error": "function not found: %s"}`+"\n", funcNameOrAddr)
		} else {
			fmt.Printf("Function not found: %s\n", funcNameOrAddr)
		}
		return nil
	}

	callees, err := db.GetCallees(int64(f.Address))
	if err != nil {
		return err
	}

	output := CalleesOutput{
		Function: f.Name,
		Callees:  make([]FunctionRef, 0, len(callees)),
		Count:    len(callees),
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
		fmt.Printf("# Callees of %s (%d)\n\n", output.Function, output.Count)
		if output.Count == 0 {
			fmt.Println("No callees found.")
		} else {
			for _, c := range output.Callees {
				fmt.Printf("- %s @ %s\n", c.Name, c.Address)
			}
		}
	}

	return nil
}
