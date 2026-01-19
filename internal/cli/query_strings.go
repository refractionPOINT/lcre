package cli

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	stringPattern string
	stringAt      int64
	stringLimit   int
	stringOffset  int
)

var queryStringsCmd = &cobra.Command{
	Use:   "strings <binary>",
	Short: "Search strings",
	Long:  "Search and list strings extracted from the binary.",
	Args:  cobra.ExactArgs(1),
	RunE:  runQueryStrings,
}

func init() {
	queryStringsCmd.Flags().StringVar(&stringPattern, "pattern", "", "Search pattern (substring match)")
	queryStringsCmd.Flags().Int64Var(&stringAt, "at", 0, "Get string at specific offset")
	queryStringsCmd.Flags().IntVar(&stringLimit, "limit", 100, "Maximum number of results")
	queryStringsCmd.Flags().IntVar(&stringOffset, "offset", 0, "Skip first N results (for pagination)")
	queryCmd.AddCommand(queryStringsCmd)
}

type StringsOutput struct {
	Strings   []StringInfo `json:"strings"`
	Count     int          `json:"count"`
	Total     int          `json:"total"`
	Truncated bool         `json:"truncated"`
}

type StringInfo struct {
	Value    string `json:"value"`
	Offset   string `json:"offset"`
	Section  string `json:"section,omitempty"`
	Encoding string `json:"encoding"`
}

func runQueryStrings(cmd *cobra.Command, args []string) error {
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

	// Handle --at flag for specific offset lookup
	if stringAt > 0 {
		str, err := db.GetStringAt(stringAt)
		if err != nil {
			return err
		}
		if str == nil {
			if outputFormat == "json" {
				fmt.Println(`{"found": false}`)
			} else {
				fmt.Printf("No string found at offset 0x%x\n", stringAt)
			}
			return nil
		}

		output := struct {
			Found  bool       `json:"found"`
			String StringInfo `json:"string"`
		}{
			Found: true,
			String: StringInfo{
				Value:    str.Value,
				Offset:   formatAddress(int64(str.Offset)),
				Section:  str.Section,
				Encoding: str.Encoding,
			},
		}

		if outputFormat == "json" {
			outputJSON(output)
		} else {
			fmt.Printf("String at 0x%x: %q\n", str.Offset, str.Value)
			if str.Section != "" {
				fmt.Printf("  Section: %s\n", str.Section)
			}
			fmt.Printf("  Encoding: %s\n", str.Encoding)
		}
		return nil
	}

	// Regular string search
	strings, total, err := db.QueryStrings(stringPattern, stringLimit, stringOffset)
	if err != nil {
		return err
	}

	output := StringsOutput{
		Strings:   make([]StringInfo, 0, len(strings)),
		Count:     len(strings),
		Total:     total,
		Truncated: total > stringOffset+len(strings),
	}

	for _, s := range strings {
		output.Strings = append(output.Strings, StringInfo{
			Value:    s.Value,
			Offset:   formatAddress(int64(s.Offset)),
			Section:  s.Section,
			Encoding: s.Encoding,
		})
	}

	if outputFormat == "json" {
		outputJSON(output)
	} else {
		printStringsMarkdown(output, stringPattern)
	}

	return nil
}

func printStringsMarkdown(s StringsOutput, pattern string) {
	if pattern != "" {
		fmt.Printf("# Strings matching %q (%d/%d)\n\n", pattern, s.Count, s.Total)
	} else {
		fmt.Printf("# Strings (%d/%d)\n\n", s.Count, s.Total)
	}

	if s.Count == 0 {
		fmt.Println("No strings found.")
		return
	}

	for _, str := range s.Strings {
		truncated := str.Value
		if len(truncated) > 80 {
			truncated = truncated[:77] + "..."
		}
		fmt.Printf("- **%s** `%s`\n", str.Offset, truncated)
	}

	if s.Truncated {
		fmt.Printf("\n_Showing %d of %d results. Use --offset to paginate._\n", s.Count, s.Total)
	}
}
