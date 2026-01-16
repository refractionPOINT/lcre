package cli

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	iocType string
)

var queryIOCsCmd = &cobra.Command{
	Use:   "iocs <binary>",
	Short: "List IOCs",
	Long:  "List Indicators of Compromise (URLs, IPs, domains, paths, etc.) found in the binary.",
	Args:  cobra.ExactArgs(1),
	RunE:  runQueryIOCs,
}

func init() {
	queryIOCsCmd.Flags().StringVar(&iocType, "type", "", "Filter by IOC type (url, domain, ip, email, path, registry, hash)")
	queryCmd.AddCommand(queryIOCsCmd)
}

type IOCsOutput struct {
	IOCs  []IOCInfo `json:"iocs"`
	Count int       `json:"count"`
	ByType map[string]int `json:"by_type"`
}

type IOCInfo struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Offset  string `json:"offset,omitempty"`
	Section string `json:"section,omitempty"`
	Context string `json:"context,omitempty"`
}

func runQueryIOCs(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	binaryPath := args[0]
	absPath, err := filepath.Abs(binaryPath)
	if err != nil {
		return err
	}

	_, db, _, err := ensureAnalyzed(ctx, absPath, queryDeep)
	if err != nil {
		return err
	}
	defer db.Close()

	iocs, err := db.QueryIOCs(iocType)
	if err != nil {
		return err
	}

	output := IOCsOutput{
		IOCs:   make([]IOCInfo, 0, len(iocs)),
		Count:  len(iocs),
		ByType: make(map[string]int),
	}

	for _, ioc := range iocs {
		output.IOCs = append(output.IOCs, IOCInfo{
			Type:    string(ioc.Type),
			Value:   ioc.Value,
			Offset:  formatAddress(int64(ioc.Offset)),
			Section: ioc.Section,
			Context: ioc.Context,
		})
		output.ByType[string(ioc.Type)]++
	}

	if outputFormat == "json" {
		outputJSON(output)
	} else {
		printIOCsMarkdown(output)
	}

	return nil
}

func printIOCsMarkdown(i IOCsOutput) {
	fmt.Printf("# Indicators of Compromise (%d)\n\n", i.Count)

	if i.Count == 0 {
		fmt.Println("No IOCs found.")
		return
	}

	// Print summary by type
	fmt.Println("## Summary")
	for t, count := range i.ByType {
		fmt.Printf("- %s: %d\n", t, count)
	}
	fmt.Println()

	// Group by type
	byType := make(map[string][]IOCInfo)
	for _, ioc := range i.IOCs {
		byType[ioc.Type] = append(byType[ioc.Type], ioc)
	}

	typeOrder := []string{"url", "ip", "domain", "email", "path", "registry", "hash"}
	for _, t := range typeOrder {
		iocs, ok := byType[t]
		if !ok || len(iocs) == 0 {
			continue
		}

		fmt.Printf("## %s (%d)\n", typeLabel(t), len(iocs))
		for _, ioc := range iocs {
			fmt.Printf("- `%s`", ioc.Value)
			if ioc.Offset != "0x0" && ioc.Offset != "" {
				fmt.Printf(" @ %s", ioc.Offset)
			}
			fmt.Println()
		}
		fmt.Println()
	}
}

func typeLabel(t string) string {
	labels := map[string]string{
		"url":      "URLs",
		"domain":   "Domains",
		"ip":       "IP Addresses",
		"email":    "Email Addresses",
		"path":     "File Paths",
		"registry": "Registry Keys",
		"hash":     "Hashes",
	}
	if label, ok := labels[t]; ok {
		return label
	}
	return t
}
