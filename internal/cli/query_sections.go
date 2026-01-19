package cli

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/refractionPOINT/lcre/internal/model"
	"github.com/spf13/cobra"
)

var (
	sectionName string
)

var querySectionsCmd = &cobra.Command{
	Use:   "sections <binary>",
	Short: "List binary sections",
	Long:  "List all sections in the binary with entropy and permissions.",
	Args:  cobra.ExactArgs(1),
	RunE:  runQuerySections,
}

func init() {
	querySectionsCmd.Flags().StringVar(&sectionName, "name", "", "Filter by section name")
	queryCmd.AddCommand(querySectionsCmd)
}

type SectionsOutput struct {
	Sections []SectionInfo `json:"sections"`
	Count    int           `json:"count"`
}

type SectionInfo struct {
	Name         string  `json:"name"`
	VirtualAddr  string  `json:"virtual_addr"`
	VirtualSize  uint64  `json:"virtual_size"`
	RawSize      uint64  `json:"raw_size"`
	Entropy      float64 `json:"entropy"`
	Permissions  string  `json:"permissions"`
	HighEntropy  bool    `json:"high_entropy"`
}

func runQuerySections(cmd *cobra.Command, args []string) error {
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

	sections, err := db.QuerySections(sectionName)
	if err != nil {
		return err
	}

	output := SectionsOutput{
		Sections: make([]SectionInfo, 0, len(sections)),
		Count:    len(sections),
	}

	for _, s := range sections {
		output.Sections = append(output.Sections, SectionInfo{
			Name:         s.Name,
			VirtualAddr:  formatAddress(int64(s.VirtualAddr)),
			VirtualSize:  s.VirtualSize,
			RawSize:      s.RawSize,
			Entropy:      s.Entropy,
			Permissions:  s.Permissions,
			HighEntropy:  s.Entropy >= 7.0,
		})
	}

	if outputFormat == "json" {
		outputJSON(output)
	} else {
		printSectionsMarkdown(output)
	}

	return nil
}

func printSectionsMarkdown(s SectionsOutput) {
	fmt.Printf("# Sections (%d)\n\n", s.Count)
	if s.Count == 0 {
		fmt.Println("No sections found.")
		return
	}

	fmt.Println("| Name | Address | VSize | RSize | Entropy | Perms |")
	fmt.Println("|------|---------|-------|-------|---------|-------|")
	for _, sec := range s.Sections {
		entropyStr := fmt.Sprintf("%.2f", sec.Entropy)
		if sec.HighEntropy {
			entropyStr += " ⚠"
		}
		fmt.Printf("| %s | %s | %d | %d | %s | %s |\n",
			sec.Name, sec.VirtualAddr, sec.VirtualSize, sec.RawSize, entropyStr, sec.Permissions)
	}
}

// For models not cached in database - direct from analysis
func sectionToInfo(s model.Section) SectionInfo {
	return SectionInfo{
		Name:         s.Name,
		VirtualAddr:  formatAddress(int64(s.VirtualAddr)),
		VirtualSize:  s.VirtualSize,
		RawSize:      s.RawSize,
		Entropy:      s.Entropy,
		Permissions:  s.Permissions,
		HighEntropy:  s.Entropy >= 7.0,
	}
}
