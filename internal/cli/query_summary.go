package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/refractionPOINT/lcre/internal/cache"
	"github.com/spf13/cobra"
)

var querySummaryCmd = &cobra.Command{
	Use:   "summary <binary>",
	Short: "Get analysis summary",
	Long: `Get a summary of the binary analysis including metadata and counts.
First query triggers analysis, subsequent queries are instant.`,
	Args: cobra.ExactArgs(1),
	RunE: runQuerySummary,
}

func init() {
	queryCmd.AddCommand(querySummaryCmd)
}

// SummaryOutput represents the JSON output for the summary command.
type SummaryOutput struct {
	Metadata       MetadataSummary  `json:"metadata"`
	YARAMatchCount int              `json:"yara_match_count"`
	YARAMatches    []YARASummary    `json:"yara_matches,omitempty"`
	Counts         CountSummary     `json:"counts"`
	Cached         bool             `json:"cached"`
	AnalysisTime   string           `json:"analysis_time,omitempty"`
}

type MetadataSummary struct {
	Format string `json:"format"`
	Arch   string `json:"arch"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type YARASummary struct {
	Rule string   `json:"rule"`
	Tags []string `json:"tags,omitempty"`
}

type CountSummary struct {
	Sections  int `json:"sections"`
	Imports   int `json:"imports"`
	Exports   int `json:"exports"`
	Strings   int `json:"strings"`
	Functions int `json:"functions"`
	IOCs      int `json:"iocs"`
}

func runQuerySummary(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	binaryPath := args[0]
	absPath, err := filepath.Abs(binaryPath)
	if err != nil {
		return err
	}

	start := time.Now()
	mgr, db, wasNew, err := ensureAnalyzed(ctx, absPath, queryDeep)
	if err != nil {
		return err
	}
	defer db.Close()

	// Load cached metadata
	meta, err := mgr.LoadMetadata(absPath)
	if err != nil {
		return fmt.Errorf("load metadata: %w", err)
	}

	// Get counts from database
	sections, _ := db.QuerySections("")
	imports, _ := db.QueryImports("", "")
	exports, _ := db.QueryExports("")
	_, stringCount, _ := db.QueryStrings("", 1, 0)
	functions, _ := db.QueryFunctions("", 0, 0)
	iocs, _ := db.QueryIOCs("")

	// Get YARA matches
	yaraMatches, _ := db.QueryYARAMatches("")
	yaraSummaries := make([]YARASummary, 0)
	for i, m := range yaraMatches {
		if i >= 5 {
			break
		}
		yaraSummaries = append(yaraSummaries, YARASummary{
			Rule: m.Rule,
			Tags: m.Tags,
		})
	}

	output := SummaryOutput{
		Metadata: MetadataSummary{
			Format: string(meta.Binary.Format),
			Arch:   string(meta.Binary.Arch),
			Size:   meta.Binary.Size,
			SHA256: meta.Binary.SHA256,
		},
		YARAMatchCount: len(yaraMatches),
		YARAMatches:    yaraSummaries,
		Counts: CountSummary{
			Sections:  len(sections),
			Imports:   len(imports),
			Exports:   len(exports),
			Strings:   stringCount,
			Functions: len(functions),
			IOCs:      len(iocs),
		},
		Cached: !wasNew,
	}

	if wasNew {
		output.AnalysisTime = fmt.Sprintf("%.2fs", time.Since(start).Seconds())
	}

	if outputFormat == "json" {
		outputJSON(output)
	} else {
		printSummaryMarkdown(output, meta)
	}

	return nil
}

func printSummaryMarkdown(s SummaryOutput, meta *cache.CachedMetadata) {
	fmt.Printf("# Binary Summary\n\n")
	fmt.Printf("**Format:** %s | **Arch:** %s | **Size:** %s\n", s.Metadata.Format, s.Metadata.Arch, formatBytes(s.Metadata.Size))
	fmt.Printf("**SHA256:** %s\n\n", s.Metadata.SHA256)

	if len(s.YARAMatches) > 0 {
		fmt.Printf("## YARA Matches (%d)\n", s.YARAMatchCount)
		for _, m := range s.YARAMatches {
			if len(m.Tags) > 0 {
				fmt.Printf("- %s [%s]\n", m.Rule, strings.Join(m.Tags, ", "))
			} else {
				fmt.Printf("- %s\n", m.Rule)
			}
		}
		fmt.Println()
	}

	fmt.Printf("## Counts\n")
	fmt.Printf("- Sections: %d\n", s.Counts.Sections)
	fmt.Printf("- Imports: %d\n", s.Counts.Imports)
	fmt.Printf("- Exports: %d\n", s.Counts.Exports)
	fmt.Printf("- Strings: %d\n", s.Counts.Strings)
	fmt.Printf("- Functions: %d\n", s.Counts.Functions)
	fmt.Printf("- IOCs: %d\n", s.Counts.IOCs)

	if !s.Cached {
		fmt.Printf("\n_Analysis time: %s_\n", s.AnalysisTime)
	}
}
