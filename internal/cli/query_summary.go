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

var (
	summaryFull bool
)

var querySummaryCmd = &cobra.Command{
	Use:   "summary <binary>",
	Short: "Get analysis summary",
	Long: `Get a summary of the binary analysis including metadata and counts.
First query triggers analysis, subsequent queries are instant.

Use --full to include complete metadata details (hashes, compiler, timestamp, etc.)`,
	Args: cobra.ExactArgs(1),
	RunE: runQuerySummary,
}

func init() {
	querySummaryCmd.Flags().BoolVar(&summaryFull, "full", false, "Include full metadata details")
	queryCmd.AddCommand(querySummaryCmd)
}

// SummaryOutput represents the JSON output for the summary command.
type SummaryOutput struct {
	Metadata       MetadataSummary   `json:"metadata"`
	FullMetadata   *FullMetadata     `json:"full_metadata,omitempty"`
	YARAMatchCount int               `json:"yara_match_count"`
	YARAMatches    []YARASummary     `json:"yara_matches,omitempty"`
	Counts         CountSummary      `json:"counts"`
	Cached         bool              `json:"cached"`
	AnalysisTime   string            `json:"analysis_time,omitempty"`
}

type MetadataSummary struct {
	Format string `json:"format"`
	Arch   string `json:"arch"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type FullMetadata struct {
	Path      string `json:"path"`
	Name      string `json:"name"`
	Bits      int    `json:"bits"`
	Endian    string `json:"endian"`
	MD5       string `json:"md5"`
	SHA1      string `json:"sha1"`
	Compiler  string `json:"compiler,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
	IsSigned  bool   `json:"is_signed"`
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

	// Include full metadata if requested
	if summaryFull {
		output.FullMetadata = &FullMetadata{
			Path:      meta.Binary.Path,
			Name:      meta.Binary.Name,
			Bits:      meta.Binary.Bits,
			Endian:    string(meta.Binary.Endian),
			MD5:       meta.Binary.MD5,
			SHA1:      meta.Binary.SHA1,
			Compiler:  meta.Binary.Compiler,
			Timestamp: meta.Binary.Timestamp,
			IsSigned:  meta.Binary.IsSigned,
		}
	}

	if wasNew {
		output.AnalysisTime = fmt.Sprintf("%.2fs", time.Since(start).Seconds())
	}

	if outputFormat == "json" {
		outputJSON(output)
	} else {
		printSummaryMarkdown(output, meta, summaryFull)
	}

	return nil
}

func printSummaryMarkdown(s SummaryOutput, meta *cache.CachedMetadata, full bool) {
	fmt.Printf("# Binary Summary\n\n")
	fmt.Printf("**Format:** %s | **Arch:** %s | **Size:** %s\n", s.Metadata.Format, s.Metadata.Arch, formatBytes(s.Metadata.Size))
	fmt.Printf("**SHA256:** %s\n\n", s.Metadata.SHA256)

	// Full metadata details
	if full && s.FullMetadata != nil {
		fmt.Printf("## Metadata Details\n")
		fmt.Printf("- **Path:** %s\n", s.FullMetadata.Path)
		fmt.Printf("- **Name:** %s\n", s.FullMetadata.Name)
		fmt.Printf("- **Architecture:** %s (%d-bit, %s)\n", s.Metadata.Arch, s.FullMetadata.Bits, s.FullMetadata.Endian)
		fmt.Printf("- **MD5:** %s\n", s.FullMetadata.MD5)
		fmt.Printf("- **SHA1:** %s\n", s.FullMetadata.SHA1)
		if s.FullMetadata.Compiler != "" {
			fmt.Printf("- **Compiler:** %s\n", s.FullMetadata.Compiler)
		}
		if s.FullMetadata.Timestamp > 0 {
			fmt.Printf("- **Timestamp:** %d\n", s.FullMetadata.Timestamp)
		}
		fmt.Printf("- **Signed:** %v\n", s.FullMetadata.IsSigned)
		fmt.Println()
	}

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
