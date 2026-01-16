package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/maxime/lcre/internal/cache"
	"github.com/maxime/lcre/internal/model"
	"github.com/spf13/cobra"
)

var querySummaryCmd = &cobra.Command{
	Use:   "summary <binary>",
	Short: "Get analysis summary",
	Long: `Get a summary of the binary analysis including metadata, risk level, and top findings.
First query triggers analysis, subsequent queries are instant.`,
	Args: cobra.ExactArgs(1),
	RunE: runQuerySummary,
}

func init() {
	queryCmd.AddCommand(querySummaryCmd)
}

// SummaryOutput represents the JSON output for the summary command.
type SummaryOutput struct {
	Metadata      MetadataSummary   `json:"metadata"`
	RiskLevel     string            `json:"risk_level"`
	TotalScore    int               `json:"total_score"`
	HeuristicCount int              `json:"heuristic_count"`
	TopFindings   []FindingSummary  `json:"top_findings"`
	Counts        CountSummary      `json:"counts"`
	Cached        bool              `json:"cached"`
	AnalysisTime  string            `json:"analysis_time,omitempty"`
}

type MetadataSummary struct {
	Format  string `json:"format"`
	Arch    string `json:"arch"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}

type FindingSummary struct {
	RuleID   string `json:"rule"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Category string `json:"category,omitempty"`
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

	// Get top findings
	heuristics, _ := db.QueryHeuristics("")
	topFindings := make([]FindingSummary, 0)
	for i, h := range heuristics {
		if i >= 5 {
			break
		}
		topFindings = append(topFindings, FindingSummary{
			RuleID:   h.RuleID,
			Name:     h.Name,
			Severity: string(h.Severity),
			Category: string(h.Category),
		})
	}

	output := SummaryOutput{
		Metadata: MetadataSummary{
			Format: string(meta.Binary.Format),
			Arch:   string(meta.Binary.Arch),
			Size:   meta.Binary.Size,
			SHA256: meta.Binary.SHA256,
		},
		RiskLevel:      meta.RiskLevel,
		TotalScore:     meta.TotalScore,
		HeuristicCount: len(heuristics),
		TopFindings:    topFindings,
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

	// Risk indicator
	riskEmoji := "✅"
	switch model.Severity(s.RiskLevel) {
	case model.SeverityHigh, model.SeverityCritical:
		riskEmoji = "🔴"
	case model.SeverityMedium:
		riskEmoji = "🟡"
	case model.SeverityLow:
		riskEmoji = "🟠"
	}
	fmt.Printf("## Risk Level: %s %s (score: %d)\n\n", riskEmoji, s.RiskLevel, s.TotalScore)

	if len(s.TopFindings) > 0 {
		fmt.Printf("## Top Findings\n")
		for _, f := range s.TopFindings {
			fmt.Printf("- **[%s]** %s (%s)\n", f.Severity, f.Name, f.RuleID)
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
