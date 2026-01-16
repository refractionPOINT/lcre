package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	heuristicCategory string
)

var queryHeuristicsCmd = &cobra.Command{
	Use:   "heuristics <binary>",
	Short: "List heuristic findings",
	Long:  "List heuristic matches and risk indicators for the binary.",
	Args:  cobra.ExactArgs(1),
	RunE:  runQueryHeuristics,
}

func init() {
	queryHeuristicsCmd.Flags().StringVar(&heuristicCategory, "category", "", "Filter by category (packer, injection, anti-debug, persistence, crypto, network, evasion, anomaly)")
	queryCmd.AddCommand(queryHeuristicsCmd)
}

type HeuristicsOutput struct {
	RiskLevel  string           `json:"risk_level"`
	TotalScore int              `json:"total_score"`
	Matches    []HeuristicInfo  `json:"matches"`
	Count      int              `json:"count"`
	Summary    string           `json:"summary,omitempty"`
}

type HeuristicInfo struct {
	RuleID      string   `json:"rule_id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	Evidence    []string `json:"evidence,omitempty"`
}

func runQueryHeuristics(cmd *cobra.Command, args []string) error {
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

	matches, err := db.QueryHeuristics(heuristicCategory)
	if err != nil {
		return err
	}

	meta, err := mgr.LoadMetadata(absPath)
	if err != nil {
		return fmt.Errorf("load metadata: %w", err)
	}

	output := HeuristicsOutput{
		RiskLevel:  meta.RiskLevel,
		TotalScore: meta.TotalScore,
		Matches:    make([]HeuristicInfo, 0, len(matches)),
		Count:      len(matches),
	}

	for _, m := range matches {
		output.Matches = append(output.Matches, HeuristicInfo{
			RuleID:      m.RuleID,
			Name:        m.Name,
			Description: m.Description,
			Severity:    string(m.Severity),
			Category:    string(m.Category),
			Evidence:    m.Evidence,
		})
	}

	if outputFormat == "json" {
		outputJSON(output)
	} else {
		printHeuristicsMarkdown(output)
	}

	return nil
}

func printHeuristicsMarkdown(h HeuristicsOutput) {
	fmt.Printf("# Heuristic Analysis\n\n")
	fmt.Printf("**Risk Level:** %s (score: %d)\n", strings.ToUpper(h.RiskLevel), h.TotalScore)
	fmt.Printf("**Findings:** %d\n\n", h.Count)

	if h.Count == 0 {
		fmt.Println("No suspicious indicators detected.")
		return
	}

	for _, m := range h.Matches {
		severityIcon := "ℹ️"
		switch m.Severity {
		case "critical":
			severityIcon = "🔴"
		case "high":
			severityIcon = "🟠"
		case "medium":
			severityIcon = "🟡"
		case "low":
			severityIcon = "🟢"
		}

		fmt.Printf("## %s [%s] %s\n", severityIcon, m.RuleID, m.Name)
		fmt.Printf("%s\n", m.Description)
		fmt.Printf("**Category:** %s | **Severity:** %s\n", m.Category, m.Severity)

		if len(m.Evidence) > 0 {
			fmt.Println("**Evidence:**")
			for _, e := range m.Evidence {
				fmt.Printf("- %s\n", e)
			}
		}
		fmt.Println()
	}
}
