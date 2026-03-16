package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/refractionPOINT/lcre/internal/yara"
	"github.com/spf13/cobra"
)

var (
	yaraRulesFile string
	yaraRulesDir  string
	yaraListRules bool
)

var queryYaraCmd = &cobra.Command{
	Use:   "yara <binary>",
	Short: "Scan binary with YARA rules",
	Long: `Scan a binary using YARA signature rules.

By default, uses embedded YARA rules that cover common malware families including:
- Ransomware: Locky, Petya, WannaCry, Ryuk
- APT malware: Stuxnet, Duqu, Flame
- Trojans: Emotet, Trickbot, AgentTesla
- Red team tools: Cobalt Strike, Metasploit
- Packers: UPX, VMProtect, Themida, ASPack

You can also specify custom rules using --rules or --rules-dir flags.

Note: Requires the 'yara' command-line tool to be installed and available in PATH.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runQueryYara,
}

func init() {
	queryYaraCmd.Flags().StringVar(&yaraRulesFile, "rules", "", "Path to a YARA rules file")
	queryYaraCmd.Flags().StringVar(&yaraRulesDir, "rules-dir", "", "Path to a directory containing YARA rules")
	queryYaraCmd.Flags().BoolVar(&yaraListRules, "list-families", false, "List malware families covered by embedded rules")
	queryCmd.AddCommand(queryYaraCmd)
}

type YaraScanOutput struct {
	Path      string        `json:"path"`
	Available bool          `json:"yara_available"`
	Matches   []YaraMatch   `json:"matches,omitempty"`
	Error     string        `json:"error,omitempty"`
}

type YaraMatch struct {
	Rule        string   `json:"rule"`
	Tags        []string `json:"tags,omitempty"`
	Description string   `json:"description,omitempty"`
	Strings     []string `json:"strings,omitempty"`
}

func runQueryYara(cmd *cobra.Command, args []string) error {
	// Handle --list-families flag
	if yaraListRules {
		families := yara.GetRuleFamilies()
		categories := yara.GetRuleCategories()

		if outputFormat == "json" {
			outputJSON(map[string]interface{}{
				"families":   families,
				"categories": categories,
			})
		} else {
			fmt.Println("# Embedded YARA Rules Coverage")
			fmt.Println()
			fmt.Println("## Malware Families")
			for _, family := range families {
				fmt.Printf("- %s\n", family)
			}
			fmt.Println()
			fmt.Println("## Categories")
			for _, cat := range categories {
				fmt.Printf("- %s\n", cat)
			}
		}
		return nil
	}

	if len(args) == 0 {
		return fmt.Errorf("binary path required (or use --list-families)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	binaryPath := args[0]
	absPath, err := filepath.Abs(binaryPath)
	if err != nil {
		return err
	}

	// Check if file exists
	if _, err := os.Stat(absPath); err != nil {
		return fmt.Errorf("file not found: %s", absPath)
	}

	scanner := yara.NewScanner()

	// Set custom rules if specified
	if yaraRulesFile != "" {
		scanner.SetRulesFile(yaraRulesFile)
	} else if yaraRulesDir != "" {
		scanner.SetRulesDir(yaraRulesDir)
	} else {
		// Use embedded rules
		rulesPath, err := yara.WriteEmbeddedRules()
		if err != nil {
			return fmt.Errorf("failed to write embedded rules: %w", err)
		}
		defer os.Remove(rulesPath)
		scanner.SetRulesFile(rulesPath)
	}

	output := YaraScanOutput{
		Path:      absPath,
		Available: scanner.Available(),
	}

	if !output.Available {
		output.Error = "yara command not found in PATH - install YARA to enable signature scanning"
		if outputFormat == "json" {
			outputJSON(output)
		} else {
			fmt.Println("# YARA Scan")
			fmt.Println()
			fmt.Printf("**Error:** %s\n", output.Error)
			fmt.Println()
			fmt.Println("To install YARA:")
			fmt.Println("- Ubuntu/Debian: `apt-get install yara`")
			fmt.Println("- macOS: `brew install yara`")
			fmt.Println("- From source: https://virustotal.github.io/yara/")
		}
		return nil
	}

	// Run scan
	result, err := scanner.Scan(ctx, absPath)
	if err != nil {
		return fmt.Errorf("YARA scan failed: %w", err)
	}

	if result.Error != "" {
		output.Error = result.Error
	}

	for _, match := range result.Matches {
		output.Matches = append(output.Matches, YaraMatch{
			Rule:    match.Rule,
			Tags:    match.Tags,
			Strings: match.Strings,
		})
	}

	if outputFormat == "json" {
		outputJSON(output)
	} else {
		fmt.Println("# YARA Scan Results")
		fmt.Println()
		fmt.Printf("**Binary:** %s\n", filepath.Base(absPath))
		fmt.Println()

		if output.Error != "" {
			fmt.Printf("**Error:** %s\n", output.Error)
		} else if len(output.Matches) == 0 {
			fmt.Println("No YARA rules matched.")
		} else {
			fmt.Printf("**Matches:** %d\n\n", len(output.Matches))
			for _, match := range output.Matches {
				fmt.Printf("## %s\n", match.Rule)
				if len(match.Tags) > 0 {
					fmt.Printf("*Tags:* %v\n", match.Tags)
				}
				if len(match.Strings) > 0 {
					fmt.Println("*String matches:*")
					for _, s := range match.Strings {
						fmt.Printf("  - %s\n", s)
					}
				}
				fmt.Println()
			}
		}
	}

	return nil
}
