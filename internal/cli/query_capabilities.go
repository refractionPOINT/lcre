package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	capNamespace string
	capName      string
)

var queryCapabilitiesCmd = &cobra.Command{
	Use:   "capabilities <binary>",
	Short: "Show detected capabilities (from capa enrichment)",
	Long: `Display behavioral capabilities detected by capa or similar tools.
Requires prior enrichment: lcre enrich <binary> --tool capa --input <file>

Capabilities include MITRE ATT&CK and MBC mappings when available.`,
	Args: cobra.ExactArgs(1),
	RunE: runQueryCapabilities,
}

func init() {
	queryCapabilitiesCmd.Flags().StringVar(&capNamespace, "namespace", "", "Filter by namespace prefix (e.g., 'anti-analysis')")
	queryCapabilitiesCmd.Flags().StringVar(&capName, "name", "", "Filter by name pattern")
	queryCmd.AddCommand(queryCapabilitiesCmd)
}

func runQueryCapabilities(cmd *cobra.Command, args []string) error {
	binaryPath := args[0]
	if err := validateBinaryPath(binaryPath); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	_, db, _, err := ensureAnalyzed(ctx, binaryPath, false)
	if err != nil {
		return err
	}
	defer db.Close()

	caps, err := db.QueryCapabilities(capNamespace, capName)
	if err != nil {
		return err
	}

	if len(caps) == 0 {
		fmt.Fprintln(os.Stdout, "No capabilities found. Enrich with capa first:")
		fmt.Fprintln(os.Stdout, "  lcre enrich <binary> --tool capa --input <capa_output.json>")
		return nil
	}

	switch outputFormat {
	case "json":
		data, _ := json.MarshalIndent(caps, "", "  ")
		fmt.Println(string(data))
		return nil
	default:
		fmt.Fprintf(os.Stdout, "# Capabilities (%d)\n\n", len(caps))
		fmt.Fprintln(os.Stdout, "| Capability | Namespace | ATT&CK | MBC |")
		fmt.Fprintln(os.Stdout, "|------------|-----------|--------|-----|")
		for _, c := range caps {
			attack := "-"
			if len(c.AttackIDs) > 0 {
				attack = strings.Join(c.AttackIDs, ", ")
			}
			mbc := "-"
			if len(c.MBCIDs) > 0 {
				mbc = strings.Join(c.MBCIDs, ", ")
			}
			fmt.Fprintf(os.Stdout, "| %s | %s | %s | %s |\n",
				c.Name, c.Namespace, attack, mbc)
		}
		return nil
	}
}
