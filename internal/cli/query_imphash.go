package cli

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
)

var queryImpHashCmd = &cobra.Command{
	Use:   "imphash <binary>",
	Short: "Get the import hash (imphash) of a PE binary",
	Long: `Get the import hash (imphash) of a PE binary.

The import hash is an MD5 hash of the imported functions which allows
fuzzy matching of related malware samples that share similar import tables.

This technique was popularized by Mandiant and is useful for:
- Identifying malware families that share similar import patterns
- Finding variants of known malware
- Clustering related samples for analysis`,
	Args: cobra.ExactArgs(1),
	RunE: runQueryImpHash,
}

func init() {
	queryCmd.AddCommand(queryImpHashCmd)
}

type ImpHashOutput struct {
	Path    string `json:"path"`
	Name    string `json:"name"`
	Format  string `json:"format"`
	ImpHash string `json:"imphash"`
	Note    string `json:"note,omitempty"`
}

func runQueryImpHash(cmd *cobra.Command, args []string) error {
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

	meta, err := mgr.LoadMetadata(absPath)
	if err != nil {
		return fmt.Errorf("load metadata: %w", err)
	}

	output := ImpHashOutput{
		Path:    meta.Binary.Path,
		Name:    meta.Binary.Name,
		Format:  string(meta.Binary.Format),
		ImpHash: meta.Binary.ImpHash,
	}

	if meta.Binary.Format != "PE" {
		output.Note = "Import hash is only supported for PE (Windows) binaries"
	} else if output.ImpHash == "" {
		output.Note = "No import hash available (binary may have no imports or be malformed)"
	}

	if outputFormat == "json" {
		outputJSON(output)
	} else {
		fmt.Printf("# Import Hash (ImpHash)\n\n")
		fmt.Printf("**Binary:** %s\n", output.Name)
		fmt.Printf("**Format:** %s\n", output.Format)
		if output.ImpHash != "" {
			fmt.Printf("**ImpHash:** %s\n", output.ImpHash)
		} else if output.Note != "" {
			fmt.Printf("\n*%s*\n", output.Note)
		}
	}

	return nil
}
