package cli

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
)

var queryInfoCmd = &cobra.Command{
	Use:   "info <binary>",
	Short: "Get binary metadata",
	Long:  "Get basic binary metadata including hashes, format, architecture, and size.",
	Args:  cobra.ExactArgs(1),
	RunE:  runQueryInfo,
}

func init() {
	queryCmd.AddCommand(queryInfoCmd)
}

type InfoOutput struct {
	Path      string `json:"path"`
	Name      string `json:"name"`
	Format    string `json:"format"`
	Arch      string `json:"arch"`
	Bits      int    `json:"bits"`
	Endian    string `json:"endian"`
	Size      int64  `json:"size"`
	MD5       string `json:"md5"`
	SHA1      string `json:"sha1"`
	SHA256    string `json:"sha256"`
	Compiler  string `json:"compiler,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
	IsSigned  bool   `json:"is_signed"`
}

func runQueryInfo(cmd *cobra.Command, args []string) error {
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

	output := InfoOutput{
		Path:      meta.Binary.Path,
		Name:      meta.Binary.Name,
		Format:    string(meta.Binary.Format),
		Arch:      string(meta.Binary.Arch),
		Bits:      meta.Binary.Bits,
		Endian:    string(meta.Binary.Endian),
		Size:      meta.Binary.Size,
		MD5:       meta.Binary.MD5,
		SHA1:      meta.Binary.SHA1,
		SHA256:    meta.Binary.SHA256,
		Compiler:  meta.Binary.Compiler,
		Timestamp: meta.Binary.Timestamp,
		IsSigned:  meta.Binary.IsSigned,
	}

	if outputFormat == "json" {
		outputJSON(output)
	} else {
		fmt.Printf("# Binary Info\n\n")
		fmt.Printf("**Path:** %s\n", output.Path)
		fmt.Printf("**Name:** %s\n", output.Name)
		fmt.Printf("**Format:** %s\n", output.Format)
		fmt.Printf("**Architecture:** %s (%d-bit, %s)\n", output.Arch, output.Bits, output.Endian)
		fmt.Printf("**Size:** %s (%d bytes)\n", formatBytes(output.Size), output.Size)
		fmt.Printf("\n## Hashes\n")
		fmt.Printf("- **MD5:** %s\n", output.MD5)
		fmt.Printf("- **SHA1:** %s\n", output.SHA1)
		fmt.Printf("- **SHA256:** %s\n", output.SHA256)
		if output.Compiler != "" {
			fmt.Printf("\n**Compiler:** %s\n", output.Compiler)
		}
		if output.Timestamp > 0 {
			fmt.Printf("**Timestamp:** %d\n", output.Timestamp)
		}
		fmt.Printf("**Signed:** %v\n", output.IsSigned)
	}

	return nil
}
