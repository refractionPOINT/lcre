package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/refractionPOINT/lcre/internal/backend"
	_ "github.com/refractionPOINT/lcre/internal/backend/native"
	"github.com/refractionPOINT/lcre/internal/model"
	"github.com/refractionPOINT/lcre/internal/output"
)

// DiffResult contains the differences between two binaries
type DiffResult struct {
	BinaryA         string              `json:"binary_a"`
	BinaryB         string              `json:"binary_b"`
	MetadataChanges []Change            `json:"metadata_changes,omitempty"`
	SectionChanges  []SectionDiff       `json:"section_changes,omitempty"`
	ImportChanges   ImportDiff          `json:"import_changes,omitempty"`
	ExportChanges   ExportDiff          `json:"export_changes,omitempty"`
	Summary         string              `json:"summary"`
}

// Change represents a single field change
type Change struct {
	Field    string `json:"field"`
	OldValue string `json:"old_value"`
	NewValue string `json:"new_value"`
}

// SectionDiff represents section differences
type SectionDiff struct {
	Name    string  `json:"name"`
	Status  string  `json:"status"` // added, removed, modified
	Changes []Change `json:"changes,omitempty"`
}

// ImportDiff represents import differences
type ImportDiff struct {
	Added   []model.Import `json:"added,omitempty"`
	Removed []model.Import `json:"removed,omitempty"`
}

// ExportDiff represents export differences
type ExportDiff struct {
	Added   []model.Export `json:"added,omitempty"`
	Removed []model.Export `json:"removed,omitempty"`
}

var diffCmd = &cobra.Command{
	Use:   "diff <binary_a> <binary_b>",
	Short: "Compare two binaries",
	Long: `Compares two binaries and shows differences in:
- Metadata (size, hashes, arch)
- Sections (added, removed, modified)
- Imports (added, removed)
- Exports (added, removed)`,
	Args: cobra.ExactArgs(2),
	RunE: runDiff,
}

func init() {
	rootCmd.AddCommand(diffCmd)
}

func runDiff(cmd *cobra.Command, args []string) error {
	pathA, pathB := args[0], args[1]

	if err := validateBinaryPath(pathA); err != nil {
		return fmt.Errorf("binary A: %w", err)
	}
	if err := validateBinaryPath(pathB); err != nil {
		return fmt.Errorf("binary B: %w", err)
	}

	// Get the native backend
	b, err := backend.DefaultRegistry.Get("native")
	if err != nil {
		return fmt.Errorf("native backend not available: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	opts := backend.AnalysisOptions{
		Timeout:        timeout,
		IncludeStrings: false, // Don't need strings for diff
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Analyzing %s...\n", pathA)
	}
	resultA, err := b.Analyze(ctx, pathA, opts)
	if err != nil {
		return fmt.Errorf("analysis of %s failed: %w", pathA, err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Analyzing %s...\n", pathB)
	}
	resultB, err := b.Analyze(ctx, pathB, opts)
	if err != nil {
		return fmt.Errorf("analysis of %s failed: %w", pathB, err)
	}

	// Compute diff
	diff := computeDiff(resultA, resultB)

	// Output results
	switch outputFormat {
	case "json":
		writer := output.NewJSONWriter(true)
		return writer.Write(os.Stdout, diff)
	case "md":
		return outputDiffMarkdown(diff)
	default:
		return fmt.Errorf("unknown output format: %s", outputFormat)
	}
}

func computeDiff(a, b *model.AnalysisResult) *DiffResult {
	diff := &DiffResult{
		BinaryA: a.Metadata.Path,
		BinaryB: b.Metadata.Path,
	}

	// Metadata changes
	if a.Metadata.Size != b.Metadata.Size {
		diff.MetadataChanges = append(diff.MetadataChanges, Change{
			Field:    "size",
			OldValue: fmt.Sprintf("%d", a.Metadata.Size),
			NewValue: fmt.Sprintf("%d", b.Metadata.Size),
		})
	}
	if a.Metadata.SHA256 != b.Metadata.SHA256 {
		diff.MetadataChanges = append(diff.MetadataChanges, Change{
			Field:    "sha256",
			OldValue: a.Metadata.SHA256,
			NewValue: b.Metadata.SHA256,
		})
	}
	if a.Metadata.Arch != b.Metadata.Arch {
		diff.MetadataChanges = append(diff.MetadataChanges, Change{
			Field:    "arch",
			OldValue: a.Metadata.Arch,
			NewValue: b.Metadata.Arch,
		})
	}

	// Section changes
	sectionsA := make(map[string]model.Section)
	for _, sec := range a.Sections {
		sectionsA[sec.Name] = sec
	}
	sectionsB := make(map[string]model.Section)
	for _, sec := range b.Sections {
		sectionsB[sec.Name] = sec
	}

	for name, secA := range sectionsA {
		if secB, ok := sectionsB[name]; ok {
			// Section exists in both - check for modifications
			var changes []Change
			if secA.RawSize != secB.RawSize {
				changes = append(changes, Change{
					Field:    "size",
					OldValue: fmt.Sprintf("%d", secA.RawSize),
					NewValue: fmt.Sprintf("%d", secB.RawSize),
				})
			}
			if secA.VirtualAddr != secB.VirtualAddr {
				changes = append(changes, Change{
					Field:    "virtual_addr",
					OldValue: fmt.Sprintf("0x%x", secA.VirtualAddr),
					NewValue: fmt.Sprintf("0x%x", secB.VirtualAddr),
				})
			}
			if len(changes) > 0 {
				diff.SectionChanges = append(diff.SectionChanges, SectionDiff{
					Name:    name,
					Status:  "modified",
					Changes: changes,
				})
			}
		} else {
			// Section removed
			diff.SectionChanges = append(diff.SectionChanges, SectionDiff{
				Name:   name,
				Status: "removed",
			})
		}
	}
	for name := range sectionsB {
		if _, ok := sectionsA[name]; !ok {
			// Section added
			diff.SectionChanges = append(diff.SectionChanges, SectionDiff{
				Name:   name,
				Status: "added",
			})
		}
	}

	// Import changes
	importsA := make(map[string]model.Import)
	for _, imp := range a.Imports {
		key := imp.Library + ":" + imp.Function
		importsA[key] = imp
	}
	importsB := make(map[string]model.Import)
	for _, imp := range b.Imports {
		key := imp.Library + ":" + imp.Function
		importsB[key] = imp
	}

	for key, imp := range importsA {
		if _, ok := importsB[key]; !ok {
			diff.ImportChanges.Removed = append(diff.ImportChanges.Removed, imp)
		}
	}
	for key, imp := range importsB {
		if _, ok := importsA[key]; !ok {
			diff.ImportChanges.Added = append(diff.ImportChanges.Added, imp)
		}
	}

	// Export changes
	exportsA := make(map[string]model.Export)
	for _, exp := range a.Exports {
		exportsA[exp.Name] = exp
	}
	exportsB := make(map[string]model.Export)
	for _, exp := range b.Exports {
		exportsB[exp.Name] = exp
	}

	for name, exp := range exportsA {
		if _, ok := exportsB[name]; !ok {
			diff.ExportChanges.Removed = append(diff.ExportChanges.Removed, exp)
		}
	}
	for name, exp := range exportsB {
		if _, ok := exportsA[name]; !ok {
			diff.ExportChanges.Added = append(diff.ExportChanges.Added, exp)
		}
	}

	// Generate summary
	changes := len(diff.MetadataChanges) + len(diff.SectionChanges) +
		len(diff.ImportChanges.Added) + len(diff.ImportChanges.Removed) +
		len(diff.ExportChanges.Added) + len(diff.ExportChanges.Removed)
	if changes == 0 {
		diff.Summary = "No significant differences detected"
	} else {
		diff.Summary = fmt.Sprintf("%d differences detected", changes)
	}

	return diff
}

func outputDiffMarkdown(diff *DiffResult) error {
	fmt.Printf("# Binary Diff\n\n")
	fmt.Printf("**Binary A:** %s\n", diff.BinaryA)
	fmt.Printf("**Binary B:** %s\n\n", diff.BinaryB)
	fmt.Printf("**Summary:** %s\n\n", diff.Summary)

	if len(diff.MetadataChanges) > 0 {
		fmt.Print("## Metadata Changes\n\n")
		fmt.Println("| Field | Binary A | Binary B |")
		fmt.Println("|-------|----------|----------|")
		for _, c := range diff.MetadataChanges {
			fmt.Printf("| %s | %s | %s |\n", c.Field, c.OldValue, c.NewValue)
		}
		fmt.Println()
	}

	if len(diff.SectionChanges) > 0 {
		fmt.Print("## Section Changes\n\n")
		for _, sec := range diff.SectionChanges {
			switch sec.Status {
			case "added":
				fmt.Printf("- **%s**: added\n", sec.Name)
			case "removed":
				fmt.Printf("- **%s**: removed\n", sec.Name)
			case "modified":
				fmt.Printf("- **%s**: modified\n", sec.Name)
				for _, c := range sec.Changes {
					fmt.Printf("  - %s: %s -> %s\n", c.Field, c.OldValue, c.NewValue)
				}
			}
		}
		fmt.Println()
	}

	if len(diff.ImportChanges.Added) > 0 || len(diff.ImportChanges.Removed) > 0 {
		fmt.Print("## Import Changes\n\n")
		for _, imp := range diff.ImportChanges.Added {
			fmt.Printf("- **+** %s:%s\n", imp.Library, imp.Function)
		}
		for _, imp := range diff.ImportChanges.Removed {
			fmt.Printf("- **-** %s:%s\n", imp.Library, imp.Function)
		}
		fmt.Println()
	}

	if len(diff.ExportChanges.Added) > 0 || len(diff.ExportChanges.Removed) > 0 {
		fmt.Print("## Export Changes\n\n")
		for _, exp := range diff.ExportChanges.Added {
			fmt.Printf("- **+** %s\n", exp.Name)
		}
		for _, exp := range diff.ExportChanges.Removed {
			fmt.Printf("- **-** %s\n", exp.Name)
		}
		fmt.Println()
	}

	return nil
}
