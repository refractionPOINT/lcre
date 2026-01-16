package output

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/maxime/lcre/internal/model"
)

// MarkdownWriter writes analysis results as Markdown
type MarkdownWriter struct{}

// NewMarkdownWriter creates a new Markdown writer
func NewMarkdownWriter() *MarkdownWriter {
	return &MarkdownWriter{}
}

// Write writes an analysis result as Markdown to the given writer
func (w *MarkdownWriter) Write(writer io.Writer, result *model.AnalysisResult) error {
	var sb strings.Builder

	// Header
	sb.WriteString(fmt.Sprintf("# Binary Analysis Report: %s\n\n", result.Metadata.Name))

	// Metadata
	sb.WriteString("## Metadata\n\n")
	sb.WriteString("| Property | Value |\n")
	sb.WriteString("|----------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Path | `%s` |\n", result.Metadata.Path))
	sb.WriteString(fmt.Sprintf("| Size | %d bytes |\n", result.Metadata.Size))
	sb.WriteString(fmt.Sprintf("| Format | %s |\n", result.Metadata.Format))
	sb.WriteString(fmt.Sprintf("| Architecture | %s (%d-bit) |\n", result.Metadata.Arch, result.Metadata.Bits))
	sb.WriteString(fmt.Sprintf("| MD5 | `%s` |\n", result.Metadata.MD5))
	sb.WriteString(fmt.Sprintf("| SHA256 | `%s` |\n", result.Metadata.SHA256))
	sb.WriteString(fmt.Sprintf("| Backend | %s |\n", result.Backend))
	sb.WriteString(fmt.Sprintf("| Duration | %.2fs |\n", result.Duration))
	sb.WriteString("\n")

	// Sections
	if len(result.Sections) > 0 {
		sb.WriteString("## Sections\n\n")
		sb.WriteString("| Name | Virtual Address | Size | Entropy | Permissions |\n")
		sb.WriteString("|------|-----------------|------|---------|-------------|\n")
		for _, sec := range result.Sections {
			sb.WriteString(fmt.Sprintf("| %s | 0x%x | %d | %.2f | %s |\n",
				sec.Name, sec.VirtualAddr, sec.RawSize, sec.Entropy, sec.Permissions))
		}
		sb.WriteString("\n")
	}

	// Imports
	if len(result.Imports) > 0 {
		sb.WriteString("## Imports\n\n")

		// Group by library
		libs := make(map[string][]model.Import)
		for _, imp := range result.Imports {
			libs[imp.Library] = append(libs[imp.Library], imp)
		}

		for lib, imports := range libs {
			sb.WriteString(fmt.Sprintf("### %s\n\n", lib))
			for _, imp := range imports {
				sb.WriteString(fmt.Sprintf("- `%s`\n", imp.Function))
			}
			sb.WriteString("\n")
		}
	}

	// Exports
	if len(result.Exports) > 0 {
		sb.WriteString("## Exports\n\n")
		sb.WriteString("| Name | Address | Ordinal |\n")
		sb.WriteString("|------|---------|--------|\n")
		for _, exp := range result.Exports {
			sb.WriteString(fmt.Sprintf("| %s | 0x%x | %d |\n", exp.Name, exp.Address, exp.Ordinal))
		}
		sb.WriteString("\n")
	}

	// Heuristics
	if result.Heuristics != nil && result.Heuristics.HasMatches() {
		sb.WriteString("## Heuristic Analysis\n\n")
		sb.WriteString(fmt.Sprintf("**Risk Level:** %s (Score: %d)\n\n",
			strings.ToUpper(string(result.Heuristics.RiskLevel)), result.Heuristics.TotalScore))

		sb.WriteString("| Rule ID | Name | Severity | Category |\n")
		sb.WriteString("|---------|------|----------|----------|\n")
		for _, match := range result.Heuristics.Matches {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
				match.RuleID, match.Name, match.Severity, match.Category))
		}
		sb.WriteString("\n")

		// Details for each match
		sb.WriteString("### Details\n\n")
		for _, match := range result.Heuristics.Matches {
			sb.WriteString(fmt.Sprintf("#### %s: %s\n\n", match.RuleID, match.Name))
			sb.WriteString(fmt.Sprintf("%s\n\n", match.Description))
			if len(match.Evidence) > 0 {
				sb.WriteString("**Evidence:**\n")
				for _, ev := range match.Evidence {
					sb.WriteString(fmt.Sprintf("- `%s`\n", ev))
				}
				sb.WriteString("\n")
			}
		}
	}

	// Strings (truncated)
	if len(result.Strings) > 0 {
		sb.WriteString("## Strings\n\n")
		maxStrings := 50
		if len(result.Strings) < maxStrings {
			maxStrings = len(result.Strings)
		}
		sb.WriteString(fmt.Sprintf("Showing %d of %d strings:\n\n", maxStrings, len(result.Strings)))
		sb.WriteString("```\n")
		for i := 0; i < maxStrings; i++ {
			s := result.Strings[i]
			// Truncate long strings
			val := s.Value
			if len(val) > 80 {
				val = val[:77] + "..."
			}
			sb.WriteString(fmt.Sprintf("0x%08x: %s\n", s.Offset, val))
		}
		sb.WriteString("```\n\n")
	}

	// Errors
	if len(result.Errors) > 0 {
		sb.WriteString("## Errors\n\n")
		for _, err := range result.Errors {
			sb.WriteString(fmt.Sprintf("- %s\n", err))
		}
		sb.WriteString("\n")
	}

	_, err := writer.Write([]byte(sb.String()))
	return err
}

// WriteToFile writes an analysis result as Markdown to a file
func (w *MarkdownWriter) WriteToFile(path string, result *model.AnalysisResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return w.Write(f, result)
}

// WriteIOCs writes IOC results as Markdown
func (w *MarkdownWriter) WriteIOCs(writer io.Writer, result *model.IOCResult) error {
	var sb strings.Builder

	sb.WriteString("# IOC Extraction Report\n\n")
	sb.WriteString(fmt.Sprintf("**Total IOCs found:** %d\n\n", result.Count))

	if len(result.URLs) > 0 {
		sb.WriteString("## URLs\n\n")
		for _, ioc := range result.URLs {
			sb.WriteString(fmt.Sprintf("- `%s`\n", ioc.Value))
		}
		sb.WriteString("\n")
	}

	if len(result.IPs) > 0 {
		sb.WriteString("## IP Addresses\n\n")
		for _, ioc := range result.IPs {
			sb.WriteString(fmt.Sprintf("- `%s`\n", ioc.Value))
		}
		sb.WriteString("\n")
	}

	if len(result.Domains) > 0 {
		sb.WriteString("## Domains\n\n")
		for _, ioc := range result.Domains {
			sb.WriteString(fmt.Sprintf("- `%s`\n", ioc.Value))
		}
		sb.WriteString("\n")
	}

	if len(result.Paths) > 0 {
		sb.WriteString("## File Paths\n\n")
		for _, ioc := range result.Paths {
			sb.WriteString(fmt.Sprintf("- `%s`\n", ioc.Value))
		}
		sb.WriteString("\n")
	}

	if len(result.Registry) > 0 {
		sb.WriteString("## Registry Keys\n\n")
		for _, ioc := range result.Registry {
			sb.WriteString(fmt.Sprintf("- `%s`\n", ioc.Value))
		}
		sb.WriteString("\n")
	}

	_, err := writer.Write([]byte(sb.String()))
	return err
}
