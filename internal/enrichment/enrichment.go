// Package enrichment provides parsers for external analysis tool output.
// It enables the agent-mediated workflow where an AI agent runs tools
// (e.g., via REMnux MCP) and feeds their output back into LCRE's cache.
package enrichment

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/refractionPOINT/lcre/internal/model"
)

// ToolParser parses output from a specific tool into LCRE model types.
type ToolParser interface {
	// ToolName returns the canonical name of the tool this parser handles.
	ToolName() string
	// Parse reads tool output and extracts structured data.
	Parse(data []byte) (*Result, error)
}

// Result holds the parsed output from an external tool.
// Each field is optional; parsers populate only what they extract.
type Result struct {
	// Capabilities extracted (e.g., from capa)
	Capabilities []model.Capability `json:"capabilities,omitempty"`
	// Packer/compiler detections (e.g., from diec)
	Detections []model.PackerDetection `json:"detections,omitempty"`
	// Additional strings discovered (e.g., from floss)
	Strings []model.ExtractedString `json:"strings,omitempty"`
	// Raw output preserved for generic storage (JSON or plain text)
	RawJSON string `json:"raw_output,omitempty"`
}

// registry maps tool names to their parsers.
var registry = map[string]ToolParser{}

// RegisterParser adds a parser to the global registry.
func RegisterParser(p ToolParser) {
	registry[p.ToolName()] = p
}

// GetParser returns the parser for a given tool name, or nil if unknown.
func GetParser(tool string) ToolParser {
	return registry[tool]
}

// KnownTools returns all tool names with registered parsers.
func KnownTools() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}

// ParseToolOutput reads a file and parses it using the appropriate parser.
// If a parser is registered for the tool, the data must be valid JSON for
// parsing into structured types. For unknown tools, any format (JSON or
// plain text) is accepted and stored as raw output.
func ParseToolOutput(tool string, inputPath string) (*Result, error) {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, fmt.Errorf("read input file: %w", err)
	}

	parser := GetParser(tool)
	if parser != nil {
		// Dedicated parsers expect JSON
		if !json.Valid(data) {
			return nil, fmt.Errorf("%s parser requires JSON input", tool)
		}
		result, err := parser.Parse(data)
		if err != nil {
			return nil, fmt.Errorf("parse %s output: %w", tool, err)
		}
		result.RawJSON = string(data)
		return result, nil
	}

	// No parser — store raw output as-is (JSON or plain text)
	return &Result{
		RawJSON: string(data),
	}, nil
}
