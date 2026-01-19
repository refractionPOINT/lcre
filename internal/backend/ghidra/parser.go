package ghidra

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/refractionPOINT/lcre/internal/model"
)

// GhidraOutput represents the JSON output from ExportAnalysis.java
type GhidraOutput struct {
	Program     ProgramInfo     `json:"program"`
	Functions   []FunctionInfo  `json:"functions"`
	Imports     []ImportInfo    `json:"imports"`
	Exports     []ExportInfo    `json:"exports"`
	Strings     []StringInfo    `json:"strings"`
	EntryPoints []EntryInfo     `json:"entry_points"`
	CallGraph   *CallGraphInfo  `json:"call_graph,omitempty"`
	Sections    []SectionInfo   `json:"sections"`
}

// ProgramInfo contains program metadata from Ghidra
type ProgramInfo struct {
	Name        string `json:"name"`
	Language    string `json:"language"`
	Compiler    string `json:"compiler"`
	ImageBase   uint64 `json:"image_base"`
	MinAddress  uint64 `json:"min_address"`
	MaxAddress  uint64 `json:"max_address"`
	Endian      string `json:"endian"`
	PointerSize int    `json:"pointer_size"`
}

// FunctionInfo contains function data from Ghidra
type FunctionInfo struct {
	Name       string   `json:"name"`
	Address    uint64   `json:"address"`
	Size       uint64   `json:"size"`
	Signature  string   `json:"signature"`
	Callers    []uint64 `json:"callers"`
	Callees    []uint64 `json:"callees"`
	IsExternal bool     `json:"is_external"`
	IsThunk    bool     `json:"is_thunk"`
}

// ImportInfo contains import data from Ghidra
type ImportInfo struct {
	Library  string `json:"library"`
	Name     string `json:"name"`
	Address  uint64 `json:"address"`
	Ordinal  int    `json:"ordinal"`
}

// ExportInfo contains export data from Ghidra
type ExportInfo struct {
	Name    string `json:"name"`
	Address uint64 `json:"address"`
	Ordinal int    `json:"ordinal"`
}

// StringInfo contains string data from Ghidra
type StringInfo struct {
	Value   string   `json:"value"`
	Address uint64   `json:"address"`
	Length  int      `json:"length"`
	XRefs   []uint64 `json:"xrefs"`
}

// EntryInfo contains entry point data
type EntryInfo struct {
	Name    string `json:"name"`
	Address uint64 `json:"address"`
	Type    string `json:"type"`
}

// CallGraphInfo contains call graph data
type CallGraphInfo struct {
	Nodes []CallGraphNode `json:"nodes"`
	Edges []CallGraphEdge `json:"edges"`
}

// CallGraphNode represents a function in the call graph
type CallGraphNode struct {
	Address uint64 `json:"address"`
	Name    string `json:"name"`
}

// CallGraphEdge represents a call edge
type CallGraphEdge struct {
	From uint64 `json:"from"`
	To   uint64 `json:"to"`
}

// SectionInfo contains section data from Ghidra
type SectionInfo struct {
	Name        string `json:"name"`
	Start       uint64 `json:"start"`
	End         uint64 `json:"end"`
	Size        uint64 `json:"size"`
	Permissions string `json:"permissions"`
}

// Parser parses Ghidra output JSON
type Parser struct{}

// ParseFile parses a Ghidra JSON output file
func (p *Parser) ParseFile(path string) (*model.AnalysisResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read output file: %w", err)
	}

	return p.Parse(data)
}

// Parse parses Ghidra JSON output bytes
func (p *Parser) Parse(data []byte) (*model.AnalysisResult, error) {
	var ghidraOutput GhidraOutput
	if err := json.Unmarshal(data, &ghidraOutput); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	result := &model.AnalysisResult{}

	// Convert program info to metadata
	result.Metadata = p.convertMetadata(&ghidraOutput.Program)

	// Convert sections
	for _, sec := range ghidraOutput.Sections {
		result.Sections = append(result.Sections, model.Section{
			Name:        sec.Name,
			VirtualAddr: sec.Start,
			VirtualSize: sec.Size,
			RawSize:     sec.Size,
			Permissions: sec.Permissions,
		})
	}

	// Convert imports
	for _, imp := range ghidraOutput.Imports {
		result.Imports = append(result.Imports, model.Import{
			Library:  imp.Library,
			Function: imp.Name,
			Address:  imp.Address,
			Ordinal:  imp.Ordinal,
		})
	}

	// Convert exports
	for _, exp := range ghidraOutput.Exports {
		result.Exports = append(result.Exports, model.Export{
			Name:    exp.Name,
			Address: exp.Address,
			Ordinal: exp.Ordinal,
		})
	}

	// Convert strings
	for _, str := range ghidraOutput.Strings {
		result.Strings = append(result.Strings, model.ExtractedString{
			Value:  str.Value,
			Offset: str.Address,
			XRefs:  str.XRefs,
		})
	}

	// Convert functions
	for _, fn := range ghidraOutput.Functions {
		result.Functions = append(result.Functions, model.Function{
			Name:       fn.Name,
			Address:    fn.Address,
			Size:       fn.Size,
			Signature:  fn.Signature,
			Callers:    fn.Callers,
			Callees:    fn.Callees,
			IsExternal: fn.IsExternal,
			IsThunk:    fn.IsThunk,
		})
	}

	// Convert call graph
	if ghidraOutput.CallGraph != nil {
		result.CallGraph = &model.CallGraph{
			Nodes: make([]model.CallGraphNode, len(ghidraOutput.CallGraph.Nodes)),
			Edges: make([]model.CallGraphEdge, len(ghidraOutput.CallGraph.Edges)),
		}
		for i, node := range ghidraOutput.CallGraph.Nodes {
			result.CallGraph.Nodes[i] = model.CallGraphNode{
				Address: node.Address,
				Name:    node.Name,
			}
		}
		for i, edge := range ghidraOutput.CallGraph.Edges {
			result.CallGraph.Edges[i] = model.CallGraphEdge{
				From: edge.From,
				To:   edge.To,
			}
		}
	}

	// Convert entry points
	for _, ep := range ghidraOutput.EntryPoints {
		result.EntryPoints = append(result.EntryPoints, model.EntryPoint{
			Name:    ep.Name,
			Address: ep.Address,
			Type:    ep.Type,
		})
	}

	return result, nil
}

// convertMetadata converts Ghidra program info to our metadata format
func (p *Parser) convertMetadata(prog *ProgramInfo) model.BinaryMetadata {
	meta := model.BinaryMetadata{
		Compiler: prog.Compiler,
		Endian:   prog.Endian,
	}

	// Determine format and architecture from language
	// Ghidra language IDs are like "x86:LE:64:default"
	lang := prog.Language
	if lang != "" {
		// Parse architecture from language
		switch {
		case contains(lang, "x86") && contains(lang, "64"):
			meta.Arch = "x86_64"
			meta.Bits = 64
		case contains(lang, "x86"):
			meta.Arch = "x86"
			meta.Bits = 32
		case contains(lang, "ARM") && contains(lang, "64"):
			meta.Arch = "ARM64"
			meta.Bits = 64
		case contains(lang, "ARM"):
			meta.Arch = "ARM"
			meta.Bits = 32
		case contains(lang, "MIPS"):
			meta.Arch = "MIPS"
			if prog.PointerSize == 8 {
				meta.Bits = 64
			} else {
				meta.Bits = 32
			}
		default:
			meta.Arch = lang
			meta.Bits = prog.PointerSize * 8
		}
	}

	return meta
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
