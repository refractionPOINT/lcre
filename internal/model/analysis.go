package model

import "time"

// AnalysisResult is the top-level output structure for binary analysis
type AnalysisResult struct {
	Metadata    BinaryMetadata    `json:"metadata"`
	PEInfo      *PEInfo           `json:"pe_info,omitempty"`
	Sections    []Section         `json:"sections"`
	Imports     []Import          `json:"imports"`
	Exports     []Export          `json:"exports"`
	Strings     []ExtractedString `json:"strings,omitempty"`
	Functions   []Function        `json:"functions,omitempty"`
	CallGraph   *CallGraph        `json:"call_graph,omitempty"`
	EntryPoints []EntryPoint      `json:"entry_points,omitempty"`
	Heuristics  *HeuristicsResult `json:"heuristics,omitempty"`
	Backend     string            `json:"backend"`
	Duration    float64           `json:"duration_seconds"`
	Timestamp   time.Time         `json:"timestamp"`
	Partial     bool              `json:"partial"`
	Errors      []string          `json:"errors,omitempty"`
}

// AddError adds an error message to the result
func (r *AnalysisResult) AddError(err string) {
	r.Errors = append(r.Errors, err)
	r.Partial = true
}

// HasErrors returns true if there are any errors
func (r *AnalysisResult) HasErrors() bool {
	return len(r.Errors) > 0
}
