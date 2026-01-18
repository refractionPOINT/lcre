package backend

import (
	"context"
	"time"

	"github.com/maxime/lcre/internal/model"
)

// Capabilities describes what a backend can analyze
type Capabilities struct {
	ParseHeaders   bool `json:"parse_headers"`
	ParseImports   bool `json:"parse_imports"`
	ParseExports   bool `json:"parse_exports"`
	ExtractStrings bool `json:"extract_strings"`
	CalcEntropy    bool `json:"calc_entropy"`
	Decompile      bool `json:"decompile"`
	CallGraph      bool `json:"call_graph"`
	CrossRefs      bool `json:"cross_refs"`
}

// AnalysisOptions configures the analysis
type AnalysisOptions struct {
	Timeout         time.Duration
	WorkspacePath   string
	IncludeStrings  bool
	MinStringLength int
	MaxStrings      int
	DeepAnalysis    bool
}

// DefaultOptions returns default analysis options
func DefaultOptions() AnalysisOptions {
	return AnalysisOptions{
		Timeout:         120 * time.Second,
		IncludeStrings:  true,
		MinStringLength: 4,
		MaxStrings:      10000,
		DeepAnalysis:    false,
	}
}

// Backend is the interface that all analysis backends must implement
type Backend interface {
	// Name returns the backend name
	Name() string

	// Capabilities returns what this backend can do
	Capabilities() Capabilities

	// Available checks if the backend is available
	// Returns true if available, or false with a reason message
	Available() (bool, string)

	// Analyze performs analysis on the given binary
	Analyze(ctx context.Context, path string, opts AnalysisOptions) (*model.AnalysisResult, error)
}
