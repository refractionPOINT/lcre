package native

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/refractionPOINT/lcre/internal/backend"
	"github.com/refractionPOINT/lcre/internal/model"
	"github.com/refractionPOINT/lcre/internal/util"
)

// Backend implements native Go binary parsing
type Backend struct{}

// New creates a new native backend
func New() *Backend {
	return &Backend{}
}

// Name returns the backend name
func (b *Backend) Name() string {
	return "native"
}

// Capabilities returns what this backend can do
func (b *Backend) Capabilities() backend.Capabilities {
	return backend.Capabilities{
		ParseHeaders:   true,
		ParseImports:   true,
		ParseExports:   true,
		ExtractStrings: true,
		CalcEntropy:    true,
		Decompile:      false,
		CallGraph:      false,
		CrossRefs:      false,
	}
}

// Available checks if the backend is available
func (b *Backend) Available() (bool, string) {
	return true, "native Go parsing always available"
}

// Analyze performs analysis on the given binary
func (b *Backend) Analyze(ctx context.Context, path string, opts backend.AnalysisOptions) (*model.AnalysisResult, error) {
	start := time.Now()

	result := &model.AnalysisResult{
		Backend:   b.Name(),
		Timestamp: start,
	}

	// Compute hashes
	hashes, err := util.HashFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to hash file: %w", err)
	}

	// Get file size
	size, err := util.FileSize(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get file size: %w", err)
	}

	// Detect format
	format, err := util.DetectFormat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to detect format: %w", err)
	}

	result.Metadata = model.BinaryMetadata{
		Path:   path,
		Name:   filepath.Base(path),
		Size:   size,
		MD5:    hashes.MD5,
		SHA1:   hashes.SHA1,
		SHA256: hashes.SHA256,
		Format: format,
	}

	// Parse based on format
	switch format {
	case model.FormatPE:
		if err := parsePE(ctx, path, result); err != nil {
			result.AddError(fmt.Sprintf("PE parsing error: %v", err))
		}
	case model.FormatELF:
		if err := parseELF(ctx, path, result); err != nil {
			result.AddError(fmt.Sprintf("ELF parsing error: %v", err))
		}
	case model.FormatMachO:
		if err := parseMachO(ctx, path, result); err != nil {
			result.AddError(fmt.Sprintf("Mach-O parsing error: %v", err))
		}
	default:
		result.AddError(fmt.Sprintf("unsupported binary format: %s", format))
	}

	// Extract strings if requested
	if opts.IncludeStrings {
		strings, err := ExtractStrings(path, opts.MinStringLength, opts.MaxStrings)
		if err != nil {
			result.AddError(fmt.Sprintf("string extraction error: %v", err))
		} else {
			result.Strings = strings
		}
	}

	// Calculate section entropy
	for i := range result.Sections {
		if err := calculateSectionEntropy(path, &result.Sections[i]); err != nil {
			result.AddError(fmt.Sprintf("entropy calculation error for %s: %v", result.Sections[i].Name, err))
		}
	}

	result.Duration = time.Since(start).Seconds()
	return result, nil
}

// Register registers this backend with the default registry
func Register() {
	backend.DefaultRegistry.Register(New())
}

func init() {
	Register()
}
