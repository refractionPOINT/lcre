package rules

import (
	"context"
	"fmt"
	"strings"

	"github.com/maxime/lcre/internal/model"
)

// TinyTextRule detects anomalously small .text sections
type TinyTextRule struct {
	minTextSize uint64
}

func NewTinyTextRule() *TinyTextRule {
	return &TinyTextRule{minTextSize: 1024} // 1KB minimum
}

func (r *TinyTextRule) ID() string              { return "SECTION001" }
func (r *TinyTextRule) Name() string            { return "Tiny Text Section" }
func (r *TinyTextRule) Category() model.Category { return model.CategoryAnomaly }
func (r *TinyTextRule) Severity() model.Severity { return model.SeverityMedium }

func (r *TinyTextRule) Description() string {
	return "Binary has unusually small .text section, suggesting code is elsewhere (packing)"
}

func (r *TinyTextRule) Evaluate(ctx context.Context, result *model.AnalysisResult) (bool, []string) {
	var textSize uint64
	var hasHighEntropySection bool
	var highEntropySize uint64

	for _, sec := range result.Sections {
		name := strings.ToLower(sec.Name)
		if name == ".text" || name == "__text" {
			textSize = sec.RawSize
		}
		if sec.Entropy > 7.0 && sec.RawSize > 10240 { // > 10KB high entropy
			hasHighEntropySection = true
			highEntropySize = sec.RawSize
		}
	}

	// Suspicious: tiny .text with large high-entropy section
	if textSize > 0 && textSize < r.minTextSize && hasHighEntropySection {
		return true, []string{
			fmt.Sprintf(".text section is only %d bytes", textSize),
			fmt.Sprintf("High entropy section is %d bytes", highEntropySize),
		}
	}

	return false, nil
}
