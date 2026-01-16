package rules

import (
	"context"
	"fmt"
	"strings"

	"github.com/maxime/lcre/internal/model"
)

// Known packer section names
var packerSections = map[string]string{
	"UPX0":     "UPX",
	"UPX1":     "UPX",
	"UPX2":     "UPX",
	".upx":     "UPX",
	".aspack":  "ASPack",
	".adata":   "ASPack",
	"ASPack":   "ASPack",
	".MPRESS1": "MPRESS",
	".MPRESS2": "MPRESS",
	".vmp0":    "VMProtect",
	".vmp1":    "VMProtect",
	".vmp2":    "VMProtect",
	".themida": "Themida",
	".enigma1": "Enigma",
	".enigma2": "Enigma",
	".nsp0":    "NsPack",
	".nsp1":    "NsPack",
	".nsp2":    "NsPack",
	".petite":  "Petite",
	".pec":     "PECompact",
	".pec1":    "PECompact",
	".pec2":    "PECompact",
	"BitArts":  "Crunch/BitArts",
	".perplex": "Perplex",
	".spack":   "Simple Pack",
	".svkp":    "SVK Protector",
	".yP":      "Y0da Protector",
	"_winzip_": "WinZip SFX",
	".rsrc":    "", // Not a packer, but common section
}

// PackerSectionsRule detects packers by section names
type PackerSectionsRule struct{}

// NewPackerSectionsRule creates a new packer sections rule
func NewPackerSectionsRule() *PackerSectionsRule {
	return &PackerSectionsRule{}
}

func (r *PackerSectionsRule) ID() string           { return "PACKER001" }
func (r *PackerSectionsRule) Name() string         { return "Packer Sections" }
func (r *PackerSectionsRule) Category() model.Category { return model.CategoryPacker }
func (r *PackerSectionsRule) Severity() model.Severity { return model.SeverityMedium }

func (r *PackerSectionsRule) Description() string {
	return "Binary contains section names associated with known packers/protectors"
}

func (r *PackerSectionsRule) Evaluate(ctx context.Context, result *model.AnalysisResult) (bool, []string) {
	var evidence []string
	detected := make(map[string]bool)

	for _, section := range result.Sections {
		name := strings.TrimSpace(section.Name)
		if packer, ok := packerSections[name]; ok && packer != "" {
			if !detected[packer] {
				detected[packer] = true
				evidence = append(evidence, "Section '"+name+"' indicates "+packer)
			}
		}
	}

	return len(evidence) > 0, evidence
}

// HighEntropyRule detects high entropy sections
type HighEntropyRule struct {
	threshold float64
}

// NewHighEntropyRule creates a new high entropy rule
func NewHighEntropyRule() *HighEntropyRule {
	return &HighEntropyRule{threshold: 7.0}
}

func (r *HighEntropyRule) ID() string           { return "PACKER002" }
func (r *HighEntropyRule) Name() string         { return "High Entropy Sections" }
func (r *HighEntropyRule) Category() model.Category { return model.CategoryPacker }
func (r *HighEntropyRule) Severity() model.Severity { return model.SeverityMedium }

func (r *HighEntropyRule) Description() string {
	return "Binary contains sections with high entropy suggesting encryption or packing"
}

func (r *HighEntropyRule) Evaluate(ctx context.Context, result *model.AnalysisResult) (bool, []string) {
	var evidence []string

	for _, section := range result.Sections {
		if section.Entropy > r.threshold {
			evidence = append(evidence,
				"Section '"+section.Name+"' has entropy "+
				formatFloat(section.Entropy)+" (threshold: "+formatFloat(r.threshold)+")")
		}
	}

	return len(evidence) > 0, evidence
}

func formatFloat(f float64) string {
	return strings.TrimRight(strings.TrimRight(
		fmt.Sprintf("%.2f", f), "0"), ".")
}
