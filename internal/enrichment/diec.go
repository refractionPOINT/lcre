package enrichment

import (
	"encoding/json"

	"github.com/refractionPOINT/lcre/internal/model"
)

func init() {
	RegisterParser(&DIECParser{})
}

// DIECParser parses Detect It Easy (diec) JSON output.
type DIECParser struct{}

func (p *DIECParser) ToolName() string { return "diec" }

// diecOutput represents the top-level diec JSON structure.
type diecOutput struct {
	Detects []diecDetect `json:"detects"`
}

type diecDetect struct {
	Filetype string `json:"filetype"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	String   string `json:"string"`
	Version  string `json:"version"`
}

func (p *DIECParser) Parse(data []byte) (*Result, error) {
	var output diecOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, err
	}

	var detections []model.PackerDetection
	for _, d := range output.Detects {
		detections = append(detections, model.PackerDetection{
			Type:    d.Type,
			Name:    d.Name,
			Version: d.Version,
			String:  d.String,
		})
	}

	return &Result{
		Detections: detections,
	}, nil
}
