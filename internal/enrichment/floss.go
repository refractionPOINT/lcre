package enrichment

import (
	"encoding/json"

	"github.com/refractionPOINT/lcre/internal/model"
)

func init() {
	RegisterParser(&FLOSSParser{})
}

// FLOSSParser parses FLARE Obfuscated String Solver (floss) JSON output.
type FLOSSParser struct{}

func (p *FLOSSParser) ToolName() string { return "floss" }

// flossOutput represents the top-level floss JSON structure.
type flossOutput struct {
	Strings flossStrings `json:"strings"`
}

type flossStrings struct {
	StaticStrings  []flossString `json:"static_strings"`
	StackStrings   []flossString `json:"stack_strings"`
	TightStrings   []flossString `json:"tight_strings"`
	DecodedStrings []flossString `json:"decoded_strings"`
}

type flossString struct {
	String   string `json:"string"`
	Offset   uint64 `json:"offset"`
	Encoding string `json:"encoding"`
	Function string `json:"function,omitempty"`
}

func (p *FLOSSParser) Parse(data []byte) (*Result, error) {
	var output flossOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, err
	}

	var strings []model.ExtractedString

	// Import decoded and obfuscated strings — the high-value ones FLOSS
	// finds that basic string extraction misses.
	for _, s := range output.Strings.StackStrings {
		strings = append(strings, model.ExtractedString{
			Value:    s.String,
			Offset:   s.Offset,
			Encoding: s.Encoding,
			Section:  "floss:stack",
		})
	}
	for _, s := range output.Strings.TightStrings {
		strings = append(strings, model.ExtractedString{
			Value:    s.String,
			Offset:   s.Offset,
			Encoding: s.Encoding,
			Section:  "floss:tight",
		})
	}
	for _, s := range output.Strings.DecodedStrings {
		strings = append(strings, model.ExtractedString{
			Value:    s.String,
			Offset:   s.Offset,
			Encoding: s.Encoding,
			Section:  "floss:decoded",
		})
	}

	return &Result{
		Strings: strings,
	}, nil
}
