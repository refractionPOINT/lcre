package enrichment

import (
	"encoding/json"

	"github.com/refractionPOINT/lcre/internal/model"
)

func init() {
	RegisterParser(&CapaParser{})
}

// CapaParser parses capa JSON output (capa -j <binary>).
type CapaParser struct{}

func (p *CapaParser) ToolName() string { return "capa" }

// capaOutput represents the top-level capa JSON structure.
type capaOutput struct {
	Rules map[string]capaRule `json:"rules"`
}

type capaRule struct {
	Meta    capaRuleMeta `json:"meta"`
	Source  string       `json:"source"`
}

type capaRuleMeta struct {
	Name      string          `json:"name"`
	Namespace string          `json:"namespace"`
	Authors   []string        `json:"authors"`
	Scopes    capaScopes      `json:"scopes"`
	AttackArr json.RawMessage `json:"att&ck"`
	MBCArr    json.RawMessage `json:"mbc"`
	Attack    json.RawMessage `json:"attack"`
}

type capaScopes struct {
	Static  string `json:"static"`
	Dynamic string `json:"dynamic"`
}

type capaAttackEntry struct {
	Technique    string `json:"technique"`
	Subtechnique string `json:"subtechnique"`
	ID           string `json:"id"`
}

type capaMBCEntry struct {
	Objective string `json:"objective"`
	Behavior  string `json:"behavior"`
	ID        string `json:"id"`
}

func (p *CapaParser) Parse(data []byte) (*Result, error) {
	var output capaOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, err
	}

	var caps []model.Capability
	for _, rule := range output.Rules {
		cap := model.Capability{
			Name:      rule.Meta.Name,
			Namespace: rule.Meta.Namespace,
		}
		if len(rule.Meta.Authors) > 0 {
			cap.Author = rule.Meta.Authors[0]
		}
		if rule.Meta.Scopes.Static != "" {
			cap.Scope = rule.Meta.Scopes.Static
		}

		// Parse ATT&CK entries — try both "att&ck" and "attack" keys
		attackData := rule.Meta.AttackArr
		if attackData == nil {
			attackData = rule.Meta.Attack
		}
		if attackData != nil {
			var attacks []capaAttackEntry
			if json.Unmarshal(attackData, &attacks) == nil {
				for _, a := range attacks {
					if a.ID != "" {
						cap.AttackIDs = append(cap.AttackIDs, a.ID)
					}
				}
			}
		}

		// Parse MBC entries
		if rule.Meta.MBCArr != nil {
			var mbcs []capaMBCEntry
			if json.Unmarshal(rule.Meta.MBCArr, &mbcs) == nil {
				for _, m := range mbcs {
					if m.ID != "" {
						cap.MBCIDs = append(cap.MBCIDs, m.ID)
					}
				}
			}
		}

		caps = append(caps, cap)
	}

	return &Result{
		Capabilities: caps,
	}, nil
}
