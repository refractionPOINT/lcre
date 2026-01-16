package model

// Severity represents the severity level of a heuristic match
type Severity string

const (
	SeverityInfo    Severity = "info"
	SeverityLow     Severity = "low"
	SeverityMedium  Severity = "medium"
	SeverityHigh    Severity = "high"
	SeverityCritical Severity = "critical"
)

// Category represents the category of a heuristic rule
type Category string

const (
	CategoryPacker     Category = "packer"
	CategoryAntiDebug  Category = "anti-debug"
	CategoryInjection  Category = "injection"
	CategoryPersistence Category = "persistence"
	CategoryCrypto     Category = "crypto"
	CategoryNetwork    Category = "network"
	CategoryEvasion    Category = "evasion"
	CategoryAnomaly    Category = "anomaly"
)

// HeuristicMatch represents a single heuristic rule match
type HeuristicMatch struct {
	RuleID      string   `json:"rule_id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Category    Category `json:"category"`
	Evidence    []string `json:"evidence,omitempty"`
	References  []string `json:"references,omitempty"`
}

// HeuristicsResult contains all heuristic analysis results
type HeuristicsResult struct {
	Matches     []HeuristicMatch `json:"matches"`
	TotalScore  int              `json:"total_score"`
	RiskLevel   Severity         `json:"risk_level"`
	Summary     string           `json:"summary"`
}

// AddMatch adds a heuristic match to the result
func (h *HeuristicsResult) AddMatch(match HeuristicMatch) {
	h.Matches = append(h.Matches, match)
	h.updateScore()
}

// updateScore recalculates the total score based on matches
func (h *HeuristicsResult) updateScore() {
	h.TotalScore = 0
	for _, m := range h.Matches {
		switch m.Severity {
		case SeverityInfo:
			h.TotalScore += 1
		case SeverityLow:
			h.TotalScore += 5
		case SeverityMedium:
			h.TotalScore += 15
		case SeverityHigh:
			h.TotalScore += 30
		case SeverityCritical:
			h.TotalScore += 50
		}
	}

	// Update risk level based on score
	switch {
	case h.TotalScore >= 100:
		h.RiskLevel = SeverityCritical
	case h.TotalScore >= 50:
		h.RiskLevel = SeverityHigh
	case h.TotalScore >= 25:
		h.RiskLevel = SeverityMedium
	case h.TotalScore >= 10:
		h.RiskLevel = SeverityLow
	default:
		h.RiskLevel = SeverityInfo
	}
}

// HasMatches returns true if there are any heuristic matches
func (h *HeuristicsResult) HasMatches() bool {
	return len(h.Matches) > 0
}

// MatchesByCategory returns matches filtered by category
func (h *HeuristicsResult) MatchesByCategory(cat Category) []HeuristicMatch {
	var result []HeuristicMatch
	for _, m := range h.Matches {
		if m.Category == cat {
			result = append(result, m)
		}
	}
	return result
}
