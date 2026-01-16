package model

import (
	"testing"
)

func TestHeuristicsResultAddMatch(t *testing.T) {
	h := &HeuristicsResult{}

	h.AddMatch(HeuristicMatch{
		RuleID:   "TEST001",
		Severity: SeverityMedium,
	})

	if len(h.Matches) != 1 {
		t.Errorf("Expected 1 match, got %d", len(h.Matches))
	}

	if h.TotalScore != 15 {
		t.Errorf("Expected score 15 for medium severity, got %d", h.TotalScore)
	}
}

func TestHeuristicsResultScoring(t *testing.T) {
	h := &HeuristicsResult{}

	// Add matches of different severities
	h.AddMatch(HeuristicMatch{RuleID: "1", Severity: SeverityInfo})     // +1
	h.AddMatch(HeuristicMatch{RuleID: "2", Severity: SeverityLow})      // +5
	h.AddMatch(HeuristicMatch{RuleID: "3", Severity: SeverityMedium})   // +15
	h.AddMatch(HeuristicMatch{RuleID: "4", Severity: SeverityHigh})     // +30
	h.AddMatch(HeuristicMatch{RuleID: "5", Severity: SeverityCritical}) // +50

	expectedScore := 1 + 5 + 15 + 30 + 50
	if h.TotalScore != expectedScore {
		t.Errorf("Expected total score %d, got %d", expectedScore, h.TotalScore)
	}
}

func TestHeuristicsResultRiskLevel(t *testing.T) {
	tests := []struct {
		numMatches int
		severity   Severity
		expected   Severity
	}{
		{0, SeverityInfo, SeverityInfo},         // No matches = info (default)
		{5, SeverityInfo, SeverityInfo},         // 5 points = info
		{10, SeverityInfo, SeverityLow},         // 10 points = low
		{3, SeverityMedium, SeverityMedium},     // 45 points = medium (25-49)
		{2, SeverityHigh, SeverityHigh},         // 60 points = high (50-99)
		{2, SeverityCritical, SeverityCritical}, // 100 points = critical
	}

	for _, tt := range tests {
		h := &HeuristicsResult{RiskLevel: SeverityInfo} // Initialize with default
		for i := 0; i < tt.numMatches; i++ {
			h.AddMatch(HeuristicMatch{Severity: tt.severity})
		}

		if h.RiskLevel != tt.expected {
			t.Errorf("%d matches of %s: expected risk level %s, got %s (score: %d)",
				tt.numMatches, tt.severity, tt.expected, h.RiskLevel, h.TotalScore)
		}
	}
}

func TestHeuristicsResultHasMatches(t *testing.T) {
	h := &HeuristicsResult{}

	if h.HasMatches() {
		t.Error("Empty result should not have matches")
	}

	h.AddMatch(HeuristicMatch{RuleID: "TEST"})

	if !h.HasMatches() {
		t.Error("Result with match should have matches")
	}
}

func TestHeuristicsResultMatchesByCategory(t *testing.T) {
	h := &HeuristicsResult{}

	h.AddMatch(HeuristicMatch{RuleID: "1", Category: CategoryPacker})
	h.AddMatch(HeuristicMatch{RuleID: "2", Category: CategoryPacker})
	h.AddMatch(HeuristicMatch{RuleID: "3", Category: CategoryInjection})

	packerMatches := h.MatchesByCategory(CategoryPacker)
	if len(packerMatches) != 2 {
		t.Errorf("Expected 2 packer matches, got %d", len(packerMatches))
	}

	injectionMatches := h.MatchesByCategory(CategoryInjection)
	if len(injectionMatches) != 1 {
		t.Errorf("Expected 1 injection match, got %d", len(injectionMatches))
	}

	cryptoMatches := h.MatchesByCategory(CategoryCrypto)
	if len(cryptoMatches) != 0 {
		t.Errorf("Expected 0 crypto matches, got %d", len(cryptoMatches))
	}
}
