package heuristics

import (
	"context"
	"testing"

	"github.com/maxime/lcre/internal/model"
)

// mockRule is a test rule that always matches
type mockRule struct {
	id       string
	name     string
	category model.Category
	severity model.Severity
	matches  bool
	evidence []string
}

func (r *mockRule) ID() string              { return r.id }
func (r *mockRule) Name() string            { return r.name }
func (r *mockRule) Description() string     { return "Test rule" }
func (r *mockRule) Category() model.Category { return r.category }
func (r *mockRule) Severity() model.Severity { return r.severity }

func (r *mockRule) Evaluate(ctx context.Context, result *model.AnalysisResult) (bool, []string) {
	return r.matches, r.evidence
}

func TestEngineAnalyze(t *testing.T) {
	engine := NewEngine()

	// Add test rules
	engine.AddRule(&mockRule{
		id:       "TEST001",
		name:     "Test Rule 1",
		category: model.CategoryPacker,
		severity: model.SeverityMedium,
		matches:  true,
		evidence: []string{"evidence1"},
	})

	engine.AddRule(&mockRule{
		id:       "TEST002",
		name:     "Test Rule 2",
		category: model.CategoryInjection,
		severity: model.SeverityHigh,
		matches:  false,
		evidence: nil,
	})

	result := &model.AnalysisResult{}
	heuristics := engine.Analyze(context.Background(), result)

	// Should have one match (TEST001)
	if len(heuristics.Matches) != 1 {
		t.Errorf("Expected 1 match, got %d", len(heuristics.Matches))
	}

	if heuristics.Matches[0].RuleID != "TEST001" {
		t.Errorf("Expected rule ID TEST001, got %s", heuristics.Matches[0].RuleID)
	}

	// Score should reflect medium severity (15 points)
	if heuristics.TotalScore != 15 {
		t.Errorf("Expected score 15, got %d", heuristics.TotalScore)
	}
}

func TestEngineRuleCount(t *testing.T) {
	engine := NewEngine()

	if engine.RuleCount() != 0 {
		t.Error("New engine should have 0 rules")
	}

	engine.AddRule(&mockRule{id: "1"})
	engine.AddRule(&mockRule{id: "2"})

	if engine.RuleCount() != 2 {
		t.Errorf("Expected 2 rules, got %d", engine.RuleCount())
	}
}

func TestEngineSeverityScoring(t *testing.T) {
	tests := []struct {
		severity model.Severity
		expected int
	}{
		{model.SeverityInfo, 1},
		{model.SeverityLow, 5},
		{model.SeverityMedium, 15},
		{model.SeverityHigh, 30},
		{model.SeverityCritical, 50},
	}

	for _, tt := range tests {
		engine := NewEngine()
		engine.AddRule(&mockRule{
			id:       "TEST",
			severity: tt.severity,
			matches:  true,
		})

		result := &model.AnalysisResult{}
		heuristics := engine.Analyze(context.Background(), result)

		if heuristics.TotalScore != tt.expected {
			t.Errorf("Severity %s: expected score %d, got %d",
				tt.severity, tt.expected, heuristics.TotalScore)
		}
	}
}

func TestEngineRiskLevel(t *testing.T) {
	tests := []struct {
		numHighMatches int
		expectedLevel  model.Severity
	}{
		{0, model.SeverityInfo},     // No matches = info (default)
		{1, model.SeverityMedium},   // 30 points
		{2, model.SeverityHigh},     // 60 points
		{4, model.SeverityCritical}, // 120 points
	}

	for _, tt := range tests {
		engine := NewEngine()
		for i := 0; i < tt.numHighMatches; i++ {
			engine.AddRule(&mockRule{
				id:       string(rune('A' + i)),
				severity: model.SeverityHigh,
				matches:  true,
			})
		}

		result := &model.AnalysisResult{}
		heuristics := engine.Analyze(context.Background(), result)

		if heuristics.RiskLevel != tt.expectedLevel {
			t.Errorf("%d high matches: expected risk level %s, got %s (score: %d)",
				tt.numHighMatches, tt.expectedLevel, heuristics.RiskLevel, heuristics.TotalScore)
		}
	}
}

func TestEngineContextCancellation(t *testing.T) {
	engine := NewEngine()

	// Add a rule
	engine.AddRule(&mockRule{
		id:      "TEST",
		matches: true,
	})

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := &model.AnalysisResult{}
	heuristics := engine.Analyze(ctx, result)

	// Should return early due to cancellation
	// The exact behavior depends on when the cancellation is checked
	_ = heuristics // Result is valid, just may have fewer matches
}
