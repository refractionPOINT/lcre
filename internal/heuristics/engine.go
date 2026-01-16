package heuristics

import (
	"context"

	"github.com/maxime/lcre/internal/model"
)

// Rule is the interface that all heuristic rules must implement
type Rule interface {
	// ID returns the unique rule identifier
	ID() string

	// Name returns a human-readable rule name
	Name() string

	// Description returns what this rule detects
	Description() string

	// Category returns the rule category
	Category() model.Category

	// Severity returns the default severity of matches
	Severity() model.Severity

	// Evaluate checks if the rule matches and returns evidence
	Evaluate(ctx context.Context, result *model.AnalysisResult) (matched bool, evidence []string)
}

// Engine runs heuristic analysis on binary analysis results
type Engine struct {
	rules []Rule
}

// NewEngine creates a new heuristics engine
func NewEngine() *Engine {
	return &Engine{
		rules: make([]Rule, 0),
	}
}

// AddRule adds a rule to the engine
func (e *Engine) AddRule(rule Rule) {
	e.rules = append(e.rules, rule)
}

// AddRules adds multiple rules to the engine
func (e *Engine) AddRules(rules ...Rule) {
	e.rules = append(e.rules, rules...)
}

// Analyze runs all rules against the analysis result
func (e *Engine) Analyze(ctx context.Context, result *model.AnalysisResult) *model.HeuristicsResult {
	heuristics := &model.HeuristicsResult{
		Matches:   make([]model.HeuristicMatch, 0),
		RiskLevel: model.SeverityInfo, // Default risk level
	}

	for _, rule := range e.rules {
		select {
		case <-ctx.Done():
			return heuristics
		default:
		}

		matched, evidence := rule.Evaluate(ctx, result)
		if matched {
			heuristics.AddMatch(model.HeuristicMatch{
				RuleID:      rule.ID(),
				Name:        rule.Name(),
				Description: rule.Description(),
				Severity:    rule.Severity(),
				Category:    rule.Category(),
				Evidence:    evidence,
			})
		}
	}

	// Generate summary
	e.generateSummary(heuristics)

	return heuristics
}

// generateSummary creates a text summary of the findings
func (e *Engine) generateSummary(h *model.HeuristicsResult) {
	if len(h.Matches) == 0 {
		h.Summary = "No suspicious indicators detected."
		return
	}

	// Count by category
	categories := make(map[model.Category]int)
	for _, m := range h.Matches {
		categories[m.Category]++
	}

	summary := ""
	if count, ok := categories[model.CategoryPacker]; ok && count > 0 {
		summary += "Possible packing/obfuscation detected. "
	}
	if count, ok := categories[model.CategoryInjection]; ok && count > 0 {
		summary += "Process injection capabilities detected. "
	}
	if count, ok := categories[model.CategoryAntiDebug]; ok && count > 0 {
		summary += "Anti-debugging techniques present. "
	}
	if count, ok := categories[model.CategoryPersistence]; ok && count > 0 {
		summary += "Persistence mechanisms detected. "
	}
	if count, ok := categories[model.CategoryCrypto]; ok && count > 0 {
		summary += "Cryptographic operations detected. "
	}
	if count, ok := categories[model.CategoryNetwork]; ok && count > 0 {
		summary += "Network IOCs found in strings. "
	}

	if summary == "" {
		summary = "Suspicious indicators detected - manual review recommended."
	}

	h.Summary = summary
}

// RuleCount returns the number of registered rules
func (e *Engine) RuleCount() int {
	return len(e.rules)
}

// Rules returns all registered rules
func (e *Engine) Rules() []Rule {
	return e.rules
}
