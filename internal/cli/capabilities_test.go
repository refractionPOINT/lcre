package cli

import (
	"encoding/json"
	"testing"
)

func TestBuildCapabilitiesOutput(t *testing.T) {
	output := buildCapabilitiesOutput()

	if output == nil {
		t.Fatal("buildCapabilitiesOutput() returned nil")
	}

	// Check basic fields
	if output.Version == "" {
		t.Error("Version should not be empty")
	}
	if output.Tool != "lcre" {
		t.Errorf("Tool = %q, want %q", output.Tool, "lcre")
	}
	if output.Description == "" {
		t.Error("Description should not be empty")
	}
}

func TestCapabilitiesGlobalFlags(t *testing.T) {
	output := buildCapabilitiesOutput()

	if len(output.GlobalFlags) == 0 {
		t.Fatal("GlobalFlags should not be empty")
	}

	// Check that expected global flags are present
	expectedFlags := map[string]bool{
		"--output":  false,
		"--verbose": false,
		"--timeout": false,
	}

	for _, flag := range output.GlobalFlags {
		if _, ok := expectedFlags[flag.Name]; ok {
			expectedFlags[flag.Name] = true
		}
	}

	for name, found := range expectedFlags {
		if !found {
			t.Errorf("Expected global flag %q not found", name)
		}
	}
}

func TestCapabilitiesCommands(t *testing.T) {
	output := buildCapabilitiesOutput()

	if len(output.Commands) == 0 {
		t.Fatal("Commands should not be empty")
	}

	// Check that expected top-level commands are present
	expectedCommands := map[string]bool{
		"triage": false,
		"report": false,
		"iocs":   false,
		"diff":   false,
		"ghidra": false,
		"cache":  false,
		"query":  false,
	}

	for _, cmd := range output.Commands {
		if _, ok := expectedCommands[cmd.Name]; ok {
			expectedCommands[cmd.Name] = true
		}
	}

	for name, found := range expectedCommands {
		if !found {
			t.Errorf("Expected command %q not found", name)
		}
	}
}

func TestCapabilitiesQuerySubcommands(t *testing.T) {
	output := buildCapabilitiesOutput()

	var queryCmd *CommandInfo
	for i := range output.Commands {
		if output.Commands[i].Name == "query" {
			queryCmd = &output.Commands[i]
			break
		}
	}

	if queryCmd == nil {
		t.Fatal("query command not found")
	}

	if len(queryCmd.Subcommands) == 0 {
		t.Fatal("query should have subcommands")
	}

	// Check for expected query subcommands
	expectedSubcommands := []string{
		"query summary",
		"query heuristics",
		"query imports",
		"query exports",
		"query sections",
		"query strings",
		"query functions",
		"query decompile",
	}

	subcommandNames := make(map[string]bool)
	for _, sub := range queryCmd.Subcommands {
		subcommandNames[sub.Name] = true
	}

	for _, expected := range expectedSubcommands {
		if !subcommandNames[expected] {
			t.Errorf("Expected query subcommand %q not found", expected)
		}
	}
}

func TestCapabilitiesWorkflows(t *testing.T) {
	output := buildCapabilitiesOutput()

	if len(output.Workflows) == 0 {
		t.Fatal("Workflows should not be empty")
	}

	// Check that expected workflows are present
	expectedWorkflows := map[string]bool{
		"quick_triage":          false,
		"malware_analysis":      false,
		"binary_comparison":     false,
		"ioc_extraction":        false,
		"function_tracing":      false,
		"packed_binary_analysis": false,
	}

	for _, wf := range output.Workflows {
		if _, ok := expectedWorkflows[wf.Name]; ok {
			expectedWorkflows[wf.Name] = true
		}
	}

	for name, found := range expectedWorkflows {
		if !found {
			t.Errorf("Expected workflow %q not found", name)
		}
	}
}

func TestCapabilitiesWorkflowSteps(t *testing.T) {
	output := buildCapabilitiesOutput()

	for _, wf := range output.Workflows {
		if len(wf.Steps) == 0 {
			t.Errorf("Workflow %q has no steps", wf.Name)
			continue
		}

		// Check that steps are ordered starting at 1
		for i, step := range wf.Steps {
			if step.Order != i+1 {
				t.Errorf("Workflow %q step %d has Order=%d, want %d", wf.Name, i, step.Order, i+1)
			}
			if step.Command == "" {
				t.Errorf("Workflow %q step %d has empty Command", wf.Name, i+1)
			}
			if step.Description == "" {
				t.Errorf("Workflow %q step %d has empty Description", wf.Name, i+1)
			}
		}
	}
}

func TestCapabilitiesJSONSerialization(t *testing.T) {
	output := buildCapabilitiesOutput()

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal capabilities: %v", err)
	}

	if len(data) == 0 {
		t.Error("Serialized JSON should not be empty")
	}

	// Verify it can be unmarshaled back
	var decoded CapabilitiesOutput
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal capabilities: %v", err)
	}

	if decoded.Tool != output.Tool {
		t.Errorf("Roundtrip failed: Tool = %q, want %q", decoded.Tool, output.Tool)
	}
	if len(decoded.Commands) != len(output.Commands) {
		t.Errorf("Roundtrip failed: Commands count = %d, want %d", len(decoded.Commands), len(output.Commands))
	}
}

func TestCapabilitiesExamples(t *testing.T) {
	output := buildCapabilitiesOutput()

	// Check that some commands have examples
	hasExamples := false
	for _, cmd := range output.Commands {
		if len(cmd.Examples) > 0 {
			hasExamples = true
			for _, ex := range cmd.Examples {
				if ex.Command == "" {
					t.Errorf("Command %q has example with empty Command", cmd.Name)
				}
				if ex.Description == "" {
					t.Errorf("Command %q has example with empty Description", cmd.Name)
				}
			}
		}
		// Check subcommands for examples
		for _, sub := range cmd.Subcommands {
			if len(sub.Examples) > 0 {
				hasExamples = true
				for _, ex := range sub.Examples {
					if ex.Command == "" {
						t.Errorf("Subcommand %q has example with empty Command", sub.Name)
					}
				}
			}
		}
	}

	if !hasExamples {
		t.Error("Expected at least some commands to have examples")
	}
}

func TestExtractGlobalFlags(t *testing.T) {
	flags := extractGlobalFlags(rootCmd)

	if len(flags) == 0 {
		t.Error("extractGlobalFlags should return flags")
	}

	for _, flag := range flags {
		if flag.Name == "" {
			t.Error("Flag name should not be empty")
		}
		if flag.Type == "" {
			t.Error("Flag type should not be empty")
		}
	}
}

func TestShorthandStr(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"o", "-o"},
		{"v", "-v"},
	}

	for _, tt := range tests {
		result := shorthandStr(tt.input)
		if result != tt.expected {
			t.Errorf("shorthandStr(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestGetWorkflows(t *testing.T) {
	workflows := getWorkflows()

	if len(workflows) == 0 {
		t.Error("getWorkflows should return workflows")
	}

	for _, wf := range workflows {
		if wf.Name == "" {
			t.Error("Workflow name should not be empty")
		}
		if wf.Description == "" {
			t.Errorf("Workflow %q should have a description", wf.Name)
		}
		if wf.WhenToUse == "" {
			t.Errorf("Workflow %q should have WhenToUse guidance", wf.Name)
		}
		if len(wf.Steps) == 0 {
			t.Errorf("Workflow %q should have steps", wf.Name)
		}
	}
}

func TestGetExamplesForCommand(t *testing.T) {
	// Test commands that should have examples
	commandsWithExamples := []string{"triage", "report", "query summary", "diff"}

	for _, cmd := range commandsWithExamples {
		examples := getExamplesForCommand(cmd)
		if len(examples) == 0 {
			t.Errorf("getExamplesForCommand(%q) should return examples", cmd)
		}
	}

	// Test unknown command returns nil
	examples := getExamplesForCommand("nonexistent")
	if examples != nil {
		t.Error("getExamplesForCommand for unknown command should return nil")
	}
}
