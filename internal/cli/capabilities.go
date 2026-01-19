package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// CapabilitiesOutput is the top-level structure for the capabilities command output.
type CapabilitiesOutput struct {
	Version     string        `json:"version"`
	Tool        string        `json:"tool"`
	Description string        `json:"description"`
	GlobalFlags []FlagInfo    `json:"global_flags"`
	Commands    []CommandInfo `json:"commands"`
	Workflows   []Workflow    `json:"workflows"`
}

// CommandInfo describes a CLI command and its subcommands.
type CommandInfo struct {
	Name        string        `json:"name"`
	Use         string        `json:"use"`
	Short       string        `json:"short"`
	Long        string        `json:"long,omitempty"`
	Flags       []FlagInfo    `json:"flags,omitempty"`
	Subcommands []CommandInfo `json:"subcommands,omitempty"`
	Examples    []Example     `json:"examples,omitempty"`
}

// FlagInfo describes a CLI flag.
type FlagInfo struct {
	Name        string `json:"name"`
	Shorthand   string `json:"shorthand,omitempty"`
	Default     string `json:"default,omitempty"`
	Description string `json:"description"`
	Type        string `json:"type"`
}

// Example shows a command example.
type Example struct {
	Command     string `json:"command"`
	Description string `json:"description"`
}

// Workflow describes a multi-step investigation workflow.
type Workflow struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	WhenToUse   string         `json:"when_to_use"`
	Steps       []WorkflowStep `json:"steps"`
}

// WorkflowStep is a single step in a workflow.
type WorkflowStep struct {
	Order       int    `json:"order"`
	Command     string `json:"command"`
	Description string `json:"description"`
}

var capabilitiesCmd = &cobra.Command{
	Use:   "capabilities",
	Short: "Output machine-readable capabilities for AI assistants",
	Long: `Outputs comprehensive JSON describing all LCRE commands, flags, and
recommended investigation workflows. Designed for AI assistants like Claude Code
to quickly understand what LCRE can do.`,
	RunE: runCapabilities,
}

func init() {
	rootCmd.AddCommand(capabilitiesCmd)
}

func runCapabilities(cmd *cobra.Command, args []string) error {
	output := buildCapabilitiesOutput()

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal capabilities: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

func buildCapabilitiesOutput() *CapabilitiesOutput {
	return &CapabilitiesOutput{
		Version:     "1.0.0",
		Tool:        "lcre",
		Description: "Binary Forensics CLI for static analysis, malware investigation, and reverse engineering automation",
		GlobalFlags: extractGlobalFlags(rootCmd),
		Commands:    extractCommands(rootCmd),
		Workflows:   getWorkflows(),
	}
}

func extractGlobalFlags(cmd *cobra.Command) []FlagInfo {
	var flags []FlagInfo
	cmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		flags = append(flags, FlagInfo{
			Name:        "--" + f.Name,
			Shorthand:   shorthandStr(f.Shorthand),
			Default:     f.DefValue,
			Description: f.Usage,
			Type:        f.Value.Type(),
		})
	})
	return flags
}

func extractCommands(parent *cobra.Command) []CommandInfo {
	var commands []CommandInfo

	for _, cmd := range parent.Commands() {
		if cmd.Hidden || cmd.Name() == "help" || cmd.Name() == "completion" {
			continue
		}

		info := CommandInfo{
			Name:     cmd.Name(),
			Use:      "lcre " + cmd.Use,
			Short:    cmd.Short,
			Long:     cmd.Long,
			Flags:    extractLocalFlags(cmd),
			Examples: getExamplesForCommand(cmd.Name()),
		}

		// Recursively extract subcommands
		if len(cmd.Commands()) > 0 {
			info.Subcommands = extractSubcommands(cmd)
		}

		commands = append(commands, info)
	}

	return commands
}

func extractSubcommands(parent *cobra.Command) []CommandInfo {
	var subcommands []CommandInfo

	for _, cmd := range parent.Commands() {
		if cmd.Hidden || cmd.Name() == "help" {
			continue
		}

		info := CommandInfo{
			Name:     parent.Name() + " " + cmd.Name(),
			Use:      "lcre " + parent.Name() + " " + cmd.Use,
			Short:    cmd.Short,
			Long:     cmd.Long,
			Flags:    extractLocalFlags(cmd),
			Examples: getExamplesForCommand(parent.Name() + " " + cmd.Name()),
		}

		// Handle nested subcommands if any
		if len(cmd.Commands()) > 0 {
			info.Subcommands = extractSubcommands(cmd)
		}

		subcommands = append(subcommands, info)
	}

	return subcommands
}

func extractLocalFlags(cmd *cobra.Command) []FlagInfo {
	var flags []FlagInfo
	cmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
		// Skip flags that are inherited from parent
		if cmd.Parent() != nil && cmd.Parent().PersistentFlags().Lookup(f.Name) != nil {
			return
		}
		flags = append(flags, FlagInfo{
			Name:        "--" + f.Name,
			Shorthand:   shorthandStr(f.Shorthand),
			Default:     f.DefValue,
			Description: f.Usage,
			Type:        f.Value.Type(),
		})
	})
	return flags
}

func shorthandStr(s string) string {
	if s == "" {
		return ""
	}
	return "-" + s
}

func getExamplesForCommand(name string) []Example {
	examples := map[string][]Example{
		"analyze": {
			{Command: "lcre analyze /path/to/suspicious.exe", Description: "Fast initial analysis of a binary"},
			{Command: "lcre analyze --strings=false /path/to/binary", Description: "Analysis without string extraction"},
			{Command: "lcre analyze --iocs /path/to/binary", Description: "Include IOC extraction"},
		},
		"diff": {
			{Command: "lcre diff old_version.exe new_version.exe", Description: "Compare two binary versions"},
		},
		"cache list": {
			{Command: "lcre cache list", Description: "List all cached analyses"},
		},
		"cache clear": {
			{Command: "lcre cache clear", Description: "Clear all cached analyses"},
			{Command: "lcre cache clear /path/to/binary", Description: "Clear cache for specific binary"},
		},
		"cache info": {
			{Command: "lcre cache info /path/to/binary", Description: "Show cache details for binary"},
		},
		"query summary": {
			{Command: "lcre query summary /path/to/binary", Description: "Get analysis summary with YARA matches and counts"},
			{Command: "lcre query summary --full /path/to/binary", Description: "Get summary with full metadata details"},
		},
		"query iocs": {
			{Command: "lcre query iocs /path/to/binary", Description: "Get extracted IOCs from cache"},
		},
		"query imports": {
			{Command: "lcre query imports /path/to/binary", Description: "List all imports"},
			{Command: "lcre query imports --library kernel32 /path/to/binary", Description: "Filter by library"},
		},
		"query exports": {
			{Command: "lcre query exports /path/to/binary", Description: "List all exports"},
		},
		"query sections": {
			{Command: "lcre query sections /path/to/binary", Description: "List binary sections with entropy"},
		},
		"query strings": {
			{Command: "lcre query strings /path/to/binary", Description: "List extracted strings"},
			{Command: "lcre query strings --pattern http /path/to/binary", Description: "Search for pattern"},
		},
		"query functions": {
			{Command: "lcre query --deep functions /path/to/binary", Description: "List functions (requires deep analysis)"},
		},
		"query function": {
			{Command: "lcre query function /path/to/binary main", Description: "Get function details"},
			{Command: "lcre query function /path/to/binary 0x401000", Description: "Get function by address"},
		},
		"query decompile": {
			{Command: "lcre query --deep decompile /path/to/binary main", Description: "Decompile function"},
		},
		"query callers": {
			{Command: "lcre query callers /path/to/binary func_name", Description: "Find who calls this function"},
		},
		"query callees": {
			{Command: "lcre query callees /path/to/binary func_name", Description: "Find what this function calls"},
		},
		"query call-path": {
			{Command: "lcre query call-path /path/to/binary main evil_func", Description: "Find call path between functions"},
		},
		"query xrefs-to": {
			{Command: "lcre query xrefs-to /path/to/binary 0x401000", Description: "Find references to address"},
		},
		"query xrefs-from": {
			{Command: "lcre query xrefs-from /path/to/binary 0x401000", Description: "Find references from address"},
		},
		"query bytes": {
			{Command: "lcre query bytes /path/to/binary 0x0 64", Description: "Hex dump 64 bytes from offset 0"},
		},
		"query search-bytes": {
			{Command: "lcre query search-bytes /path/to/binary 4D5A9000", Description: "Search for byte pattern"},
		},
	}

	return examples[name]
}

func getWorkflows() []Workflow {
	return []Workflow{
		{
			Name:        "quick_triage",
			Description: "Fast initial assessment of a suspicious binary",
			WhenToUse:   "First step when investigating any unknown binary. Provides summary and key indicators without deep analysis.",
			Steps: []WorkflowStep{
				{Order: 1, Command: "lcre query summary <binary>", Description: "Get overview with YARA matches and counts"},
				{Order: 2, Command: "lcre query yara <binary>", Description: "Check YARA signature matches"},
				{Order: 3, Command: "lcre query iocs <binary>", Description: "Extract IOCs (URLs, IPs, domains, file paths)"},
			},
		},
		{
			Name:        "malware_analysis",
			Description: "Deep analysis workflow for confirmed or suspected malware",
			WhenToUse:   "When quick triage indicates high risk or suspicious behavior requiring deeper investigation.",
			Steps: []WorkflowStep{
				{Order: 1, Command: "lcre query summary <binary>", Description: "Initial risk assessment"},
				{Order: 2, Command: "lcre query summary --deep <binary>", Description: "Trigger deep analysis with Ghidra"},
				{Order: 3, Command: "lcre query --deep functions <binary>", Description: "List all functions for review"},
				{Order: 4, Command: "lcre query --deep decompile <binary> <suspicious_func>", Description: "Examine suspicious functions"},
				{Order: 5, Command: "lcre query --deep call-path <binary> main <target_func>", Description: "Trace how malicious functions are reached"},
			},
		},
		{
			Name:        "binary_comparison",
			Description: "Compare two binary versions to identify changes",
			WhenToUse:   "When comparing a known-good binary against a potentially modified version, or tracking malware evolution.",
			Steps: []WorkflowStep{
				{Order: 1, Command: "lcre diff <binary_a> <binary_b>", Description: "Get structural differences (sections, imports, exports)"},
				{Order: 2, Command: "lcre query summary <binary_a>", Description: "Get summary of first binary"},
				{Order: 3, Command: "lcre query summary <binary_b>", Description: "Get summary of second binary"},
				{Order: 4, Command: "lcre query yara <binary_b>", Description: "Check new binary for malware signatures"},
			},
		},
		{
			Name:        "ioc_extraction",
			Description: "Comprehensive IOC extraction for threat intelligence",
			WhenToUse:   "When building threat intelligence from a malware sample - extracting network indicators, file paths, and other artifacts.",
			Steps: []WorkflowStep{
				{Order: 1, Command: "lcre query iocs <binary>", Description: "Extract IOCs from cached analysis"},
				{Order: 2, Command: "lcre query strings --pattern http <binary>", Description: "Find URL-related strings"},
				{Order: 3, Command: "lcre query strings --pattern \"C:\\\\\" <binary>", Description: "Find Windows file paths"},
				{Order: 4, Command: "lcre query imports --library ws2_32 <binary>", Description: "Check for networking imports"},
				{Order: 5, Command: "lcre query imports --library wininet <binary>", Description: "Check for HTTP/internet imports"},
			},
		},
		{
			Name:        "function_tracing",
			Description: "Trace execution flow through functions",
			WhenToUse:   "When understanding how a specific functionality is implemented or how a suspicious function is called.",
			Steps: []WorkflowStep{
				{Order: 1, Command: "lcre query --deep functions --name <pattern> <binary>", Description: "Find functions matching pattern"},
				{Order: 2, Command: "lcre query --deep function <binary> <func_name>", Description: "Get function details including callers/callees"},
				{Order: 3, Command: "lcre query --deep callers <binary> <func_name>", Description: "Find all functions that call this function"},
				{Order: 4, Command: "lcre query --deep callees <binary> <func_name>", Description: "Find all functions called by this function"},
				{Order: 5, Command: "lcre query --deep decompile <binary> <func_name>", Description: "Examine decompiled code"},
			},
		},
		{
			Name:        "packed_binary_analysis",
			Description: "Handle packed or obfuscated binaries",
			WhenToUse:   "When YARA detects packing or section entropy is high. The binary needs to be unpacked first for meaningful analysis.",
			Steps: []WorkflowStep{
				{Order: 1, Command: "lcre query yara <binary>", Description: "Check for packer signatures (UPX, VMProtect, etc.)"},
				{Order: 2, Command: "lcre query sections <binary>", Description: "Check section entropy (high entropy suggests packing)"},
				{Order: 3, Command: "lcre query bytes <binary> 0x0 256", Description: "Examine PE header for packer artifacts"},
				{Order: 4, Command: "lcre query imports <binary>", Description: "Check imports (packed binaries often have few imports)"},
			},
		},
		{
			Name:        "string_analysis",
			Description: "Detailed string analysis for artifact discovery",
			WhenToUse:   "When looking for specific artifacts like config data, C2 servers, credentials, or debugging strings.",
			Steps: []WorkflowStep{
				{Order: 1, Command: "lcre query strings <binary>", Description: "Get all strings"},
				{Order: 2, Command: "lcre query strings --pattern password <binary>", Description: "Search for credential-related strings"},
				{Order: 3, Command: "lcre query strings --pattern config <binary>", Description: "Search for configuration strings"},
				{Order: 4, Command: "lcre query strings --at 0x<offset> <binary>", Description: "Get string at specific offset"},
			},
		},
	}
}
