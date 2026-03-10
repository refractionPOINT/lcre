package model

import "time"

// Capability represents a detected behavioral capability (e.g., from capa).
type Capability struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Author    string `json:"author,omitempty"`
	Scope     string `json:"scope,omitempty"`
	// MITRE ATT&CK technique IDs (e.g., "T1059.001")
	AttackIDs []string `json:"attack_ids,omitempty"`
	// MITRE MBC behavior IDs (e.g., "B0001")
	MBCIDs []string `json:"mbc_ids,omitempty"`
}

// PackerDetection represents a packer/compiler/linker detection result (e.g., from diec).
type PackerDetection struct {
	Type    string `json:"type"`    // "compiler", "packer", "linker", "protector", etc.
	Name    string `json:"name"`    // e.g., "UPX", "Microsoft Visual C/C++"
	Version string `json:"version,omitempty"`
	String  string `json:"string,omitempty"` // full detection string
}

// Enrichment represents raw output from an external analysis tool.
type Enrichment struct {
	Tool      string    `json:"tool"`
	Timestamp time.Time `json:"timestamp"`
	RawOutput string    `json:"raw_output"` // JSON string
}
