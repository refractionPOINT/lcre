package enrichment

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCapaParser(t *testing.T) {
	capaJSON := `{
		"rules": {
			"create process": {
				"meta": {
					"name": "create process",
					"namespace": "host-interaction/process/create",
					"authors": ["author@example.com"],
					"scopes": {"static": "function", "dynamic": "process"},
					"att&ck": [{"technique": "Execution", "subtechnique": "", "id": "T1106"}],
					"mbc": [{"objective": "Process", "behavior": "Create Process", "id": "C0017"}]
				},
				"source": "test"
			},
			"encrypt data": {
				"meta": {
					"name": "encrypt data using AES",
					"namespace": "data-manipulation/encryption/aes",
					"authors": ["test"],
					"scopes": {"static": "basic block"},
					"att&ck": [{"technique": "Data Encrypted for Impact", "subtechnique": "", "id": "T1486"}],
					"mbc": []
				},
				"source": "test"
			}
		}
	}`

	result, err := parseFromString("capa", capaJSON)
	if err != nil {
		t.Fatalf("failed to parse capa output: %v", err)
	}

	if len(result.Capabilities) != 2 {
		t.Fatalf("expected 2 capabilities, got %d", len(result.Capabilities))
	}

	// Find the "create process" capability
	var found bool
	for _, cap := range result.Capabilities {
		if cap.Name == "create process" {
			found = true
			if cap.Namespace != "host-interaction/process/create" {
				t.Errorf("expected namespace 'host-interaction/process/create', got '%s'", cap.Namespace)
			}
			if len(cap.AttackIDs) != 1 || cap.AttackIDs[0] != "T1106" {
				t.Errorf("expected ATT&CK ID T1106, got %v", cap.AttackIDs)
			}
			if len(cap.MBCIDs) != 1 || cap.MBCIDs[0] != "C0017" {
				t.Errorf("expected MBC ID C0017, got %v", cap.MBCIDs)
			}
		}
	}
	if !found {
		t.Error("'create process' capability not found in results")
	}
}

func TestDIECParser(t *testing.T) {
	diecJSON := `{
		"detects": [
			{
				"filetype": "PE32",
				"type": "compiler",
				"name": "Microsoft Visual C/C++",
				"string": "Microsoft Visual C/C++(2019 v.16.5-7)[LTCG/C]",
				"version": "2019 v.16.5-7"
			},
			{
				"filetype": "PE32",
				"type": "packer",
				"name": "UPX",
				"string": "UPX(3.96)[NRV2B]",
				"version": "3.96"
			}
		]
	}`

	result, err := parseFromString("diec", diecJSON)
	if err != nil {
		t.Fatalf("failed to parse diec output: %v", err)
	}

	if len(result.Detections) != 2 {
		t.Fatalf("expected 2 detections, got %d", len(result.Detections))
	}

	if result.Detections[0].Type != "compiler" {
		t.Errorf("expected type 'compiler', got '%s'", result.Detections[0].Type)
	}
	if result.Detections[1].Name != "UPX" {
		t.Errorf("expected name 'UPX', got '%s'", result.Detections[1].Name)
	}
}

func TestFLOSSParser(t *testing.T) {
	flossJSON := `{
		"strings": {
			"static_strings": [
				{"string": "kernel32.dll", "offset": 100, "encoding": "ascii"}
			],
			"stack_strings": [
				{"string": "secret_key_123", "offset": 200, "encoding": "utf-8"}
			],
			"tight_strings": [
				{"string": "config.dat", "offset": 300, "encoding": "ascii"}
			],
			"decoded_strings": [
				{"string": "http://evil.com/c2", "offset": 400, "encoding": "utf-16le"},
				{"string": "password123", "offset": 500, "encoding": "ascii"}
			]
		}
	}`

	result, err := parseFromString("floss", flossJSON)
	if err != nil {
		t.Fatalf("failed to parse floss output: %v", err)
	}

	// FLOSS parser imports stack, tight, and decoded strings — not static
	// (static strings are redundant with native extraction)
	if len(result.Strings) != 4 {
		t.Fatalf("expected 4 strings (1 stack + 1 tight + 2 decoded), got %d", len(result.Strings))
	}

	// Check that sections are tagged correctly
	for _, s := range result.Strings {
		if s.Section == "" {
			t.Errorf("string '%s' has empty section, expected floss:* prefix", s.Value)
		}
	}
}

func TestUnknownToolPreservesRawJSON(t *testing.T) {
	rawJSON := `{"some": "data", "nested": {"key": "value"}}`

	result, err := parseFromString("unknown_tool", rawJSON)
	if err != nil {
		t.Fatalf("failed to parse unknown tool output: %v", err)
	}

	if result.RawJSON != rawJSON {
		t.Error("raw JSON not preserved for unknown tool")
	}
	if len(result.Capabilities) != 0 {
		t.Error("unexpected capabilities for unknown tool")
	}
}

func TestDedicatedParserRejectsNonJSON(t *testing.T) {
	// Dedicated parsers (capa, diec, floss) still require JSON
	_, err := parseFromString("capa", "not json at all")
	if err == nil {
		t.Error("expected error for non-JSON input to capa parser, got nil")
	}
}

func TestUnknownToolAcceptsPlainText(t *testing.T) {
	plainText := `ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64`

	result, err := parseFromString("readelf", plainText)
	if err != nil {
		t.Fatalf("expected plain text to be accepted for unknown tool, got error: %v", err)
	}

	if result.RawJSON != plainText {
		t.Error("raw text output not preserved")
	}
	if len(result.Capabilities) != 0 {
		t.Error("unexpected capabilities for text-only tool")
	}
	if len(result.Detections) != 0 {
		t.Error("unexpected detections for text-only tool")
	}
}

// parseFromString is a test helper that writes data to a temp file and parses it.
func parseFromString(tool, data string) (*Result, error) {
	dir := t_tempDir()
	path := filepath.Join(dir, "output.json")
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		return nil, err
	}
	return ParseToolOutput(tool, path)
}

// t_tempDir creates a temp directory for tests. This is a package-level helper.
var t_tempDir = func() string {
	dir, err := os.MkdirTemp("", "enrichment-test-*")
	if err != nil {
		panic(err)
	}
	return dir
}
