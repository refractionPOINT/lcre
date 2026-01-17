package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/maxime/lcre/internal/cache"
	"github.com/maxime/lcre/internal/model"
)

func TestFormatAddress(t *testing.T) {
	tests := []struct {
		addr     int64
		expected string
	}{
		{0, "0x0"},
		{0x1000, "0x1000"},
		{0x401000, "0x401000"},
		{0xdeadbeef, "0xdeadbeef"},
		{255, "0xff"},
		{4096, "0x1000"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatAddress(tt.addr)
			if result != tt.expected {
				t.Errorf("formatAddress(%d) = %q, want %q", tt.addr, result, tt.expected)
			}
		})
	}
}

func TestParseAddressArg(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"0x1000", 0x1000},
		{"0X1000", 0x1000},
		{"0xABCDEF", 0xABCDEF},
		{"0xabcdef", 0xabcdef},
		{"1234", 1234},
		{"0", 0},
		{"0x0", 0},
		{"0x401000", 0x401000},
		{"invalid", 0},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseAddressArg(tt.input)
			if result != tt.expected {
				t.Errorf("parseAddressArg(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestValidateBinaryPath(t *testing.T) {
	tempDir := t.TempDir()

	// Create test file
	testFile := filepath.Join(tempDir, "test_binary")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"valid file", testFile, false},
		{"non-existent file", filepath.Join(tempDir, "nonexistent"), true},
		{"directory", tempDir, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBinaryPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateBinaryPath() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Helper to create a test cache with pre-populated data
func setupTestCache(t *testing.T) (*cache.Manager, string) {
	t.Helper()

	tempDir := t.TempDir()
	mgr, err := cache.NewManagerWithPath(filepath.Join(tempDir, "cache"))
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	// Create test binary
	binaryPath := filepath.Join(tempDir, "test_binary")
	if err := os.WriteFile(binaryPath, []byte("test binary content for hashing"), 0644); err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}

	// Create cache with test data
	result := &model.AnalysisResult{
		Metadata: model.BinaryMetadata{
			Path:   binaryPath,
			Name:   "test_binary",
			Size:   31,
			Format: model.FormatELF,
			Arch:   "x86_64",
			Bits:   64,
		},
		Sections: []model.Section{
			{Name: ".text", VirtualAddr: 0x1000, VirtualSize: 0x500, Entropy: 6.5, Permissions: "rx"},
			{Name: ".data", VirtualAddr: 0x2000, VirtualSize: 0x200, Entropy: 4.0, Permissions: "rw"},
		},
		Imports: []model.Import{
			{Library: "libc.so.6", Function: "printf", Address: 0x3000},
			{Library: "libc.so.6", Function: "malloc", Address: 0x3004},
		},
		Exports: []model.Export{
			{Name: "main", Ordinal: 1, Address: 0x1000},
		},
		Strings: []model.ExtractedString{
			{Value: "Hello World", Offset: 100, Section: ".rodata", Encoding: "ascii"},
			{Value: "password123", Offset: 200, Section: ".data", Encoding: "ascii"},
			{Value: "config.json", Offset: 300, Section: ".rodata", Encoding: "ascii"},
		},
		Functions: []model.Function{
			{Name: "main", Address: 0x1000, Size: 100, Signature: "int main(int, char**)"},
			{Name: "_start", Address: 0x500, Size: 50},
			{Name: "helper", Address: 0x2000, Size: 30},
		},
		CallGraph: &model.CallGraph{
			Edges: []model.CallGraphEdge{
				{From: 0x500, To: 0x1000},
				{From: 0x1000, To: 0x2000},
			},
		},
		EntryPoints: []model.EntryPoint{
			{Name: "_start", Address: 0x500, Type: "main"},
		},
		Heuristics: &model.HeuristicsResult{
			Matches: []model.HeuristicMatch{
				{
					RuleID:      "TEST_01",
					Name:        "Test Heuristic",
					Description: "Test description",
					Severity:    model.SeverityLow,
					Category:    model.CategoryAnomaly,
				},
			},
			TotalScore: 5,
			RiskLevel:  model.SeverityLow,
		},
		Backend:   "native",
		Duration:  0.5,
		Timestamp: time.Now(),
	}

	iocs := &model.IOCResult{
		URLs: []model.IOC{
			{Type: model.IOCURL, Value: "http://example.com", Offset: 100, Section: ".data"},
		},
		IPs: []model.IOC{
			{Type: model.IOCIP, Value: "192.168.1.1", Offset: 200, Section: ".data"},
		},
		Count: 2,
	}

	if err := cache.StoreAnalysisResult(mgr, binaryPath, result, iocs); err != nil {
		t.Fatalf("StoreAnalysisResult() error = %v", err)
	}

	return mgr, binaryPath
}

func TestStringsOutput_JSON(t *testing.T) {
	output := StringsOutput{
		Strings: []StringInfo{
			{Value: "Hello", Offset: "0x64", Section: ".rodata", Encoding: "ascii"},
			{Value: "World", Offset: "0xc8", Section: ".data", Encoding: "utf-8"},
		},
		Count:     2,
		Total:     10,
		Truncated: true,
	}

	if output.Count != 2 {
		t.Errorf("StringsOutput.Count = %d, want 2", output.Count)
	}
	if !output.Truncated {
		t.Error("StringsOutput.Truncated = false, want true")
	}
}

func TestFunctionsOutput_JSON(t *testing.T) {
	output := FunctionsOutput{
		Functions: []FunctionInfo{
			{Name: "main", Address: "0x1000", Size: 100, IsExternal: false},
			{Name: "printf", Address: "0x3000", Size: 0, IsExternal: true, IsThunk: true},
		},
		Count:   2,
		HasDeep: true,
	}

	if output.Count != 2 {
		t.Errorf("FunctionsOutput.Count = %d, want 2", output.Count)
	}
	if !output.HasDeep {
		t.Error("FunctionsOutput.HasDeep = false, want true")
	}
}

func TestFunctionDetailOutput(t *testing.T) {
	output := FunctionDetailOutput{
		Found: true,
		Function: FunctionInfo{
			Name:      "main",
			Address:   "0x1000",
			Size:      100,
			Signature: "int main(int, char**)",
		},
		Callers: []FunctionRef{
			{Name: "_start", Address: "0x500"},
		},
		Callees: []FunctionRef{
			{Name: "helper", Address: "0x2000"},
			{Name: "printf", Address: "0x3000"},
		},
	}

	if !output.Found {
		t.Error("FunctionDetailOutput.Found = false, want true")
	}
	if len(output.Callers) != 1 {
		t.Errorf("FunctionDetailOutput.Callers length = %d, want 1", len(output.Callers))
	}
	if len(output.Callees) != 2 {
		t.Errorf("FunctionDetailOutput.Callees length = %d, want 2", len(output.Callees))
	}
}

func TestQueryStrings_WithCache(t *testing.T) {
	mgr, binaryPath := setupTestCache(t)

	db, err := mgr.Open(binaryPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	t.Run("query all strings", func(t *testing.T) {
		strings, total, err := db.QueryStrings("", 100, 0)
		if err != nil {
			t.Fatalf("QueryStrings() error = %v", err)
		}
		if total != 3 {
			t.Errorf("Total strings = %d, want 3", total)
		}
		if len(strings) != 3 {
			t.Errorf("Returned strings = %d, want 3", len(strings))
		}
	})

	t.Run("query with pattern", func(t *testing.T) {
		// FTS matches word prefixes, so "Hello" matches "Hello World"
		strings, total, err := db.QueryStrings("Hello", 100, 0)
		if err != nil {
			t.Fatalf("QueryStrings() error = %v", err)
		}
		if total != 1 {
			t.Errorf("Total strings = %d, want 1", total)
		}
		if len(strings) != 1 {
			t.Errorf("Returned strings = %d, want 1", len(strings))
		}
	})

	t.Run("query with pagination", func(t *testing.T) {
		strings, total, err := db.QueryStrings("", 2, 0)
		if err != nil {
			t.Fatalf("QueryStrings() error = %v", err)
		}
		if total != 3 {
			t.Errorf("Total = %d, want 3", total)
		}
		if len(strings) != 2 {
			t.Errorf("Page 1 strings = %d, want 2", len(strings))
		}

		// Second page
		strings, _, err = db.QueryStrings("", 2, 2)
		if err != nil {
			t.Fatalf("QueryStrings() page 2 error = %v", err)
		}
		if len(strings) != 1 {
			t.Errorf("Page 2 strings = %d, want 1", len(strings))
		}
	})

	t.Run("get string at offset", func(t *testing.T) {
		str, err := db.GetStringAt(100)
		if err != nil {
			t.Fatalf("GetStringAt() error = %v", err)
		}
		if str == nil {
			t.Fatal("GetStringAt() returned nil")
		}
		if str.Value != "Hello World" {
			t.Errorf("GetStringAt() value = %q, want %q", str.Value, "Hello World")
		}
	})
}

func TestQueryFunctions_WithCache(t *testing.T) {
	mgr, binaryPath := setupTestCache(t)

	db, err := mgr.Open(binaryPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	t.Run("query all functions", func(t *testing.T) {
		functions, err := db.QueryFunctions("", 0, 0)
		if err != nil {
			t.Fatalf("QueryFunctions() error = %v", err)
		}
		if len(functions) != 3 {
			t.Errorf("Functions count = %d, want 3", len(functions))
		}
	})

	t.Run("query by name", func(t *testing.T) {
		functions, err := db.QueryFunctions("main", 0, 0)
		if err != nil {
			t.Fatalf("QueryFunctions() error = %v", err)
		}
		if len(functions) != 1 {
			t.Errorf("Functions count = %d, want 1", len(functions))
		}
	})

	t.Run("get function by name", func(t *testing.T) {
		f, err := db.GetFunction("main")
		if err != nil {
			t.Fatalf("GetFunction() error = %v", err)
		}
		if f == nil {
			t.Fatal("GetFunction() returned nil")
		}
		if f.Address != 0x1000 {
			t.Errorf("Function address = %x, want %x", f.Address, 0x1000)
		}
	})

	t.Run("get function by address", func(t *testing.T) {
		f, err := db.GetFunction("0x1000")
		if err != nil {
			t.Fatalf("GetFunction() error = %v", err)
		}
		if f == nil {
			t.Fatal("GetFunction() returned nil")
		}
		if f.Name != "main" {
			t.Errorf("Function name = %q, want %q", f.Name, "main")
		}
	})

	t.Run("get callers", func(t *testing.T) {
		callers, err := db.GetCallers(0x1000) // main is called by _start
		if err != nil {
			t.Fatalf("GetCallers() error = %v", err)
		}
		if len(callers) != 1 {
			t.Errorf("Callers count = %d, want 1", len(callers))
		}
		if len(callers) > 0 && callers[0].Name != "_start" {
			t.Errorf("Caller name = %q, want %q", callers[0].Name, "_start")
		}
	})

	t.Run("get callees", func(t *testing.T) {
		callees, err := db.GetCallees(0x1000) // main calls helper
		if err != nil {
			t.Fatalf("GetCallees() error = %v", err)
		}
		if len(callees) != 1 {
			t.Errorf("Callees count = %d, want 1", len(callees))
		}
		if len(callees) > 0 && callees[0].Name != "helper" {
			t.Errorf("Callee name = %q, want %q", callees[0].Name, "helper")
		}
	})
}

func TestQuerySections_WithCache(t *testing.T) {
	mgr, binaryPath := setupTestCache(t)

	db, err := mgr.Open(binaryPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	t.Run("query all sections", func(t *testing.T) {
		sections, err := db.QuerySections("")
		if err != nil {
			t.Fatalf("QuerySections() error = %v", err)
		}
		if len(sections) != 2 {
			t.Errorf("Sections count = %d, want 2", len(sections))
		}
	})

	t.Run("query by name", func(t *testing.T) {
		sections, err := db.QuerySections(".text")
		if err != nil {
			t.Fatalf("QuerySections() error = %v", err)
		}
		if len(sections) != 1 {
			t.Errorf("Sections count = %d, want 1", len(sections))
		}
		if len(sections) > 0 && sections[0].VirtualAddr != 0x1000 {
			t.Errorf("Section VirtualAddr = %x, want %x", sections[0].VirtualAddr, 0x1000)
		}
	})
}

func TestQueryImports_WithCache(t *testing.T) {
	mgr, binaryPath := setupTestCache(t)

	db, err := mgr.Open(binaryPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	t.Run("query all imports", func(t *testing.T) {
		imports, err := db.QueryImports("", "")
		if err != nil {
			t.Fatalf("QueryImports() error = %v", err)
		}
		if len(imports) != 2 {
			t.Errorf("Imports count = %d, want 2", len(imports))
		}
	})

	t.Run("filter by library", func(t *testing.T) {
		imports, err := db.QueryImports("libc", "")
		if err != nil {
			t.Fatalf("QueryImports() error = %v", err)
		}
		if len(imports) != 2 {
			t.Errorf("Imports count = %d, want 2", len(imports))
		}
	})

	t.Run("filter by function", func(t *testing.T) {
		imports, err := db.QueryImports("", "printf")
		if err != nil {
			t.Fatalf("QueryImports() error = %v", err)
		}
		if len(imports) != 1 {
			t.Errorf("Imports count = %d, want 1", len(imports))
		}
	})
}

func TestQueryExports_WithCache(t *testing.T) {
	mgr, binaryPath := setupTestCache(t)

	db, err := mgr.Open(binaryPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	exports, err := db.QueryExports("")
	if err != nil {
		t.Fatalf("QueryExports() error = %v", err)
	}
	if len(exports) != 1 {
		t.Errorf("Exports count = %d, want 1", len(exports))
	}
	if len(exports) > 0 && exports[0].Name != "main" {
		t.Errorf("Export name = %q, want %q", exports[0].Name, "main")
	}
}

func TestQueryIOCs_WithCache(t *testing.T) {
	mgr, binaryPath := setupTestCache(t)

	db, err := mgr.Open(binaryPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	t.Run("query all IOCs", func(t *testing.T) {
		iocs, err := db.QueryIOCs("")
		if err != nil {
			t.Fatalf("QueryIOCs() error = %v", err)
		}
		if len(iocs) != 2 {
			t.Errorf("IOCs count = %d, want 2", len(iocs))
		}
	})

	t.Run("filter by type", func(t *testing.T) {
		iocs, err := db.QueryIOCs("url")
		if err != nil {
			t.Fatalf("QueryIOCs() error = %v", err)
		}
		if len(iocs) != 1 {
			t.Errorf("URL IOCs count = %d, want 1", len(iocs))
		}
	})
}

func TestQueryHeuristics_WithCache(t *testing.T) {
	mgr, binaryPath := setupTestCache(t)

	db, err := mgr.Open(binaryPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	heuristics, err := db.QueryHeuristics("")
	if err != nil {
		t.Fatalf("QueryHeuristics() error = %v", err)
	}
	if len(heuristics) != 1 {
		t.Errorf("Heuristics count = %d, want 1", len(heuristics))
	}
}

func TestQueryEntryPoints_WithCache(t *testing.T) {
	mgr, binaryPath := setupTestCache(t)

	db, err := mgr.Open(binaryPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	entryPoints, err := db.QueryEntryPoints()
	if err != nil {
		t.Fatalf("QueryEntryPoints() error = %v", err)
	}
	if len(entryPoints) != 1 {
		t.Errorf("EntryPoints count = %d, want 1", len(entryPoints))
	}
	if len(entryPoints) > 0 && entryPoints[0].Name != "_start" {
		t.Errorf("EntryPoint name = %q, want %q", entryPoints[0].Name, "_start")
	}
}

func TestQueryCallGraph_WithCache(t *testing.T) {
	mgr, binaryPath := setupTestCache(t)

	db, err := mgr.Open(binaryPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	graph, err := db.GetCallGraph()
	if err != nil {
		t.Fatalf("GetCallGraph() error = %v", err)
	}
	if len(graph.Nodes) != 3 {
		t.Errorf("CallGraph nodes = %d, want 3", len(graph.Nodes))
	}
	if len(graph.Edges) != 2 {
		t.Errorf("CallGraph edges = %d, want 2", len(graph.Edges))
	}
}

func TestCacheMetadata_WithCache(t *testing.T) {
	mgr, binaryPath := setupTestCache(t)

	meta, err := mgr.LoadMetadata(binaryPath)
	if err != nil {
		t.Fatalf("LoadMetadata() error = %v", err)
	}

	if meta.StringCount != 3 {
		t.Errorf("StringCount = %d, want 3", meta.StringCount)
	}
	if meta.FunctionCount != 3 {
		t.Errorf("FunctionCount = %d, want 3", meta.FunctionCount)
	}
	if meta.ImportCount != 2 {
		t.Errorf("ImportCount = %d, want 2", meta.ImportCount)
	}
	if meta.ExportCount != 1 {
		t.Errorf("ExportCount = %d, want 1", meta.ExportCount)
	}
	if meta.HeuristicCount != 1 {
		t.Errorf("HeuristicCount = %d, want 1", meta.HeuristicCount)
	}
	if !meta.DeepAnalysis {
		t.Error("DeepAnalysis = false, want true")
	}
	if meta.TotalScore != 5 {
		t.Errorf("TotalScore = %d, want 5", meta.TotalScore)
	}
	if meta.RiskLevel != "low" {
		t.Errorf("RiskLevel = %q, want %q", meta.RiskLevel, "low")
	}
}

func TestEmptyResults(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := cache.NewManagerWithPath(filepath.Join(tempDir, "cache"))
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	// Create test binary
	binaryPath := filepath.Join(tempDir, "empty_binary")
	if err := os.WriteFile(binaryPath, []byte("empty binary"), 0644); err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}

	// Create cache with minimal data
	result := &model.AnalysisResult{
		Metadata: model.BinaryMetadata{Name: "empty_binary"},
		Backend:  "native",
	}
	if err := cache.StoreAnalysisResult(mgr, binaryPath, result, nil); err != nil {
		t.Fatalf("StoreAnalysisResult() error = %v", err)
	}

	db, err := mgr.Open(binaryPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	t.Run("empty strings", func(t *testing.T) {
		strings, total, err := db.QueryStrings("", 100, 0)
		if err != nil {
			t.Fatalf("QueryStrings() error = %v", err)
		}
		if len(strings) != 0 || total != 0 {
			t.Errorf("Expected empty strings, got %d/%d", len(strings), total)
		}
	})

	t.Run("empty functions", func(t *testing.T) {
		functions, err := db.QueryFunctions("", 0, 0)
		if err != nil {
			t.Fatalf("QueryFunctions() error = %v", err)
		}
		if len(functions) != 0 {
			t.Errorf("Expected empty functions, got %d", len(functions))
		}
	})

	t.Run("empty sections", func(t *testing.T) {
		sections, err := db.QuerySections("")
		if err != nil {
			t.Fatalf("QuerySections() error = %v", err)
		}
		if len(sections) != 0 {
			t.Errorf("Expected empty sections, got %d", len(sections))
		}
	})

	t.Run("function not found", func(t *testing.T) {
		f, err := db.GetFunction("nonexistent")
		if err != nil {
			t.Fatalf("GetFunction() error = %v", err)
		}
		if f != nil {
			t.Error("Expected nil function for nonexistent name")
		}
	})
}
