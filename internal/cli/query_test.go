package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/refractionPOINT/lcre/internal/cache"
	"github.com/refractionPOINT/lcre/internal/model"
	"github.com/refractionPOINT/lcre/internal/yara"
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
		YARA: &yara.ScanResult{
			Matches: []yara.Match{
				{
					Rule:        "Test_Rule",
					Namespace:   "test",
					Tags:        []string{"test"},
					Description: "Test description",
					Strings:     []string{"$s1: test"},
				},
			},
			Available: true,
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

func TestQueryYARAMatches_WithCache(t *testing.T) {
	mgr, binaryPath := setupTestCache(t)

	db, err := mgr.Open(binaryPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	yaraMatches, err := db.QueryYARAMatches("")
	if err != nil {
		t.Fatalf("QueryYARAMatches() error = %v", err)
	}
	if len(yaraMatches) != 1 {
		t.Errorf("YARA matches count = %d, want 1", len(yaraMatches))
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
	if meta.YARAMatchCount != 1 {
		t.Errorf("YARAMatchCount = %d, want 1", meta.YARAMatchCount)
	}
	if !meta.DeepAnalysis {
		t.Error("DeepAnalysis = false, want true")
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

// Integration tests using real system binaries

// findSystemBinary finds a suitable system binary for testing
func findSystemBinary(t *testing.T) string {
	t.Helper()
	candidates := []string{"/bin/true", "/bin/ls", "/bin/cat", "/usr/bin/true", "/usr/bin/ls"}
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	t.Skip("No suitable system binary found for integration test")
	return ""
}

func TestEnsureAnalyzed_RealBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	binaryPath := findSystemBinary(t)

	// Use a temporary cache directory
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", originalHome)

	// Create the .cache directory structure
	cacheBase := filepath.Join(tempDir, ".cache", "lcre")
	os.MkdirAll(cacheBase, 0755)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// First analysis should create cache
	mgr, db, wasNew, err := ensureAnalyzed(ctx, binaryPath, false)
	if err != nil {
		t.Fatalf("ensureAnalyzed() error = %v", err)
	}
	defer db.Close()

	if !wasNew {
		t.Error("First call to ensureAnalyzed() should set wasNew=true")
	}

	// Verify cache was created
	exists, err := mgr.Exists(binaryPath)
	if err != nil {
		t.Fatalf("Exists() error = %v", err)
	}
	if !exists {
		t.Error("Cache should exist after ensureAnalyzed()")
	}

	// Verify metadata was stored
	meta, err := mgr.LoadMetadata(binaryPath)
	if err != nil {
		t.Fatalf("LoadMetadata() error = %v", err)
	}
	if meta.Binary.Format == "" {
		t.Error("Binary format should be detected")
	}
	if meta.Binary.Size == 0 {
		t.Error("Binary size should be set")
	}

	// Verify sections were stored
	sections, err := db.QuerySections("")
	if err != nil {
		t.Fatalf("QuerySections() error = %v", err)
	}
	if len(sections) == 0 {
		t.Error("Sections should be extracted from real binary")
	}

	db.Close()

	// Second call should use cache
	mgr2, db2, wasNew2, err := ensureAnalyzed(ctx, binaryPath, false)
	if err != nil {
		t.Fatalf("ensureAnalyzed() second call error = %v", err)
	}
	defer db2.Close()
	_ = mgr2

	if wasNew2 {
		t.Error("Second call to ensureAnalyzed() should set wasNew=false (cached)")
	}
}

func TestEnsureAnalyzed_NonExistentFile(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, _, err := ensureAnalyzed(ctx, "/nonexistent/binary/path", false)
	if err == nil {
		t.Error("ensureAnalyzed() should error on non-existent file")
	}
}

func TestRunAnalysis_RealBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	binaryPath := findSystemBinary(t)

	tempDir := t.TempDir()
	mgr, err := cache.NewManagerWithPath(filepath.Join(tempDir, "cache"))
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Run analysis (shallow)
	err = runAnalysis(ctx, mgr, binaryPath, false)
	if err != nil {
		t.Fatalf("runAnalysis() error = %v", err)
	}

	// Verify results were stored
	db, err := mgr.Open(binaryPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	// Check sections
	sections, err := db.QuerySections("")
	if err != nil {
		t.Fatalf("QuerySections() error = %v", err)
	}
	t.Logf("Found %d sections in %s", len(sections), binaryPath)
	if len(sections) == 0 {
		t.Error("Should find sections in real binary")
	}

	// Check strings
	strings, total, err := db.QueryStrings("", 100, 0)
	if err != nil {
		t.Fatalf("QueryStrings() error = %v", err)
	}
	t.Logf("Found %d strings (total: %d) in %s", len(strings), total, binaryPath)

	// Check metadata
	meta, err := mgr.LoadMetadata(binaryPath)
	if err != nil {
		t.Fatalf("LoadMetadata() error = %v", err)
	}
	t.Logf("Binary format: %s, arch: %s, size: %d", meta.Binary.Format, meta.Binary.Arch, meta.Binary.Size)

	// Format may be uppercase or lowercase depending on model.BinaryFormat implementation
	if meta.Binary.Format != "elf" && meta.Binary.Format != "ELF" {
		t.Errorf("Expected ELF format, got %s", meta.Binary.Format)
	}
}

func TestSummaryOutput_Structure(t *testing.T) {
	output := SummaryOutput{
		Metadata: MetadataSummary{
			Format: "elf",
			Arch:   "x86_64",
			Size:   12345,
			SHA256: "abc123",
		},
		YARAMatchCount: 2,
		YARAMatches: []YARASummary{
			{Rule: "Test_Rule", Tags: []string{"test"}},
		},
		Counts: CountSummary{
			Sections:  5,
			Imports:   10,
			Exports:   2,
			Strings:   100,
			Functions: 50,
			IOCs:      3,
		},
		Cached:       false,
		AnalysisTime: "1.5s",
	}

	// Verify structure
	if output.Metadata.Format != "elf" {
		t.Errorf("Metadata.Format = %q, want %q", output.Metadata.Format, "elf")
	}
	if output.YARAMatchCount != 2 {
		t.Errorf("YARAMatchCount = %d, want 2", output.YARAMatchCount)
	}
	if output.Counts.Sections != 5 {
		t.Errorf("Counts.Sections = %d, want 5", output.Counts.Sections)
	}
	if len(output.YARAMatches) != 1 {
		t.Errorf("YARAMatches length = %d, want 1", len(output.YARAMatches))
	}
}

func TestInfoOutput_Structure(t *testing.T) {
	output := InfoOutput{
		Path:     "/bin/ls",
		Name:     "ls",
		Format:   "elf",
		Arch:     "x86_64",
		Bits:     64,
		Endian:   "little",
		Size:     140000,
		MD5:      "abc123",
		SHA1:     "def456",
		SHA256:   "ghi789",
		Compiler: "gcc",
		IsSigned: false,
	}

	if output.Path != "/bin/ls" {
		t.Errorf("Path = %q, want %q", output.Path, "/bin/ls")
	}
	if output.Bits != 64 {
		t.Errorf("Bits = %d, want 64", output.Bits)
	}
}

func TestOutputJSON(t *testing.T) {
	// Test that outputJSON doesn't panic with various types
	testCases := []interface{}{
		map[string]string{"key": "value"},
		[]string{"a", "b", "c"},
		struct {
			Name string `json:"name"`
		}{Name: "test"},
		nil,
	}

	for _, tc := range testCases {
		// Capture stdout
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		outputJSON(tc)

		w.Close()
		os.Stdout = old

		// Read output
		buf := make([]byte, 1024)
		n, _ := r.Read(buf)
		if n == 0 && tc != nil {
			t.Errorf("outputJSON() produced no output for %v", tc)
		}
	}
}

func TestPrintStringsMarkdown(t *testing.T) {
	// Test with strings
	output := StringsOutput{
		Strings: []StringInfo{
			{Value: "Hello", Offset: "0x100", Section: ".rodata", Encoding: "ascii"},
			{Value: "World", Offset: "0x200", Section: ".data", Encoding: "utf-8"},
		},
		Count:     2,
		Total:     10,
		Truncated: true,
	}

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printStringsMarkdown(output, "test")

	w.Close()
	os.Stdout = old

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	result := string(buf[:n])

	if !contains(result, "Strings matching") {
		t.Error("printStringsMarkdown() should include pattern in output")
	}
	if !contains(result, "0x100") {
		t.Error("printStringsMarkdown() should include offsets")
	}
}

func TestPrintStringsMarkdown_Empty(t *testing.T) {
	output := StringsOutput{
		Strings:   []StringInfo{},
		Count:     0,
		Total:     0,
		Truncated: false,
	}

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printStringsMarkdown(output, "")

	w.Close()
	os.Stdout = old

	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	result := string(buf[:n])

	if !contains(result, "No strings found") {
		t.Error("printStringsMarkdown() should indicate no strings found")
	}
}

func TestPrintFunctionsMarkdown(t *testing.T) {
	output := FunctionsOutput{
		Functions: []FunctionInfo{
			{Name: "main", Address: "0x1000", Size: 100, IsExternal: false},
			{Name: "printf", Address: "0x3000", Size: 0, IsExternal: true},
		},
		Count:   2,
		HasDeep: true,
	}

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printFunctionsMarkdown(output)

	w.Close()
	os.Stdout = old

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	result := string(buf[:n])

	if !contains(result, "Functions (2)") {
		t.Error("printFunctionsMarkdown() should include count in header")
	}
	if !contains(result, "main") {
		t.Error("printFunctionsMarkdown() should include function names")
	}
}

func TestPrintFunctionsMarkdown_NoDeepAnalysis(t *testing.T) {
	output := FunctionsOutput{
		Functions: []FunctionInfo{},
		Count:     0,
		HasDeep:   false,
	}

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printFunctionsMarkdown(output)

	w.Close()
	os.Stdout = old

	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	result := string(buf[:n])

	if !contains(result, "Deep analysis not performed") {
		t.Error("printFunctionsMarkdown() should note when deep analysis not done")
	}
}

func TestPrintFunctionDetailMarkdown(t *testing.T) {
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
		},
	}

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printFunctionDetailMarkdown(output)

	w.Close()
	os.Stdout = old

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	result := string(buf[:n])

	if !contains(result, "Function: main") {
		t.Error("printFunctionDetailMarkdown() should include function name")
	}
	if !contains(result, "Callers") {
		t.Error("printFunctionDetailMarkdown() should include callers section")
	}
	if !contains(result, "Callees") {
		t.Error("printFunctionDetailMarkdown() should include callees section")
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Additional output structure tests

func TestSectionsOutput_Structure(t *testing.T) {
	output := SectionsOutput{
		Sections: []SectionInfo{
			{Name: ".text", VirtualAddr: "0x1000", VirtualSize: 0x500, RawSize: 0x400, Entropy: 6.5, Permissions: "rx", HighEntropy: false},
			{Name: ".data", VirtualAddr: "0x2000", VirtualSize: 0x200, RawSize: 0x200, Entropy: 7.5, Permissions: "rw", HighEntropy: true},
		},
		Count: 2,
	}

	if output.Count != 2 {
		t.Errorf("Count = %d, want 2", output.Count)
	}
	if !output.Sections[1].HighEntropy {
		t.Error("Section with entropy >= 7.0 should have HighEntropy=true")
	}
}

func TestImportsOutput_Structure(t *testing.T) {
	output := ImportsOutput{
		Imports: []ImportInfo{
			{Library: "libc.so.6", Function: "printf", Address: "0x3000"},
			{Library: "libc.so.6", Function: "malloc", Address: "0x3004"},
			{Library: "libpthread.so.0", Function: "pthread_create", Address: "0x4000"},
		},
		Count: 3,
	}

	if output.Count != 3 {
		t.Errorf("Count = %d, want 3", output.Count)
	}
}

func TestPrintSectionsMarkdown(t *testing.T) {
	output := SectionsOutput{
		Sections: []SectionInfo{
			{Name: ".text", VirtualAddr: "0x1000", VirtualSize: 0x500, RawSize: 0x400, Entropy: 6.5, Permissions: "rx"},
			{Name: ".packed", VirtualAddr: "0x2000", VirtualSize: 0x200, RawSize: 0x200, Entropy: 7.8, Permissions: "rw", HighEntropy: true},
		},
		Count: 2,
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printSectionsMarkdown(output)

	w.Close()
	os.Stdout = old

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	result := string(buf[:n])

	if !contains(result, "Sections (2)") {
		t.Error("printSectionsMarkdown() should include count")
	}
	if !contains(result, ".text") {
		t.Error("printSectionsMarkdown() should include section names")
	}
	if !contains(result, "⚠") {
		t.Error("printSectionsMarkdown() should flag high entropy sections")
	}
}

func TestPrintSectionsMarkdown_Empty(t *testing.T) {
	output := SectionsOutput{
		Sections: []SectionInfo{},
		Count:    0,
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printSectionsMarkdown(output)

	w.Close()
	os.Stdout = old

	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	result := string(buf[:n])

	if !contains(result, "No sections found") {
		t.Error("printSectionsMarkdown() should indicate no sections found")
	}
}

func TestPrintImportsMarkdown(t *testing.T) {
	output := ImportsOutput{
		Imports: []ImportInfo{
			{Library: "libc.so.6", Function: "printf", Address: "0x3000"},
			{Library: "libc.so.6", Function: "malloc", Address: "0x3004"},
			{Library: "libm.so.6", Function: "sin"},
		},
		Count: 3,
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printImportsMarkdown(output)

	w.Close()
	os.Stdout = old

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	result := string(buf[:n])

	if !contains(result, "Imports (3)") {
		t.Error("printImportsMarkdown() should include count")
	}
	if !contains(result, "libc.so.6") {
		t.Error("printImportsMarkdown() should include library names")
	}
	if !contains(result, "printf") {
		t.Error("printImportsMarkdown() should include function names")
	}
}

func TestPrintImportsMarkdown_Empty(t *testing.T) {
	output := ImportsOutput{
		Imports: []ImportInfo{},
		Count:   0,
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printImportsMarkdown(output)

	w.Close()
	os.Stdout = old

	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	result := string(buf[:n])

	if !contains(result, "No imports found") {
		t.Error("printImportsMarkdown() should indicate no imports found")
	}
}

func TestPrintSummaryMarkdown(t *testing.T) {
	summaryOutput := SummaryOutput{
		Metadata: MetadataSummary{
			Format: "elf",
			Arch:   "x86_64",
			Size:   12345,
			SHA256: "abc123def456",
		},
		YARAMatchCount: 3,
		YARAMatches: []YARASummary{
			{Rule: "Malware_Packed", Tags: []string{"malware", "packed"}},
		},
		Counts: CountSummary{
			Sections:  5,
			Imports:   20,
			Exports:   2,
			Strings:   500,
			Functions: 100,
			IOCs:      5,
		},
		Cached:       false,
		AnalysisTime: "2.5s",
	}

	meta := &cache.CachedMetadata{
		Binary: model.BinaryMetadata{
			Format: model.FormatELF,
			Arch:   "x86_64",
		},
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printSummaryMarkdown(summaryOutput, meta)

	w.Close()
	os.Stdout = old

	buf := make([]byte, 8192)
	n, _ := r.Read(buf)
	result := string(buf[:n])

	if !contains(result, "Binary Summary") {
		t.Error("printSummaryMarkdown() should include header")
	}
	if !contains(result, "Counts") {
		t.Error("printSummaryMarkdown() should include counts")
	}
}

func TestSectionToInfo(t *testing.T) {
	section := model.Section{
		Name:         ".text",
		VirtualAddr:  0x1000,
		VirtualSize:  0x500,
		RawSize:      0x400,
		Entropy:      7.5,
		Permissions:  "rx",
	}

	info := sectionToInfo(section)

	if info.Name != ".text" {
		t.Errorf("Name = %q, want %q", info.Name, ".text")
	}
	if info.VirtualAddr != "0x1000" {
		t.Errorf("VirtualAddr = %q, want %q", info.VirtualAddr, "0x1000")
	}
	if !info.HighEntropy {
		t.Error("HighEntropy should be true for entropy >= 7.0")
	}
}

func TestSectionToInfo_LowEntropy(t *testing.T) {
	section := model.Section{
		Name:    ".data",
		Entropy: 4.5,
	}

	info := sectionToInfo(section)

	if info.HighEntropy {
		t.Error("HighEntropy should be false for entropy < 7.0")
	}
}

func TestCountSummary_Structure(t *testing.T) {
	counts := CountSummary{
		Sections:  10,
		Imports:   50,
		Exports:   5,
		Strings:   1000,
		Functions: 200,
		IOCs:      15,
	}

	total := counts.Sections + counts.Imports + counts.Exports + counts.Functions + counts.IOCs
	if total != 280 {
		t.Errorf("Sum of counts = %d, want 280", total)
	}
}

func TestYARASummary_Structure(t *testing.T) {
	summary := YARASummary{
		Rule: "Malware_Test",
		Tags: []string{"malware", "test"},
	}

	if summary.Rule == "" {
		t.Error("Rule should not be empty")
	}
	if len(summary.Tags) != 2 {
		t.Errorf("Tags length = %d, want 2", len(summary.Tags))
	}
}
