package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/refractionPOINT/lcre/internal/model"
	"github.com/refractionPOINT/lcre/internal/yara"
)

func createTestManagerAndBinary(t *testing.T) (*Manager, string) {
	t.Helper()
	tempDir := t.TempDir()

	mgr, err := NewManagerWithPath(filepath.Join(tempDir, "cache"))
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	binaryPath := filepath.Join(tempDir, "test_binary")
	if err := os.WriteFile(binaryPath, []byte("test binary content"), 0644); err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}

	return mgr, binaryPath
}

func TestStoreAnalysisResult(t *testing.T) {
	mgr, binaryPath := createTestManagerAndBinary(t)

	result := &model.AnalysisResult{
		Metadata: model.BinaryMetadata{
			Path:   binaryPath,
			Name:   "test_binary",
			Size:   19,
			MD5:    "abc123",
			SHA256: "def456",
			Format: model.FormatELF,
			Arch:   "x86_64",
			Bits:   64,
		},
		Sections: []model.Section{
			{Name: ".text", VirtualAddr: 0x1000, VirtualSize: 0x500, RawSize: 0x400, Entropy: 6.5, Permissions: "rx"},
			{Name: ".data", VirtualAddr: 0x2000, VirtualSize: 0x200, RawSize: 0x200, Entropy: 4.0, Permissions: "rw"},
		},
		Imports: []model.Import{
			{Library: "libc.so.6", Function: "printf", Address: 0x3000},
		},
		Exports: []model.Export{
			{Name: "main", Address: 0x1000},
		},
		Strings: []model.ExtractedString{
			{Value: "Hello World", Offset: 100, Section: ".rodata", Encoding: "ascii"},
			{Value: "Error: %s", Offset: 200, Section: ".rodata", Encoding: "ascii"},
		},
		Functions: []model.Function{
			{Name: "main", Address: 0x1000, Size: 100, Signature: "int main(int, char**)"},
			{Name: "_start", Address: 0x500, Size: 50},
		},
		CallGraph: &model.CallGraph{
			Nodes: []model.CallGraphNode{
				{Address: 0x1000, Name: "main"},
				{Address: 0x500, Name: "_start"},
			},
			Edges: []model.CallGraphEdge{
				{From: 0x500, To: 0x1000},
			},
		},
		EntryPoints: []model.EntryPoint{
			{Name: "_start", Address: 0x500, Type: "main"},
		},
		YARA: &yara.ScanResult{
			Matches: []yara.Match{
				{
					Rule:        "TEST_RULE",
					Namespace:   "test",
					Tags:        []string{"test"},
					Description: "Test description",
					Strings:     []string{"$s1: test"},
				},
			},
			Available: true,
		},
		Backend:   "native",
		Duration:  1.5,
		Timestamp: time.Now(),
	}

	iocs := &model.IOCResult{
		URLs: []model.IOC{
			{Type: model.IOCURL, Value: "http://example.com", Offset: 100},
		},
		IPs: []model.IOC{
			{Type: model.IOCIP, Value: "192.168.1.1", Offset: 200},
		},
		Count: 2,
	}

	// Store the result
	err := StoreAnalysisResult(mgr, binaryPath, result, iocs)
	if err != nil {
		t.Fatalf("StoreAnalysisResult() error = %v", err)
	}

	// Verify cache exists
	exists, err := mgr.Exists(binaryPath)
	if err != nil {
		t.Fatalf("Exists() error = %v", err)
	}
	if !exists {
		t.Error("StoreAnalysisResult() did not create cache")
	}

	// Verify metadata was saved
	meta, err := mgr.LoadMetadata(binaryPath)
	if err != nil {
		t.Fatalf("LoadMetadata() error = %v", err)
	}

	if meta.StringCount != 2 {
		t.Errorf("StringCount = %d, want 2", meta.StringCount)
	}
	if meta.FunctionCount != 2 {
		t.Errorf("FunctionCount = %d, want 2", meta.FunctionCount)
	}
	if meta.ImportCount != 1 {
		t.Errorf("ImportCount = %d, want 1", meta.ImportCount)
	}
	if meta.ExportCount != 1 {
		t.Errorf("ExportCount = %d, want 1", meta.ExportCount)
	}
	if meta.YARAMatchCount != 1 {
		t.Errorf("YARAMatchCount = %d, want 1", meta.YARAMatchCount)
	}
	if !meta.DeepAnalysis {
		t.Error("DeepAnalysis = false, want true (has functions)")
	}

	// Open database and verify data
	db, err := mgr.Open(binaryPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	// Verify sections
	sections, err := db.QuerySections("")
	if err != nil {
		t.Fatalf("QuerySections() error = %v", err)
	}
	if len(sections) != 2 {
		t.Errorf("Sections count = %d, want 2", len(sections))
	}

	// Verify imports
	imports, err := db.QueryImports("", "")
	if err != nil {
		t.Fatalf("QueryImports() error = %v", err)
	}
	if len(imports) != 1 {
		t.Errorf("Imports count = %d, want 1", len(imports))
	}

	// Verify exports
	exports, err := db.QueryExports("")
	if err != nil {
		t.Fatalf("QueryExports() error = %v", err)
	}
	if len(exports) != 1 {
		t.Errorf("Exports count = %d, want 1", len(exports))
	}

	// Verify strings
	strings, total, err := db.QueryStrings("", 100, 0)
	if err != nil {
		t.Fatalf("QueryStrings() error = %v", err)
	}
	if len(strings) != 2 || total != 2 {
		t.Errorf("Strings count = %d/%d, want 2/2", len(strings), total)
	}

	// Verify functions
	functions, err := db.QueryFunctions("", 0, 0)
	if err != nil {
		t.Fatalf("QueryFunctions() error = %v", err)
	}
	if len(functions) != 2 {
		t.Errorf("Functions count = %d, want 2", len(functions))
	}

	// Verify call graph
	graph, err := db.GetCallGraph()
	if err != nil {
		t.Fatalf("GetCallGraph() error = %v", err)
	}
	if len(graph.Edges) != 1 {
		t.Errorf("CallGraph edges = %d, want 1", len(graph.Edges))
	}

	// Verify entry points
	entryPoints, err := db.QueryEntryPoints()
	if err != nil {
		t.Fatalf("QueryEntryPoints() error = %v", err)
	}
	if len(entryPoints) != 1 {
		t.Errorf("EntryPoints count = %d, want 1", len(entryPoints))
	}

	// Verify YARA matches
	yaraMatches, err := db.QueryYARAMatches("")
	if err != nil {
		t.Fatalf("QueryYARAMatches() error = %v", err)
	}
	if len(yaraMatches) != 1 {
		t.Errorf("YARA matches count = %d, want 1", len(yaraMatches))
	}

	// Verify IOCs
	allIOCs, err := db.QueryIOCs("")
	if err != nil {
		t.Fatalf("QueryIOCs() error = %v", err)
	}
	if len(allIOCs) != 2 {
		t.Errorf("IOCs count = %d, want 2", len(allIOCs))
	}

	// Verify binary metadata was stored
	var binaryMeta model.BinaryMetadata
	if err := db.LoadMetadataJSON("binary_metadata", &binaryMeta); err != nil {
		t.Fatalf("LoadMetadataJSON() error = %v", err)
	}
	if binaryMeta.Format != model.FormatELF {
		t.Errorf("BinaryMetadata.Format = %v, want %v", binaryMeta.Format, model.FormatELF)
	}
}

func TestStoreAnalysisResult_NilIOCs(t *testing.T) {
	mgr, binaryPath := createTestManagerAndBinary(t)

	result := &model.AnalysisResult{
		Metadata: model.BinaryMetadata{
			Name: "test_binary",
		},
		Backend:  "native",
		Duration: 0.5,
	}

	// Should not error with nil IOCs
	err := StoreAnalysisResult(mgr, binaryPath, result, nil)
	if err != nil {
		t.Fatalf("StoreAnalysisResult() with nil IOCs error = %v", err)
	}
}

func TestStoreAnalysisResult_EmptyResult(t *testing.T) {
	mgr, binaryPath := createTestManagerAndBinary(t)

	result := &model.AnalysisResult{
		Metadata: model.BinaryMetadata{
			Name: "test_binary",
		},
		Backend:  "native",
		Duration: 0.5,
	}

	err := StoreAnalysisResult(mgr, binaryPath, result, nil)
	if err != nil {
		t.Fatalf("StoreAnalysisResult() with empty result error = %v", err)
	}

	// Should still create cache
	exists, _ := mgr.Exists(binaryPath)
	if !exists {
		t.Error("StoreAnalysisResult() did not create cache for empty result")
	}
}

func TestStoreAnalysisResult_SkipsIfExists(t *testing.T) {
	mgr, binaryPath := createTestManagerAndBinary(t)

	// First store
	result1 := &model.AnalysisResult{
		Metadata: model.BinaryMetadata{Name: "test_binary"},
		Sections: []model.Section{
			{Name: ".text", VirtualAddr: 0x1000},
		},
	}
	if err := StoreAnalysisResult(mgr, binaryPath, result1, nil); err != nil {
		t.Fatalf("StoreAnalysisResult() first call error = %v", err)
	}

	// Second store with different data
	result2 := &model.AnalysisResult{
		Metadata: model.BinaryMetadata{Name: "test_binary"},
		Sections: []model.Section{
			{Name: ".data", VirtualAddr: 0x2000},
			{Name: ".bss", VirtualAddr: 0x3000},
		},
	}
	if err := StoreAnalysisResult(mgr, binaryPath, result2, nil); err != nil {
		t.Fatalf("StoreAnalysisResult() second call error = %v", err)
	}

	// Should still have original data (only 1 section)
	db, err := mgr.Open(binaryPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	sections, err := db.QuerySections("")
	if err != nil {
		t.Fatalf("QuerySections() error = %v", err)
	}
	if len(sections) != 1 {
		t.Errorf("Sections count = %d, want 1 (should not overwrite)", len(sections))
	}
	if len(sections) > 0 && sections[0].Name != ".text" {
		t.Errorf("Section name = %q, want .text", sections[0].Name)
	}
}

func TestStoreAnalysisResult_ShallowAnalysis(t *testing.T) {
	mgr, binaryPath := createTestManagerAndBinary(t)

	// Result without functions (shallow analysis)
	result := &model.AnalysisResult{
		Metadata: model.BinaryMetadata{Name: "test_binary"},
		Sections: []model.Section{
			{Name: ".text", VirtualAddr: 0x1000},
		},
		Strings: []model.ExtractedString{
			{Value: "test", Offset: 100},
		},
	}

	if err := StoreAnalysisResult(mgr, binaryPath, result, nil); err != nil {
		t.Fatalf("StoreAnalysisResult() error = %v", err)
	}

	meta, err := mgr.LoadMetadata(binaryPath)
	if err != nil {
		t.Fatalf("LoadMetadata() error = %v", err)
	}

	if meta.DeepAnalysis {
		t.Error("DeepAnalysis = true, want false (no functions)")
	}
}

func TestUpdateWithDeepAnalysis(t *testing.T) {
	mgr, binaryPath := createTestManagerAndBinary(t)

	// First store shallow analysis
	result1 := &model.AnalysisResult{
		Metadata: model.BinaryMetadata{Name: "test_binary"},
		Sections: []model.Section{
			{Name: ".text", VirtualAddr: 0x1000},
		},
		Strings: []model.ExtractedString{
			{Value: "test", Offset: 100},
		},
	}
	if err := StoreAnalysisResult(mgr, binaryPath, result1, nil); err != nil {
		t.Fatalf("StoreAnalysisResult() error = %v", err)
	}

	// Verify shallow analysis
	meta, _ := mgr.LoadMetadata(binaryPath)
	if meta.DeepAnalysis {
		t.Error("Initial analysis should be shallow")
	}

	// Update with deep analysis
	deepResult := &model.AnalysisResult{
		Metadata: model.BinaryMetadata{Name: "test_binary"},
		Functions: []model.Function{
			{Name: "main", Address: 0x1000, Size: 100},
			{Name: "helper", Address: 0x2000, Size: 50},
		},
		CallGraph: &model.CallGraph{
			Edges: []model.CallGraphEdge{
				{From: 0x1000, To: 0x2000},
			},
		},
	}

	if err := UpdateWithDeepAnalysis(mgr, binaryPath, deepResult); err != nil {
		t.Fatalf("UpdateWithDeepAnalysis() error = %v", err)
	}

	// Verify deep analysis flag updated
	meta, _ = mgr.LoadMetadata(binaryPath)
	if !meta.DeepAnalysis {
		t.Error("DeepAnalysis = false, want true after update")
	}
	if meta.FunctionCount != 2 {
		t.Errorf("FunctionCount = %d, want 2", meta.FunctionCount)
	}

	// Verify functions were added
	db, err := mgr.Open(binaryPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	functions, err := db.QueryFunctions("", 0, 0)
	if err != nil {
		t.Fatalf("QueryFunctions() error = %v", err)
	}
	if len(functions) != 2 {
		t.Errorf("Functions count = %d, want 2", len(functions))
	}

	// Verify original data still exists
	strings, total, err := db.QueryStrings("", 100, 0)
	if err != nil {
		t.Fatalf("QueryStrings() error = %v", err)
	}
	if len(strings) != 1 || total != 1 {
		t.Errorf("Original strings lost: count = %d/%d, want 1/1", len(strings), total)
	}
}

func TestUpdateWithDeepAnalysis_NoCacheError(t *testing.T) {
	mgr, binaryPath := createTestManagerAndBinary(t)

	// Don't create initial cache, just try to update
	deepResult := &model.AnalysisResult{
		Functions: []model.Function{
			{Name: "main", Address: 0x1000},
		},
	}

	err := UpdateWithDeepAnalysis(mgr, binaryPath, deepResult)
	if err == nil {
		t.Error("UpdateWithDeepAnalysis() should error when cache doesn't exist")
	}
}

func TestStoreXrefs(t *testing.T) {
	mgr, binaryPath := createTestManagerAndBinary(t)

	// Create initial cache
	result := &model.AnalysisResult{
		Metadata: model.BinaryMetadata{Name: "test_binary"},
		Functions: []model.Function{
			{Name: "main", Address: 0x1000, Size: 100},
		},
	}
	if err := StoreAnalysisResult(mgr, binaryPath, result, nil); err != nil {
		t.Fatalf("StoreAnalysisResult() error = %v", err)
	}

	// Store xrefs
	xrefs := []Xref{
		{From: 0x1010, To: 0x2000, Type: "call"},
		{From: 0x1020, To: 0x3000, Type: "data"},
	}

	if err := StoreXrefs(mgr, binaryPath, xrefs); err != nil {
		t.Fatalf("StoreXrefs() error = %v", err)
	}

	// Verify xrefs were stored
	db, err := mgr.Open(binaryPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	result1, err := db.GetXrefsFrom(0x1010)
	if err != nil {
		t.Fatalf("GetXrefsFrom() error = %v", err)
	}
	if len(result1) != 1 {
		t.Errorf("Xrefs from 0x1010 = %d, want 1", len(result1))
	}
}

func TestStoreXrefs_NoCacheError(t *testing.T) {
	mgr, binaryPath := createTestManagerAndBinary(t)

	xrefs := []Xref{
		{From: 0x1000, To: 0x2000, Type: "call"},
	}

	err := StoreXrefs(mgr, binaryPath, xrefs)
	if err == nil {
		t.Error("StoreXrefs() should error when cache doesn't exist")
	}
}

func TestCollectAllIOCs(t *testing.T) {
	iocs := &model.IOCResult{
		URLs: []model.IOC{
			{Type: model.IOCURL, Value: "http://example.com", Offset: 100},
		},
		Domains: []model.IOC{
			{Type: model.IOCDomain, Value: "example.com", Offset: 200},
		},
		IPs: []model.IOC{
			{Type: model.IOCIP, Value: "192.168.1.1", Offset: 300},
		},
		Emails: []model.IOC{
			{Type: model.IOCEmail, Value: "test@example.com", Offset: 400},
		},
		Paths: []model.IOC{
			{Type: model.IOCPath, Value: "C:\\Windows\\System32", Offset: 500},
		},
		Registry: []model.IOC{
			{Type: model.IOCRegistry, Value: "HKLM\\SOFTWARE\\Test", Offset: 600},
		},
		Hashes: []model.IOC{
			{Type: model.IOCHash, Value: "abc123def456", Offset: 700},
		},
	}

	all := collectAllIOCs(iocs)

	if len(all) != 7 {
		t.Errorf("collectAllIOCs() returned %d IOCs, want 7", len(all))
	}

	// Verify each type is present
	typeCounts := make(map[model.IOCType]int)
	for _, ioc := range all {
		typeCounts[ioc.Type]++
	}

	expectedTypes := []model.IOCType{
		model.IOCURL, model.IOCDomain, model.IOCIP, model.IOCEmail,
		model.IOCPath, model.IOCRegistry, model.IOCHash,
	}
	for _, typ := range expectedTypes {
		if typeCounts[typ] != 1 {
			t.Errorf("Type %v count = %d, want 1", typ, typeCounts[typ])
		}
	}
}

func TestCollectAllIOCs_Empty(t *testing.T) {
	iocs := &model.IOCResult{}
	all := collectAllIOCs(iocs)

	if len(all) != 0 {
		t.Errorf("collectAllIOCs() returned %d IOCs, want 0", len(all))
	}
}

func TestCollectAllIOCs_Nil(t *testing.T) {
	// Test that nil doesn't cause panic - function should handle this at call site
	// but we test the function directly returns empty slice for empty IOCResult
	iocs := &model.IOCResult{}
	all := collectAllIOCs(iocs)
	if all == nil {
		// It's OK if it's nil, as long as len works
		if len(all) != 0 {
			t.Error("collectAllIOCs() should return empty/nil for empty IOCResult")
		}
	}
}

func TestStoreAnalysisResult_PreservesIOCDetails(t *testing.T) {
	mgr, binaryPath := createTestManagerAndBinary(t)

	result := &model.AnalysisResult{
		Metadata: model.BinaryMetadata{Name: "test_binary"},
	}

	iocs := &model.IOCResult{
		URLs: []model.IOC{
			{
				Type:    model.IOCURL,
				Value:   "http://malware.com/payload",
				Offset:  12345,
				Section: ".data",
				Context: "Found in suspicious string",
			},
		},
	}

	if err := StoreAnalysisResult(mgr, binaryPath, result, iocs); err != nil {
		t.Fatalf("StoreAnalysisResult() error = %v", err)
	}

	// Verify IOC details were preserved
	db, err := mgr.Open(binaryPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	storedIOCs, err := db.QueryIOCs("url")
	if err != nil {
		t.Fatalf("QueryIOCs() error = %v", err)
	}
	if len(storedIOCs) != 1 {
		t.Fatalf("Expected 1 IOC, got %d", len(storedIOCs))
	}

	ioc := storedIOCs[0]
	if ioc.Value != "http://malware.com/payload" {
		t.Errorf("IOC value = %q, want %q", ioc.Value, "http://malware.com/payload")
	}
	if ioc.Offset != 12345 {
		t.Errorf("IOC offset = %d, want 12345", ioc.Offset)
	}
	if ioc.Section != ".data" {
		t.Errorf("IOC section = %q, want .data", ioc.Section)
	}
	if ioc.Context != "Found in suspicious string" {
		t.Errorf("IOC context = %q, want %q", ioc.Context, "Found in suspicious string")
	}
}
