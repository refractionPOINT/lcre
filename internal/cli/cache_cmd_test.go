package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/refractionPOINT/lcre/internal/cache"
	"github.com/refractionPOINT/lcre/internal/model"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1572864, "1.5 MB"},
		{1073741824, "1.0 GB"},
		{1099511627776, "1.0 TB"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatBytes(tt.bytes)
			if result != tt.expected {
				t.Errorf("formatBytes(%d) = %q, want %q", tt.bytes, result, tt.expected)
			}
		})
	}
}

// Helper to create a cache for testing
func setupCacheForTests(t *testing.T) (*cache.Manager, string, string) {
	t.Helper()

	tempDir := t.TempDir()
	cacheDir := filepath.Join(tempDir, "cache")
	mgr, err := cache.NewManagerWithPath(cacheDir)
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	// Create test binary
	binaryPath := filepath.Join(tempDir, "test_binary")
	if err := os.WriteFile(binaryPath, []byte("test binary content"), 0644); err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}

	// Create cache with test data
	result := &model.AnalysisResult{
		Metadata: model.BinaryMetadata{
			Path:   binaryPath,
			Name:   "test_binary",
			Size:   19,
			Format: model.FormatELF,
		},
		Sections: []model.Section{
			{Name: ".text", VirtualAddr: 0x1000},
		},
		Strings: []model.ExtractedString{
			{Value: "test", Offset: 100},
		},
		Backend:   "native",
		Duration:  0.5,
		Timestamp: time.Now(),
	}

	if err := cache.StoreAnalysisResult(mgr, binaryPath, result, nil); err != nil {
		t.Fatalf("StoreAnalysisResult() error = %v", err)
	}

	return mgr, binaryPath, cacheDir
}

func TestCacheList(t *testing.T) {
	mgr, binaryPath, _ := setupCacheForTests(t)

	// List should return our cache
	entries, err := mgr.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if len(entries) != 1 {
		t.Errorf("List() returned %d entries, want 1", len(entries))
	}

	// Verify entry has correct metadata
	entry := entries[0]
	if len(entry.SHA256) != 64 {
		t.Errorf("Entry SHA256 length = %d, want 64", len(entry.SHA256))
	}

	// Check the path matches
	meta, err := mgr.LoadMetadata(binaryPath)
	if err != nil {
		t.Fatalf("LoadMetadata() error = %v", err)
	}
	if entry.Path != meta.Entry.Path {
		t.Errorf("Entry path = %q, want %q", entry.Path, meta.Entry.Path)
	}
}

func TestCacheList_Empty(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := cache.NewManagerWithPath(filepath.Join(tempDir, "empty_cache"))
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	entries, err := mgr.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if len(entries) != 0 {
		t.Errorf("List() returned %d entries, want 0", len(entries))
	}
}

func TestCacheClear_Specific(t *testing.T) {
	mgr, binaryPath, _ := setupCacheForTests(t)

	// Verify cache exists
	exists, _ := mgr.Exists(binaryPath)
	if !exists {
		t.Fatal("Cache should exist before clear")
	}

	// Clear specific binary
	if err := mgr.Clear(binaryPath); err != nil {
		t.Fatalf("Clear() error = %v", err)
	}

	// Verify cache removed
	exists, _ = mgr.Exists(binaryPath)
	if exists {
		t.Error("Cache should not exist after clear")
	}
}

func TestCacheClear_BySHA256(t *testing.T) {
	mgr, binaryPath, _ := setupCacheForTests(t)

	// Get hash
	hash, err := mgr.GetHash(binaryPath)
	if err != nil {
		t.Fatalf("GetHash() error = %v", err)
	}

	// Clear by hash
	if err := mgr.ClearBySHA256(hash); err != nil {
		t.Fatalf("ClearBySHA256() error = %v", err)
	}

	// Verify removed
	exists, _ := mgr.Exists(binaryPath)
	if exists {
		t.Error("Cache should not exist after ClearBySHA256")
	}
}

func TestCacheClear_All(t *testing.T) {
	tempDir := t.TempDir()
	cacheDir := filepath.Join(tempDir, "cache")
	mgr, err := cache.NewManagerWithPath(cacheDir)
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	// Create multiple caches
	binaries := []string{"binary1", "binary2", "binary3"}
	for _, name := range binaries {
		binaryPath := filepath.Join(tempDir, name)
		if err := os.WriteFile(binaryPath, []byte("content of "+name), 0644); err != nil {
			t.Fatalf("Failed to create test binary: %v", err)
		}

		result := &model.AnalysisResult{
			Metadata: model.BinaryMetadata{Name: name},
		}
		if err := cache.StoreAnalysisResult(mgr, binaryPath, result, nil); err != nil {
			t.Fatalf("StoreAnalysisResult() error = %v", err)
		}
	}

	// Verify caches exist
	entries, _ := mgr.List()
	if len(entries) != 3 {
		t.Fatalf("Expected 3 caches, got %d", len(entries))
	}

	// Clear all
	if err := mgr.ClearAll(); err != nil {
		t.Fatalf("ClearAll() error = %v", err)
	}

	// Verify all removed
	entries, _ = mgr.List()
	if len(entries) != 0 {
		t.Errorf("Expected 0 caches after ClearAll, got %d", len(entries))
	}
}

func TestCacheInfo(t *testing.T) {
	mgr, binaryPath, _ := setupCacheForTests(t)

	// Check cache exists
	exists, err := mgr.Exists(binaryPath)
	if err != nil {
		t.Fatalf("Exists() error = %v", err)
	}
	if !exists {
		t.Fatal("Cache should exist")
	}

	// Load metadata
	meta, err := mgr.LoadMetadata(binaryPath)
	if err != nil {
		t.Fatalf("LoadMetadata() error = %v", err)
	}

	// Verify metadata fields
	if meta.Entry.Path != binaryPath {
		t.Errorf("Path = %q, want %q", meta.Entry.Path, binaryPath)
	}
	if meta.Backend != "native" {
		t.Errorf("Backend = %q, want %q", meta.Backend, "native")
	}
	if meta.StringCount != 1 {
		t.Errorf("StringCount = %d, want 1", meta.StringCount)
	}
	if len(meta.Entry.SHA256) != 64 {
		t.Errorf("SHA256 length = %d, want 64", len(meta.Entry.SHA256))
	}
}

func TestCacheInfo_NotCached(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := cache.NewManagerWithPath(filepath.Join(tempDir, "cache"))
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	// Create binary but don't cache it
	binaryPath := filepath.Join(tempDir, "uncached_binary")
	if err := os.WriteFile(binaryPath, []byte("not cached"), 0644); err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}

	exists, err := mgr.Exists(binaryPath)
	if err != nil {
		t.Fatalf("Exists() error = %v", err)
	}
	if exists {
		t.Error("Cache should not exist for uncached binary")
	}
}

func TestCacheListEntry_Fields(t *testing.T) {
	mgr, binaryPath, _ := setupCacheForTests(t)

	entries, err := mgr.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("Expected 1 entry, got %d", len(entries))
	}

	entry := entries[0]

	// Verify all fields are populated
	if entry.SHA256 == "" {
		t.Error("SHA256 should not be empty")
	}
	if entry.Path == "" {
		t.Error("Path should not be empty")
	}
	if entry.Size <= 0 {
		t.Error("Size should be positive")
	}
	if entry.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}

	// Verify path matches
	meta, _ := mgr.LoadMetadata(binaryPath)
	if entry.Path != meta.Entry.Path {
		t.Errorf("Path mismatch: entry=%q, meta=%q", entry.Path, meta.Entry.Path)
	}
}

func TestCacheListEntry_DeepAnalysis(t *testing.T) {
	tempDir := t.TempDir()
	cacheDir := filepath.Join(tempDir, "cache")
	mgr, err := cache.NewManagerWithPath(cacheDir)
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	// Create shallow analysis cache
	shallowPath := filepath.Join(tempDir, "shallow_binary")
	if err := os.WriteFile(shallowPath, []byte("shallow content"), 0644); err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}
	shallowResult := &model.AnalysisResult{
		Metadata: model.BinaryMetadata{Name: "shallow"},
		// No functions = shallow analysis
	}
	if err := cache.StoreAnalysisResult(mgr, shallowPath, shallowResult, nil); err != nil {
		t.Fatalf("StoreAnalysisResult() error = %v", err)
	}

	// Create deep analysis cache
	deepPath := filepath.Join(tempDir, "deep_binary")
	if err := os.WriteFile(deepPath, []byte("deep content"), 0644); err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}
	deepResult := &model.AnalysisResult{
		Metadata: model.BinaryMetadata{Name: "deep"},
		Functions: []model.Function{
			{Name: "main", Address: 0x1000},
		},
	}
	if err := cache.StoreAnalysisResult(mgr, deepPath, deepResult, nil); err != nil {
		t.Fatalf("StoreAnalysisResult() error = %v", err)
	}

	entries, err := mgr.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("Expected 2 entries, got %d", len(entries))
	}

	// Find each entry and verify DeepAnalysis flag
	var foundShallow, foundDeep bool
	for _, e := range entries {
		if e.Path == shallowPath {
			foundShallow = true
			if e.DeepAnalysis {
				t.Error("Shallow binary should have DeepAnalysis=false")
			}
		}
		if e.Path == deepPath {
			foundDeep = true
			if !e.DeepAnalysis {
				t.Error("Deep binary should have DeepAnalysis=true")
			}
		}
	}

	if !foundShallow {
		t.Error("Shallow entry not found in list")
	}
	if !foundDeep {
		t.Error("Deep entry not found in list")
	}
}

func TestCacheWithMetadataRoundTrip(t *testing.T) {
	mgr, binaryPath, _ := setupCacheForTests(t)

	// Load metadata
	meta1, err := mgr.LoadMetadata(binaryPath)
	if err != nil {
		t.Fatalf("LoadMetadata() error = %v", err)
	}

	// Modify and save
	meta1.StringCount = 100
	meta1.FunctionCount = 50
	if err := mgr.SaveMetadata(binaryPath, meta1); err != nil {
		t.Fatalf("SaveMetadata() error = %v", err)
	}

	// Load again and verify
	meta2, err := mgr.LoadMetadata(binaryPath)
	if err != nil {
		t.Fatalf("LoadMetadata() error = %v", err)
	}

	if meta2.StringCount != 100 {
		t.Errorf("StringCount = %d, want 100", meta2.StringCount)
	}
	if meta2.FunctionCount != 50 {
		t.Errorf("FunctionCount = %d, want 50", meta2.FunctionCount)
	}
}

func TestCacheHasDeepAnalysis(t *testing.T) {
	mgr, binaryPath, _ := setupCacheForTests(t)

	// Initial cache is shallow (no functions in setupCacheForTests data has 1 string but let's verify)
	// Actually our setup does have sections and strings but not functions with call graphs
	// Let's check what it reports

	meta, _ := mgr.LoadMetadata(binaryPath)
	t.Logf("DeepAnalysis in metadata: %v", meta.DeepAnalysis)

	// HasDeepAnalysis should match metadata
	hasDeep, err := mgr.HasDeepAnalysis(binaryPath)
	if err != nil {
		t.Fatalf("HasDeepAnalysis() error = %v", err)
	}
	if hasDeep != meta.DeepAnalysis {
		t.Errorf("HasDeepAnalysis() = %v, metadata.DeepAnalysis = %v", hasDeep, meta.DeepAnalysis)
	}

	// Update to deep analysis
	meta.DeepAnalysis = true
	if err := mgr.SaveMetadata(binaryPath, meta); err != nil {
		t.Fatalf("SaveMetadata() error = %v", err)
	}

	hasDeep, _ = mgr.HasDeepAnalysis(binaryPath)
	if !hasDeep {
		t.Error("HasDeepAnalysis() = false after update, want true")
	}
}

func TestCacheDirectoryStructure(t *testing.T) {
	mgr, binaryPath, cacheDir := setupCacheForTests(t)

	// Get cache dir for binary
	binaryCacheDir, err := mgr.GetCacheDir(binaryPath)
	if err != nil {
		t.Fatalf("GetCacheDir() error = %v", err)
	}

	// Should be under the cache base dir
	if filepath.Dir(binaryCacheDir) != cacheDir {
		t.Errorf("Cache dir parent = %q, want %q", filepath.Dir(binaryCacheDir), cacheDir)
	}

	// Database file should exist
	dbPath := filepath.Join(binaryCacheDir, "analysis.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("Database file should exist")
	}

	// Metadata file should exist
	metaPath := filepath.Join(binaryCacheDir, "metadata.json")
	if _, err := os.Stat(metaPath); os.IsNotExist(err) {
		t.Error("Metadata file should exist")
	}

	// Decompiled directory should exist
	decompiledPath := filepath.Join(binaryCacheDir, "decompiled")
	if _, err := os.Stat(decompiledPath); os.IsNotExist(err) {
		t.Error("Decompiled directory should exist")
	}
}

func TestMultipleBinariesWithSameContent(t *testing.T) {
	tempDir := t.TempDir()
	cacheDir := filepath.Join(tempDir, "cache")
	mgr, err := cache.NewManagerWithPath(cacheDir)
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	// Create two binaries with same content
	content := []byte("identical content")
	binary1 := filepath.Join(tempDir, "binary1")
	binary2 := filepath.Join(tempDir, "binary2")

	os.WriteFile(binary1, content, 0644)
	os.WriteFile(binary2, content, 0644)

	// Cache first binary
	result1 := &model.AnalysisResult{
		Metadata: model.BinaryMetadata{Path: binary1, Name: "binary1"},
	}
	if err := cache.StoreAnalysisResult(mgr, binary1, result1, nil); err != nil {
		t.Fatalf("StoreAnalysisResult() error = %v", err)
	}

	// Both should point to same cache dir (same hash)
	dir1, _ := mgr.GetCacheDir(binary1)
	dir2, _ := mgr.GetCacheDir(binary2)

	if dir1 != dir2 {
		t.Error("Identical binaries should share cache directory")
	}

	// List should show only one entry
	entries, _ := mgr.List()
	if len(entries) != 1 {
		t.Errorf("Expected 1 cache entry for identical content, got %d", len(entries))
	}
}

func TestClearNonExistentCache(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := cache.NewManagerWithPath(filepath.Join(tempDir, "cache"))
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	// Create a binary but don't cache it
	binaryPath := filepath.Join(tempDir, "uncached")
	os.WriteFile(binaryPath, []byte("not cached"), 0644)

	// Clear should not error (no-op)
	err = mgr.Clear(binaryPath)
	if err != nil {
		t.Errorf("Clear() on non-existent cache should not error: %v", err)
	}

	// ClearBySHA256 with non-existent hash should not error
	err = mgr.ClearBySHA256("0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Errorf("ClearBySHA256() on non-existent hash should not error: %v", err)
	}
}
