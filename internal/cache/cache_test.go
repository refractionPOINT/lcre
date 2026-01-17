package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/maxime/lcre/internal/model"
)

func TestNewManagerWithPath(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) string
		wantErr bool
	}{
		{
			name: "creates directory if not exists",
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "new_cache_dir")
			},
			wantErr: false,
		},
		{
			name: "uses existing directory",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				return dir
			},
			wantErr: false,
		},
		{
			name: "creates nested directories",
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "deeply", "nested", "cache")
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseDir := tt.setup(t)
			mgr, err := NewManagerWithPath(baseDir)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewManagerWithPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if mgr == nil {
					t.Error("NewManagerWithPath() returned nil manager")
				}
				if _, err := os.Stat(baseDir); os.IsNotExist(err) {
					t.Errorf("NewManagerWithPath() did not create directory %s", baseDir)
				}
			}
		})
	}
}

func TestManager_GetCacheDir(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewManagerWithPath(tempDir)
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	// Create a test binary file
	binaryPath := filepath.Join(tempDir, "test_binary")
	if err := os.WriteFile(binaryPath, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}

	// Get cache dir for the binary
	cacheDir1, err := mgr.GetCacheDir(binaryPath)
	if err != nil {
		t.Errorf("GetCacheDir() error = %v", err)
	}

	// Should return consistent hash-based path
	cacheDir2, err := mgr.GetCacheDir(binaryPath)
	if err != nil {
		t.Errorf("GetCacheDir() error = %v", err)
	}

	if cacheDir1 != cacheDir2 {
		t.Errorf("GetCacheDir() returned inconsistent paths: %s vs %s", cacheDir1, cacheDir2)
	}

	// Verify path structure
	if filepath.Dir(cacheDir1) != tempDir {
		t.Errorf("GetCacheDir() parent should be base dir, got %s", filepath.Dir(cacheDir1))
	}

	// Hash should be 64 characters (SHA256 hex)
	hashName := filepath.Base(cacheDir1)
	if len(hashName) != 64 {
		t.Errorf("GetCacheDir() hash length = %d, want 64", len(hashName))
	}
}

func TestManager_GetCacheDir_NonExistentFile(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewManagerWithPath(tempDir)
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	_, err = mgr.GetCacheDir(filepath.Join(tempDir, "nonexistent"))
	if err == nil {
		t.Error("GetCacheDir() expected error for non-existent file")
	}
}

func TestManager_Exists(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewManagerWithPath(tempDir)
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	// Create a test binary
	binaryPath := filepath.Join(tempDir, "test_binary")
	if err := os.WriteFile(binaryPath, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}

	// Should not exist initially
	exists, err := mgr.Exists(binaryPath)
	if err != nil {
		t.Errorf("Exists() error = %v", err)
	}
	if exists {
		t.Error("Exists() = true, want false for uncached binary")
	}

	// Create the cache
	db, _, err := mgr.Create(binaryPath)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	db.Close()

	// Should exist now
	exists, err = mgr.Exists(binaryPath)
	if err != nil {
		t.Errorf("Exists() error = %v", err)
	}
	if !exists {
		t.Error("Exists() = false, want true for cached binary")
	}
}

func TestManager_HasDeepAnalysis(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewManagerWithPath(tempDir)
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	// Create a test binary
	binaryPath := filepath.Join(tempDir, "test_binary")
	if err := os.WriteFile(binaryPath, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}

	// Should return false for uncached binary
	hasDeep, err := mgr.HasDeepAnalysis(binaryPath)
	if err != nil {
		t.Errorf("HasDeepAnalysis() error = %v", err)
	}
	if hasDeep {
		t.Error("HasDeepAnalysis() = true, want false for uncached binary")
	}

	// Create cache with shallow analysis metadata
	db, _, err := mgr.Create(binaryPath)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	db.Close()

	meta := &CachedMetadata{
		DeepAnalysis: false,
	}
	if err := mgr.SaveMetadata(binaryPath, meta); err != nil {
		t.Fatalf("SaveMetadata() error = %v", err)
	}

	hasDeep, err = mgr.HasDeepAnalysis(binaryPath)
	if err != nil {
		t.Errorf("HasDeepAnalysis() error = %v", err)
	}
	if hasDeep {
		t.Error("HasDeepAnalysis() = true, want false for shallow analysis")
	}

	// Update to deep analysis
	meta.DeepAnalysis = true
	if err := mgr.SaveMetadata(binaryPath, meta); err != nil {
		t.Fatalf("SaveMetadata() error = %v", err)
	}

	hasDeep, err = mgr.HasDeepAnalysis(binaryPath)
	if err != nil {
		t.Errorf("HasDeepAnalysis() error = %v", err)
	}
	if !hasDeep {
		t.Error("HasDeepAnalysis() = false, want true for deep analysis")
	}
}

func TestManager_Create(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewManagerWithPath(tempDir)
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	// Create a test binary
	binaryPath := filepath.Join(tempDir, "test_binary")
	if err := os.WriteFile(binaryPath, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}

	db, cacheDir, err := mgr.Create(binaryPath)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	defer db.Close()

	// Verify cache directory was created
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		t.Errorf("Create() did not create cache directory %s", cacheDir)
	}

	// Verify decompiled directory was created
	decompiledDir := filepath.Join(cacheDir, DecompiledDir)
	if _, err := os.Stat(decompiledDir); os.IsNotExist(err) {
		t.Errorf("Create() did not create decompiled directory %s", decompiledDir)
	}

	// Verify database file was created
	dbPath := filepath.Join(cacheDir, DBFile)
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Errorf("Create() did not create database file %s", dbPath)
	}

	// Verify DB is usable
	if err := db.SetMetadata("test", "value"); err != nil {
		t.Errorf("Database not usable: %v", err)
	}
}

func TestManager_Open(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewManagerWithPath(tempDir)
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	// Create a test binary
	binaryPath := filepath.Join(tempDir, "test_binary")
	if err := os.WriteFile(binaryPath, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}

	// Should fail on non-existent cache
	_, err = mgr.Open(binaryPath)
	if err == nil {
		t.Error("Open() expected error for non-existent cache")
	}

	// Create cache first
	db1, _, err := mgr.Create(binaryPath)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := db1.SetMetadata("test_key", "test_value"); err != nil {
		t.Fatalf("SetMetadata() error = %v", err)
	}
	db1.Close()

	// Should now open successfully
	db2, err := mgr.Open(binaryPath)
	if err != nil {
		t.Errorf("Open() error = %v", err)
	}
	defer db2.Close()

	// Verify data persisted
	val, err := db2.GetMetadata("test_key")
	if err != nil {
		t.Errorf("GetMetadata() error = %v", err)
	}
	if val != "test_value" {
		t.Errorf("GetMetadata() = %q, want %q", val, "test_value")
	}
}

func TestManager_OpenOrCreate(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewManagerWithPath(tempDir)
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	// Create a test binary
	binaryPath := filepath.Join(tempDir, "test_binary")
	if err := os.WriteFile(binaryPath, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}

	// First call should create
	db1, cacheDir1, created, err := mgr.OpenOrCreate(binaryPath)
	if err != nil {
		t.Fatalf("OpenOrCreate() error = %v", err)
	}
	if !created {
		t.Error("OpenOrCreate() created = false, want true for new cache")
	}
	db1.Close()

	// Second call should open existing
	db2, cacheDir2, created, err := mgr.OpenOrCreate(binaryPath)
	if err != nil {
		t.Fatalf("OpenOrCreate() error = %v", err)
	}
	if created {
		t.Error("OpenOrCreate() created = true, want false for existing cache")
	}
	if cacheDir1 != cacheDir2 {
		t.Errorf("OpenOrCreate() cache dirs differ: %s vs %s", cacheDir1, cacheDir2)
	}
	db2.Close()
}

func TestManager_SaveAndLoadMetadata(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewManagerWithPath(tempDir)
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	// Create a test binary
	binaryPath := filepath.Join(tempDir, "test_binary")
	if err := os.WriteFile(binaryPath, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}

	// Create cache first
	db, _, err := mgr.Create(binaryPath)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	db.Close()

	// Create metadata
	now := time.Now().Truncate(time.Second)
	meta := &CachedMetadata{
		Entry: CacheEntry{
			Path:         binaryPath,
			SHA256:       "abc123",
			CreatedAt:    now,
			DeepAnalysis: true,
		},
		Binary: model.BinaryMetadata{
			Name:   "test_binary",
			Size:   12,
			Format: model.FormatELF,
			Arch:   "x86_64",
			Bits:   64,
		},
		Backend:        "native",
		AnalysisTime:   1.5,
		DeepAnalysis:   true,
		StringCount:    100,
		FunctionCount:  50,
		ImportCount:    20,
		ExportCount:    10,
		HeuristicCount: 5,
		RiskLevel:      "low",
		TotalScore:     15,
	}

	// Save
	if err := mgr.SaveMetadata(binaryPath, meta); err != nil {
		t.Fatalf("SaveMetadata() error = %v", err)
	}

	// Load
	loaded, err := mgr.LoadMetadata(binaryPath)
	if err != nil {
		t.Fatalf("LoadMetadata() error = %v", err)
	}

	// Verify fields
	if loaded.Entry.Path != meta.Entry.Path {
		t.Errorf("Path = %q, want %q", loaded.Entry.Path, meta.Entry.Path)
	}
	if loaded.Entry.SHA256 != meta.Entry.SHA256 {
		t.Errorf("SHA256 = %q, want %q", loaded.Entry.SHA256, meta.Entry.SHA256)
	}
	if loaded.DeepAnalysis != meta.DeepAnalysis {
		t.Errorf("DeepAnalysis = %v, want %v", loaded.DeepAnalysis, meta.DeepAnalysis)
	}
	if loaded.StringCount != meta.StringCount {
		t.Errorf("StringCount = %d, want %d", loaded.StringCount, meta.StringCount)
	}
	if loaded.FunctionCount != meta.FunctionCount {
		t.Errorf("FunctionCount = %d, want %d", loaded.FunctionCount, meta.FunctionCount)
	}
	if loaded.Binary.Name != meta.Binary.Name {
		t.Errorf("Binary.Name = %q, want %q", loaded.Binary.Name, meta.Binary.Name)
	}
	if loaded.Binary.Format != meta.Binary.Format {
		t.Errorf("Binary.Format = %v, want %v", loaded.Binary.Format, meta.Binary.Format)
	}
}

func TestManager_SaveAndLoadDecompiledFunction(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewManagerWithPath(tempDir)
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	// Create a test binary
	binaryPath := filepath.Join(tempDir, "test_binary")
	if err := os.WriteFile(binaryPath, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}

	// Create cache first
	db, _, err := mgr.Create(binaryPath)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	db.Close()

	tests := []struct {
		name     string
		funcName string
		code     string
	}{
		{
			name:     "simple function",
			funcName: "main",
			code:     "int main() { return 0; }",
		},
		{
			name:     "function with special characters",
			funcName: "operator<",
			code:     "bool operator<(int a, int b) { return a < b; }",
		},
		{
			name:     "namespaced function",
			funcName: "std::vector::push_back",
			code:     "void push_back(T&& value);",
		},
		{
			name:     "multiline code",
			funcName: "complex",
			code:     "int complex() {\n    int x = 1;\n    return x;\n}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save
			if err := mgr.SaveDecompiledFunction(binaryPath, tt.funcName, tt.code); err != nil {
				t.Fatalf("SaveDecompiledFunction() error = %v", err)
			}

			// Load
			loaded, err := mgr.LoadDecompiledFunction(binaryPath, tt.funcName)
			if err != nil {
				t.Fatalf("LoadDecompiledFunction() error = %v", err)
			}

			if loaded != tt.code {
				t.Errorf("LoadDecompiledFunction() = %q, want %q", loaded, tt.code)
			}
		})
	}
}

func TestManager_LoadDecompiledFunction_NotFound(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewManagerWithPath(tempDir)
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	// Create a test binary
	binaryPath := filepath.Join(tempDir, "test_binary")
	if err := os.WriteFile(binaryPath, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}

	// Create cache
	db, _, err := mgr.Create(binaryPath)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	db.Close()

	// Load non-existent function
	code, err := mgr.LoadDecompiledFunction(binaryPath, "nonexistent")
	if err != nil {
		t.Errorf("LoadDecompiledFunction() error = %v, want nil", err)
	}
	if code != "" {
		t.Errorf("LoadDecompiledFunction() = %q, want empty string", code)
	}
}

func TestManager_Clear(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewManagerWithPath(tempDir)
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	// Create a test binary
	binaryPath := filepath.Join(tempDir, "test_binary")
	if err := os.WriteFile(binaryPath, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}

	// Create cache
	db, cacheDir, err := mgr.Create(binaryPath)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	db.Close()

	// Verify cache exists
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		t.Fatal("Cache directory not created")
	}

	// Clear
	if err := mgr.Clear(binaryPath); err != nil {
		t.Fatalf("Clear() error = %v", err)
	}

	// Verify cache removed
	if _, err := os.Stat(cacheDir); !os.IsNotExist(err) {
		t.Error("Clear() did not remove cache directory")
	}
}

func TestManager_ClearAll(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewManagerWithPath(tempDir)
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	// Create multiple test binaries
	for i := 0; i < 3; i++ {
		binaryPath := filepath.Join(tempDir, "test_binary_"+string(rune('a'+i)))
		if err := os.WriteFile(binaryPath, []byte("test content "+string(rune('a'+i))), 0644); err != nil {
			t.Fatalf("Failed to create test binary: %v", err)
		}

		db, _, err := mgr.Create(binaryPath)
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		db.Close()
	}

	// Verify caches exist
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	// Count only hash directories (64 chars)
	cacheCount := 0
	for _, e := range entries {
		if e.IsDir() && len(e.Name()) == 64 {
			cacheCount++
		}
	}
	if cacheCount != 3 {
		t.Errorf("Expected 3 cache directories, got %d", cacheCount)
	}

	// Clear all
	if err := mgr.ClearAll(); err != nil {
		t.Fatalf("ClearAll() error = %v", err)
	}

	// Verify all caches removed
	entries, err = os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	cacheCount = 0
	for _, e := range entries {
		if e.IsDir() && len(e.Name()) == 64 {
			cacheCount++
		}
	}
	if cacheCount != 0 {
		t.Errorf("ClearAll() left %d cache directories", cacheCount)
	}
}

func TestManager_List(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewManagerWithPath(tempDir)
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	// Empty list initially
	entries, err := mgr.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("List() returned %d entries, want 0", len(entries))
	}

	// Create caches with metadata
	for i := 0; i < 2; i++ {
		binaryPath := filepath.Join(tempDir, "test_binary_"+string(rune('a'+i)))
		content := []byte("test content " + string(rune('a'+i)))
		if err := os.WriteFile(binaryPath, content, 0644); err != nil {
			t.Fatalf("Failed to create test binary: %v", err)
		}

		db, _, err := mgr.Create(binaryPath)
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		db.Close()

		meta := &CachedMetadata{
			Entry: CacheEntry{
				Path:         binaryPath,
				CreatedAt:    time.Now(),
				DeepAnalysis: i == 1, // Second one has deep analysis
			},
			DeepAnalysis: i == 1,
		}
		if err := mgr.SaveMetadata(binaryPath, meta); err != nil {
			t.Fatalf("SaveMetadata() error = %v", err)
		}
	}

	// List again
	entries, err = mgr.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("List() returned %d entries, want 2", len(entries))
	}

	// Verify entries have data
	for _, e := range entries {
		if len(e.SHA256) != 64 {
			t.Errorf("List() entry has invalid SHA256 length: %d", len(e.SHA256))
		}
		if e.Size <= 0 {
			t.Errorf("List() entry has invalid size: %d", e.Size)
		}
	}
}

func TestManager_ClearBySHA256(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewManagerWithPath(tempDir)
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	// Create a test binary
	binaryPath := filepath.Join(tempDir, "test_binary")
	if err := os.WriteFile(binaryPath, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}

	// Get hash
	hash, err := mgr.GetHash(binaryPath)
	if err != nil {
		t.Fatalf("GetHash() error = %v", err)
	}

	// Create cache
	db, _, err := mgr.Create(binaryPath)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	db.Close()

	// Verify exists
	exists, _ := mgr.Exists(binaryPath)
	if !exists {
		t.Fatal("Cache not created")
	}

	// Clear by hash
	if err := mgr.ClearBySHA256(hash); err != nil {
		t.Fatalf("ClearBySHA256() error = %v", err)
	}

	// Verify removed
	exists, _ = mgr.Exists(binaryPath)
	if exists {
		t.Error("ClearBySHA256() did not remove cache")
	}
}

func TestManager_GetHash(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewManagerWithPath(tempDir)
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	// Create test files with known content
	tests := []struct {
		name    string
		content []byte
	}{
		{"empty file", []byte{}},
		{"simple content", []byte("hello world")},
		{"binary content", []byte{0x00, 0x01, 0x02, 0xFF}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := filepath.Join(tempDir, tt.name)
			if err := os.WriteFile(filePath, tt.content, 0644); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			hash1, err := mgr.GetHash(filePath)
			if err != nil {
				t.Errorf("GetHash() error = %v", err)
			}

			// Hash should be consistent
			hash2, err := mgr.GetHash(filePath)
			if err != nil {
				t.Errorf("GetHash() error = %v", err)
			}
			if hash1 != hash2 {
				t.Errorf("GetHash() inconsistent: %s vs %s", hash1, hash2)
			}

			// Hash should be 64 hex characters
			if len(hash1) != 64 {
				t.Errorf("GetHash() length = %d, want 64", len(hash1))
			}
		})
	}
}

func TestSanitizeFuncName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"main", "main"},
		{"operator<", "operator_lt_"},
		{"operator>", "operator_gt_"},
		{"std::vector", "std__vector"},
		{"func/name", "func_name"},
		{"func\\name", "func_name"},
		{"func*name", "func_name"},
		{"func?name", "func_name"},
		{"func\"name", "func_name"},
		{"func|name", "func_name"},
		{"func name", "func_name"},
		{"operator<=>", "operator_lt_=_gt_"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeFuncName(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeFuncName(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGetDirSize(t *testing.T) {
	tempDir := t.TempDir()

	// Create files with known sizes
	file1 := filepath.Join(tempDir, "file1.txt")
	file2 := filepath.Join(tempDir, "file2.txt")
	subDir := filepath.Join(tempDir, "subdir")
	file3 := filepath.Join(subDir, "file3.txt")

	os.WriteFile(file1, make([]byte, 100), 0644)
	os.WriteFile(file2, make([]byte, 200), 0644)
	os.MkdirAll(subDir, 0755)
	os.WriteFile(file3, make([]byte, 300), 0644)

	size := getDirSize(tempDir)
	if size != 600 {
		t.Errorf("getDirSize() = %d, want 600", size)
	}
}

func TestGetDirSize_EmptyDir(t *testing.T) {
	tempDir := t.TempDir()
	size := getDirSize(tempDir)
	if size != 0 {
		t.Errorf("getDirSize() = %d, want 0 for empty dir", size)
	}
}

func TestManager_ConcurrentAccess(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewManagerWithPath(tempDir)
	if err != nil {
		t.Fatalf("NewManagerWithPath() error = %v", err)
	}

	// Create a test binary
	binaryPath := filepath.Join(tempDir, "test_binary")
	if err := os.WriteFile(binaryPath, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}

	// Create cache
	db, _, err := mgr.Create(binaryPath)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	db.Close()

	// Concurrent reads
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()
			for j := 0; j < 10; j++ {
				_, err := mgr.Exists(binaryPath)
				if err != nil {
					t.Errorf("Concurrent Exists() error = %v", err)
				}
				_, err = mgr.HasDeepAnalysis(binaryPath)
				if err != nil {
					t.Errorf("Concurrent HasDeepAnalysis() error = %v", err)
				}
			}
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}
