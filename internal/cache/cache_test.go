package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/refractionPOINT/lcre/internal/model"
)

func TestNewManagerWithPath(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) string
		wantErr bool
	}{
		{
			name: "valid directory",
			setup: func(t *testing.T) string {
				return t.TempDir()
			},
			wantErr: false,
		},
		{
			name: "nested directory creation",
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "nested", "path")
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
			if !tt.wantErr && mgr == nil {
				t.Error("NewManagerWithPath() returned nil manager")
			}
		})
	}
}

func TestManagerGetCacheDir(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := NewManagerWithPath(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	testFile := filepath.Join(tmpDir, "testbinary")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	dir1, err := mgr.GetCacheDir(testFile)
	if err != nil {
		t.Fatalf("GetCacheDir() error = %v", err)
	}

	dir2, err := mgr.GetCacheDir(testFile)
	if err != nil {
		t.Fatalf("GetCacheDir() second call error = %v", err)
	}

	if dir1 != dir2 {
		t.Errorf("GetCacheDir() not consistent: %s != %s", dir1, dir2)
	}

	hash, _ := mgr.GetHash(testFile)
	expectedDir := filepath.Join(tmpDir, hash)
	if dir1 != expectedDir {
		t.Errorf("GetCacheDir() = %s, want %s", dir1, expectedDir)
	}
}

func TestManagerExists(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, _ := NewManagerWithPath(tmpDir)

	testFile := filepath.Join(tmpDir, "testbinary")
	os.WriteFile(testFile, []byte("test"), 0644)

	exists, err := mgr.Exists(testFile)
	if err != nil {
		t.Fatalf("Exists() error = %v", err)
	}
	if exists {
		t.Error("Exists() = true for uncached binary")
	}

	db, _, err := mgr.Create(testFile)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	db.Close()

	exists, err = mgr.Exists(testFile)
	if err != nil {
		t.Fatalf("Exists() after create error = %v", err)
	}
	if !exists {
		t.Error("Exists() = false after Create()")
	}
}

func TestManagerCreateAndOpen(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, _ := NewManagerWithPath(tmpDir)

	testFile := filepath.Join(tmpDir, "testbinary")
	os.WriteFile(testFile, []byte("binary content"), 0644)

	db, cacheDir, err := mgr.Create(testFile)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if db == nil {
		t.Fatal("Create() returned nil db")
	}
	if cacheDir == "" {
		t.Fatal("Create() returned empty cacheDir")
	}
	db.Close()

	if _, err := os.Stat(filepath.Join(cacheDir, DBFile)); os.IsNotExist(err) {
		t.Error("Create() did not create database file")
	}
	if _, err := os.Stat(filepath.Join(cacheDir, DecompiledDir)); os.IsNotExist(err) {
		t.Error("Create() did not create decompiled directory")
	}

	db2, err := mgr.Open(testFile)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if db2 == nil {
		t.Fatal("Open() returned nil db")
	}
	db2.Close()
}

func TestManagerOpenNonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, _ := NewManagerWithPath(tmpDir)

	testFile := filepath.Join(tmpDir, "nonexistent")
	os.WriteFile(testFile, []byte("test"), 0644)

	_, err := mgr.Open(testFile)
	if err == nil {
		t.Error("Open() should fail for non-existent cache")
	}
}

func TestManagerOpenOrCreate(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, _ := NewManagerWithPath(tmpDir)

	testFile := filepath.Join(tmpDir, "testbinary")
	os.WriteFile(testFile, []byte("content"), 0644)

	db1, _, created1, err := mgr.OpenOrCreate(testFile)
	if err != nil {
		t.Fatalf("OpenOrCreate() first call error = %v", err)
	}
	if !created1 {
		t.Error("OpenOrCreate() first call should return created=true")
	}
	db1.Close()

	db2, _, created2, err := mgr.OpenOrCreate(testFile)
	if err != nil {
		t.Fatalf("OpenOrCreate() second call error = %v", err)
	}
	if created2 {
		t.Error("OpenOrCreate() second call should return created=false")
	}
	db2.Close()
}

func TestManagerMetadata(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, _ := NewManagerWithPath(tmpDir)

	testFile := filepath.Join(tmpDir, "testbinary")
	os.WriteFile(testFile, []byte("content"), 0644)

	db, cacheDir, _ := mgr.Create(testFile)
	db.Close()

	hash, _ := mgr.GetHash(testFile)

	meta := &CachedMetadata{
		Entry: CacheEntry{
			Path:         testFile,
			SHA256:       hash,
			CacheDir:     cacheDir,
			CreatedAt:    time.Now(),
			DeepAnalysis: true,
		},
		Binary: model.BinaryMetadata{
			Path:   testFile,
			Name:   "testbinary",
			Size:   7,
			Format: model.FormatELF,
			Arch:   "x86_64",
		},
		Backend:        "native",
		AnalysisTime:   1.5,
		DeepAnalysis:   true,
		StringCount:    100,
		FunctionCount:  50,
		ImportCount:    20,
		ExportCount:    5,
		YARAMatchCount: 2,
	}

	if err := mgr.SaveMetadata(testFile, meta); err != nil {
		t.Fatalf("SaveMetadata() error = %v", err)
	}

	loaded, err := mgr.LoadMetadata(testFile)
	if err != nil {
		t.Fatalf("LoadMetadata() error = %v", err)
	}

	if loaded.Binary.Name != meta.Binary.Name {
		t.Errorf("Binary.Name = %s, want %s", loaded.Binary.Name, meta.Binary.Name)
	}
	if loaded.StringCount != meta.StringCount {
		t.Errorf("StringCount = %d, want %d", loaded.StringCount, meta.StringCount)
	}
	if loaded.DeepAnalysis != meta.DeepAnalysis {
		t.Errorf("DeepAnalysis = %v, want %v", loaded.DeepAnalysis, meta.DeepAnalysis)
	}
}

func TestManagerDecompiledFunctions(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, _ := NewManagerWithPath(tmpDir)

	testFile := filepath.Join(tmpDir, "testbinary")
	os.WriteFile(testFile, []byte("content"), 0644)

	db, _, _ := mgr.Create(testFile)
	db.Close()

	funcName := "test_function"
	code := "void test_function() {\n  return;\n}"

	if err := mgr.SaveDecompiledFunction(testFile, funcName, code); err != nil {
		t.Fatalf("SaveDecompiledFunction() error = %v", err)
	}

	loaded, err := mgr.LoadDecompiledFunction(testFile, funcName)
	if err != nil {
		t.Fatalf("LoadDecompiledFunction() error = %v", err)
	}
	if loaded != code {
		t.Errorf("LoadDecompiledFunction() = %q, want %q", loaded, code)
	}

	missing, err := mgr.LoadDecompiledFunction(testFile, "nonexistent")
	if err != nil {
		t.Fatalf("LoadDecompiledFunction() for missing func error = %v", err)
	}
	if missing != "" {
		t.Errorf("LoadDecompiledFunction() for missing = %q, want empty", missing)
	}
}

func TestManagerDecompiledFunctionSpecialChars(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, _ := NewManagerWithPath(tmpDir)

	testFile := filepath.Join(tmpDir, "testbinary")
	os.WriteFile(testFile, []byte("content"), 0644)

	db, _, _ := mgr.Create(testFile)
	db.Close()

	tests := []struct {
		name string
		code string
	}{
		{"func<int>", "template code"},
		{"operator<<", "operator code"},
		{"std::vector", "vector code"},
		{"func:nested", "nested code"},
	}

	for _, tt := range tests {
		if err := mgr.SaveDecompiledFunction(testFile, tt.name, tt.code); err != nil {
			t.Errorf("SaveDecompiledFunction(%q) error = %v", tt.name, err)
			continue
		}

		loaded, err := mgr.LoadDecompiledFunction(testFile, tt.name)
		if err != nil {
			t.Errorf("LoadDecompiledFunction(%q) error = %v", tt.name, err)
			continue
		}
		if loaded != tt.code {
			t.Errorf("LoadDecompiledFunction(%q) = %q, want %q", tt.name, loaded, tt.code)
		}
	}
}

func TestManagerClear(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, _ := NewManagerWithPath(tmpDir)

	testFile := filepath.Join(tmpDir, "testbinary")
	os.WriteFile(testFile, []byte("content"), 0644)

	db, _, _ := mgr.Create(testFile)
	db.Close()

	exists, _ := mgr.Exists(testFile)
	if !exists {
		t.Fatal("Cache should exist after Create()")
	}

	if err := mgr.Clear(testFile); err != nil {
		t.Fatalf("Clear() error = %v", err)
	}

	exists, _ = mgr.Exists(testFile)
	if exists {
		t.Error("Cache should not exist after Clear()")
	}
}

func TestManagerClearAll(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, _ := NewManagerWithPath(tmpDir)

	for i := 0; i < 3; i++ {
		testFile := filepath.Join(tmpDir, "binary"+string(rune('a'+i)))
		os.WriteFile(testFile, []byte("content"+string(rune('a'+i))), 0644)
		db, _, _ := mgr.Create(testFile)
		db.Close()
	}

	entries, _ := mgr.List()
	if len(entries) != 3 {
		t.Fatalf("Expected 3 cache entries, got %d", len(entries))
	}

	if err := mgr.ClearAll(); err != nil {
		t.Fatalf("ClearAll() error = %v", err)
	}

	entries, _ = mgr.List()
	if len(entries) != 0 {
		t.Errorf("ClearAll() should remove all entries, got %d", len(entries))
	}
}

func TestManagerList(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, _ := NewManagerWithPath(tmpDir)

	entries, err := mgr.List()
	if err != nil {
		t.Fatalf("List() empty error = %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("List() empty = %d entries, want 0", len(entries))
	}

	testFile := filepath.Join(tmpDir, "testbinary")
	os.WriteFile(testFile, []byte("content"), 0644)
	db, cacheDir, _ := mgr.Create(testFile)
	db.Close()

	hash, _ := mgr.GetHash(testFile)
	meta := &CachedMetadata{
		Entry: CacheEntry{
			Path:      testFile,
			SHA256:    hash,
			CacheDir:  cacheDir,
			CreatedAt: time.Now(),
		},
		DeepAnalysis: true,
	}
	mgr.SaveMetadata(testFile, meta)

	entries, err = mgr.List()
	if err != nil {
		t.Fatalf("List() after create error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("List() = %d entries, want 1", len(entries))
	}

	if entries[0].SHA256 != hash {
		t.Errorf("Entry SHA256 = %s, want %s", entries[0].SHA256, hash)
	}
	if entries[0].Path != testFile {
		t.Errorf("Entry Path = %s, want %s", entries[0].Path, testFile)
	}
	if !entries[0].DeepAnalysis {
		t.Error("Entry DeepAnalysis = false, want true")
	}
}

func TestManagerClearBySHA256(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, _ := NewManagerWithPath(tmpDir)

	testFile := filepath.Join(tmpDir, "testbinary")
	os.WriteFile(testFile, []byte("content"), 0644)

	db, _, _ := mgr.Create(testFile)
	db.Close()

	hash, _ := mgr.GetHash(testFile)

	if err := mgr.ClearBySHA256(hash); err != nil {
		t.Fatalf("ClearBySHA256() error = %v", err)
	}

	exists, _ := mgr.Exists(testFile)
	if exists {
		t.Error("Cache should not exist after ClearBySHA256()")
	}
}

func TestManagerHasDeepAnalysis(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, _ := NewManagerWithPath(tmpDir)

	testFile := filepath.Join(tmpDir, "testbinary")
	os.WriteFile(testFile, []byte("content"), 0644)

	db, cacheDir, _ := mgr.Create(testFile)
	db.Close()

	hash, _ := mgr.GetHash(testFile)

	hasDeep, _ := mgr.HasDeepAnalysis(testFile)
	if hasDeep {
		t.Error("HasDeepAnalysis() = true before metadata saved")
	}

	meta := &CachedMetadata{
		Entry:        CacheEntry{SHA256: hash, CacheDir: cacheDir},
		DeepAnalysis: false,
	}
	mgr.SaveMetadata(testFile, meta)

	hasDeep, _ = mgr.HasDeepAnalysis(testFile)
	if hasDeep {
		t.Error("HasDeepAnalysis() = true when DeepAnalysis=false")
	}

	meta.DeepAnalysis = true
	mgr.SaveMetadata(testFile, meta)

	hasDeep, _ = mgr.HasDeepAnalysis(testFile)
	if !hasDeep {
		t.Error("HasDeepAnalysis() = false when DeepAnalysis=true")
	}
}

func TestGetHash(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, _ := NewManagerWithPath(tmpDir)

	testFile := filepath.Join(tmpDir, "testfile")
	os.WriteFile(testFile, []byte("hello world"), 0644)

	hash, err := mgr.GetHash(testFile)
	if err != nil {
		t.Fatalf("GetHash() error = %v", err)
	}

	expected := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if hash != expected {
		t.Errorf("GetHash() = %s, want %s", hash, expected)
	}

	hash2, _ := mgr.GetHash(testFile)
	if hash != hash2 {
		t.Error("GetHash() not consistent")
	}
}

func TestSanitizeFuncName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"func<int>", "func_lt_int_gt_"},
		{"operator<<", "operator_lt__lt_"},
		{"path/to/func", "path_to_func"},
		{"func:nested", "func_nested"},
		{"has spaces", "has_spaces"},
		{"file.ext", "file.ext"},
	}

	for _, tt := range tests {
		result := sanitizeFuncName(tt.input)
		if result != tt.expected {
			t.Errorf("sanitizeFuncName(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}
