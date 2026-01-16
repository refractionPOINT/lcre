package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/maxime/lcre/internal/model"
)

const (
	// CacheDir is the default cache directory name
	CacheDir = "lcre"

	// DBFile is the SQLite database filename
	DBFile = "analysis.db"

	// MetadataFile is the quick-load metadata filename
	MetadataFile = "metadata.json"

	// DecompiledDir is the directory for decompiled function files
	DecompiledDir = "decompiled"
)

// CacheEntry represents a cached analysis.
type CacheEntry struct {
	Path       string    `json:"path"`
	SHA256     string    `json:"sha256"`
	CacheDir   string    `json:"cache_dir"`
	CreatedAt  time.Time `json:"created_at"`
	DeepAnalysis bool    `json:"deep_analysis"`
}

// CachedMetadata stores quick-access binary metadata.
type CachedMetadata struct {
	Entry       CacheEntry          `json:"entry"`
	Binary      model.BinaryMetadata `json:"binary"`
	Backend     string              `json:"backend"`
	AnalysisTime float64            `json:"analysis_time_secs"`
	DeepAnalysis bool               `json:"deep_analysis"`
	StringCount int                 `json:"string_count"`
	FunctionCount int               `json:"function_count"`
	ImportCount int                 `json:"import_count"`
	ExportCount int                 `json:"export_count"`
	HeuristicCount int              `json:"heuristic_count"`
	RiskLevel   string              `json:"risk_level"`
	TotalScore  int                 `json:"total_score"`
}

// Manager handles cache directory operations.
type Manager struct {
	baseDir string
}

// NewManager creates a new cache manager.
func NewManager() (*Manager, error) {
	cacheBase, err := os.UserCacheDir()
	if err != nil {
		// Fallback to home directory
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("get user cache dir: %w", err)
		}
		cacheBase = filepath.Join(home, ".cache")
	}

	baseDir := filepath.Join(cacheBase, CacheDir)
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("create cache directory: %w", err)
	}

	return &Manager{baseDir: baseDir}, nil
}

// NewManagerWithPath creates a cache manager with a custom base directory.
func NewManagerWithPath(baseDir string) (*Manager, error) {
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("create cache directory: %w", err)
	}
	return &Manager{baseDir: baseDir}, nil
}

// GetCacheDir returns the cache directory for a binary.
func (m *Manager) GetCacheDir(binaryPath string) (string, error) {
	hash, err := m.hashFile(binaryPath)
	if err != nil {
		return "", err
	}
	return filepath.Join(m.baseDir, hash), nil
}

// Exists checks if a cache exists for the given binary.
func (m *Manager) Exists(binaryPath string) (bool, error) {
	cacheDir, err := m.GetCacheDir(binaryPath)
	if err != nil {
		return false, err
	}

	dbPath := filepath.Join(cacheDir, DBFile)
	_, err = os.Stat(dbPath)
	return err == nil, nil
}

// HasDeepAnalysis checks if deep analysis is cached.
func (m *Manager) HasDeepAnalysis(binaryPath string) (bool, error) {
	meta, err := m.LoadMetadata(binaryPath)
	if err != nil {
		return false, nil
	}
	return meta.DeepAnalysis, nil
}

// Create creates a new cache directory for a binary and returns the DB.
func (m *Manager) Create(binaryPath string) (*DB, string, error) {
	hash, err := m.hashFile(binaryPath)
	if err != nil {
		return nil, "", err
	}

	cacheDir := filepath.Join(m.baseDir, hash)
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, "", fmt.Errorf("create cache directory: %w", err)
	}

	// Create decompiled directory
	decompiledDir := filepath.Join(cacheDir, DecompiledDir)
	if err := os.MkdirAll(decompiledDir, 0755); err != nil {
		return nil, "", fmt.Errorf("create decompiled directory: %w", err)
	}

	dbPath := filepath.Join(cacheDir, DBFile)
	db, err := OpenDB(dbPath)
	if err != nil {
		return nil, "", err
	}

	return db, cacheDir, nil
}

// Open opens an existing cache for a binary.
func (m *Manager) Open(binaryPath string) (*DB, error) {
	cacheDir, err := m.GetCacheDir(binaryPath)
	if err != nil {
		return nil, err
	}

	dbPath := filepath.Join(cacheDir, DBFile)
	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf("cache not found for %s", binaryPath)
	}

	return OpenDB(dbPath)
}

// OpenOrCreate opens an existing cache or creates a new one.
func (m *Manager) OpenOrCreate(binaryPath string) (*DB, string, bool, error) {
	exists, err := m.Exists(binaryPath)
	if err != nil {
		return nil, "", false, err
	}

	if exists {
		cacheDir, err := m.GetCacheDir(binaryPath)
		if err != nil {
			return nil, "", false, err
		}
		db, err := m.Open(binaryPath)
		if err != nil {
			return nil, "", false, err
		}
		return db, cacheDir, false, nil
	}

	db, cacheDir, err := m.Create(binaryPath)
	return db, cacheDir, true, err
}

// SaveMetadata saves quick-access metadata.
func (m *Manager) SaveMetadata(binaryPath string, meta *CachedMetadata) error {
	cacheDir, err := m.GetCacheDir(binaryPath)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(cacheDir, MetadataFile), data, 0644)
}

// LoadMetadata loads quick-access metadata.
func (m *Manager) LoadMetadata(binaryPath string) (*CachedMetadata, error) {
	cacheDir, err := m.GetCacheDir(binaryPath)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(filepath.Join(cacheDir, MetadataFile))
	if err != nil {
		return nil, err
	}

	var meta CachedMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}

	return &meta, nil
}

// SaveDecompiledFunction saves a decompiled function to the cache.
func (m *Manager) SaveDecompiledFunction(binaryPath, funcName, code string) error {
	cacheDir, err := m.GetCacheDir(binaryPath)
	if err != nil {
		return err
	}

	decompiledDir := filepath.Join(cacheDir, DecompiledDir)
	if err := os.MkdirAll(decompiledDir, 0755); err != nil {
		return err
	}

	// Sanitize function name for filename
	safeName := sanitizeFuncName(funcName)
	filePath := filepath.Join(decompiledDir, safeName+".c")

	return os.WriteFile(filePath, []byte(code), 0644)
}

// LoadDecompiledFunction loads a decompiled function from the cache.
func (m *Manager) LoadDecompiledFunction(binaryPath, funcName string) (string, error) {
	cacheDir, err := m.GetCacheDir(binaryPath)
	if err != nil {
		return "", err
	}

	safeName := sanitizeFuncName(funcName)
	filePath := filepath.Join(cacheDir, DecompiledDir, safeName+".c")

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}

	return string(data), nil
}

// Clear removes the cache for a specific binary.
func (m *Manager) Clear(binaryPath string) error {
	cacheDir, err := m.GetCacheDir(binaryPath)
	if err != nil {
		return err
	}

	return os.RemoveAll(cacheDir)
}

// ClearAll removes all cached analyses.
func (m *Manager) ClearAll() error {
	entries, err := os.ReadDir(m.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			if err := os.RemoveAll(filepath.Join(m.baseDir, entry.Name())); err != nil {
				return err
			}
		}
	}

	return nil
}

// ListCacheEntry represents an entry in the cache list.
type ListCacheEntry struct {
	SHA256    string    `json:"sha256"`
	Path      string    `json:"path,omitempty"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
	DeepAnalysis bool   `json:"deep_analysis"`
}

// List returns all cached analyses.
func (m *Manager) List() ([]ListCacheEntry, error) {
	entries, err := os.ReadDir(m.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var results []ListCacheEntry
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		cacheDir := filepath.Join(m.baseDir, entry.Name())
		metaPath := filepath.Join(cacheDir, MetadataFile)

		var listEntry ListCacheEntry
		listEntry.SHA256 = entry.Name()

		// Try to load metadata
		if data, err := os.ReadFile(metaPath); err == nil {
			var meta CachedMetadata
			if json.Unmarshal(data, &meta) == nil {
				listEntry.Path = meta.Entry.Path
				listEntry.CreatedAt = meta.Entry.CreatedAt
				listEntry.DeepAnalysis = meta.DeepAnalysis
			}
		}

		// Get directory size
		listEntry.Size = getDirSize(cacheDir)

		results = append(results, listEntry)
	}

	return results, nil
}

// ClearBySHA256 removes the cache for a specific SHA256 hash.
func (m *Manager) ClearBySHA256(hash string) error {
	cacheDir := filepath.Join(m.baseDir, hash)
	return os.RemoveAll(cacheDir)
}

// hashFile computes the SHA256 hash of a file.
func (m *Manager) hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash file: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// GetHash returns the SHA256 hash of a file.
func (m *Manager) GetHash(path string) (string, error) {
	return m.hashFile(path)
}

// sanitizeFuncName converts a function name to a safe filename.
func sanitizeFuncName(name string) string {
	// Replace problematic characters
	replacer := strings.NewReplacer(
		"<", "_lt_",
		">", "_gt_",
		":", "_",
		"/", "_",
		"\\", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"|", "_",
		" ", "_",
	)
	return replacer.Replace(name)
}

// getDirSize calculates the total size of a directory.
func getDirSize(path string) int64 {
	var size int64
	filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size
}

// ErrNotCached is returned when a cache entry doesn't exist.
var ErrNotCached = errors.New("binary not cached")
