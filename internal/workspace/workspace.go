package workspace

import (
	"fmt"
	"os"
	"path/filepath"
)

// Workspace manages temporary directories for analysis
type Workspace struct {
	BasePath string
	paths    []string
}

// New creates a new workspace in a temp directory
func New(prefix string) (*Workspace, error) {
	basePath, err := os.MkdirTemp("", prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to create workspace: %w", err)
	}
	return &Workspace{
		BasePath: basePath,
		paths:    []string{basePath},
	}, nil
}

// NewWithPath creates a workspace at a specific path
func NewWithPath(path string) (*Workspace, error) {
	if err := os.MkdirAll(path, 0755); err != nil {
		return nil, fmt.Errorf("failed to create workspace at %s: %w", path, err)
	}
	return &Workspace{
		BasePath: path,
		paths:    []string{path},
	}, nil
}

// SubDir creates a subdirectory in the workspace
func (w *Workspace) SubDir(name string) (string, error) {
	path := filepath.Join(w.BasePath, name)
	if err := os.MkdirAll(path, 0755); err != nil {
		return "", fmt.Errorf("failed to create subdir %s: %w", name, err)
	}
	w.paths = append(w.paths, path)
	return path, nil
}

// TempFile creates a temporary file in the workspace
func (w *Workspace) TempFile(pattern string) (*os.File, error) {
	return os.CreateTemp(w.BasePath, pattern)
}

// Path returns the full path for a file in the workspace
func (w *Workspace) Path(name string) string {
	return filepath.Join(w.BasePath, name)
}

// Cleanup removes the workspace and all its contents
func (w *Workspace) Cleanup() error {
	return os.RemoveAll(w.BasePath)
}

// Exists checks if a file exists in the workspace
func (w *Workspace) Exists(name string) bool {
	_, err := os.Stat(w.Path(name))
	return err == nil
}

// ReadFile reads a file from the workspace
func (w *Workspace) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(w.Path(name))
}

// WriteFile writes data to a file in the workspace
func (w *Workspace) WriteFile(name string, data []byte) error {
	return os.WriteFile(w.Path(name), data, 0644)
}
