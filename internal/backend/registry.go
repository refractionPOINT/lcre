package backend

import (
	"fmt"
	"sync"
)

// Registry manages available backends
type Registry struct {
	mu       sync.RWMutex
	backends map[string]Backend
}

// NewRegistry creates a new backend registry
func NewRegistry() *Registry {
	return &Registry{
		backends: make(map[string]Backend),
	}
}

// Register adds a backend to the registry
func (r *Registry) Register(b Backend) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.backends[b.Name()] = b
}

// Get returns a backend by name
func (r *Registry) Get(name string) (Backend, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := r.backends[name]
	if !ok {
		return nil, fmt.Errorf("backend not found: %s", name)
	}
	return b, nil
}

// List returns all registered backend names
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.backends))
	for name := range r.backends {
		names = append(names, name)
	}
	return names
}

// Available returns all available backends
func (r *Registry) Available() []Backend {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var available []Backend
	for _, b := range r.backends {
		if ok, _ := b.Available(); ok {
			available = append(available, b)
		}
	}
	return available
}

// Default returns the default backend (native if available)
func (r *Registry) Default() (Backend, error) {
	// Prefer native backend
	if b, err := r.Get("native"); err == nil {
		if ok, _ := b.Available(); ok {
			return b, nil
		}
	}

	// Fall back to any available backend
	available := r.Available()
	if len(available) > 0 {
		return available[0], nil
	}

	return nil, fmt.Errorf("no backends available")
}

// DefaultRegistry is the global registry
var DefaultRegistry = NewRegistry()
