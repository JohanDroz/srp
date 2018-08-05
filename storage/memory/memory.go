package memory

import (
	"context"
	"fmt"

	"github.com/johandroz/srp/storage"
)

// Verify Storage satisfies the correct interface
var _ storage.Backend = (*MemoryBackend)(nil)

// MemoryBackend is a physical storage that stores data
// in memory
type MemoryBackend struct {
	m map[string]map[string]interface{}
}

// NewMemoryBackend constructs an in memory Storage.
func NewMemoryBackend() (*MemoryBackend, error) {
	return &MemoryBackend{
		m: map[string]map[string]interface{}{},
	}, nil
}

// Put is used to insert or update an entry.
func (s *MemoryBackend) Put(ctx context.Context, key string, val map[string]interface{}) error {
	s.m[key] = val
	return nil
}

// Get is used to fetch and entry.
func (s *MemoryBackend) Get(ctx context.Context, key string) (map[string]interface{}, error) {
	var val, ok = s.m[key]
	if !ok {
		return nil, fmt.Errorf("key not found")
	}
	return val, nil
}

// Delete is used to permanently delete an entry
func (s *MemoryBackend) Delete(ctx context.Context, key string) error {
	delete(s.m, key)
	return nil
}
