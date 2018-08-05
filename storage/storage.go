// Package storage is inspired by the package physical from Hashicorp Vault:
// https://github.com/hashicorp/vault/blob/master/physical/
package storage

//go:generate mockgen -destination=./mock/backend.go -package=mock -mock_names=Backend=Backend github.com/johandroz/srp/storage Backend

import "context"

// Backend is the interface required for a physical
// backend.
type Backend interface {
	// Storage is the interface for the storage.
	// Put is used to insert or update an entry
	Put(ctx context.Context, key string, m map[string]interface{}) error

	// Get is used to fetch an entry
	Get(ctx context.Context, key string) (map[string]interface{}, error)

	// Delete is used to permanently delete an entry
	Delete(ctx context.Context, key string) error
}
