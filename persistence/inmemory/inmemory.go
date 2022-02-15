package inmemory

import (
	"clouditor.io/clouditor/persistence"
	"clouditor.io/clouditor/persistence/gorm"
)

// NewStorage creates a new in-memory storage. For now this uses the gorm provider
// with the gorm.WithInMemory. In the future we want to supply our own independent
// implementation.
func NewStorage() (persistence.Storage, error) {
	return gorm.NewStorage(gorm.WithInMemory())
}