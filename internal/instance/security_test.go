package instance

import (
	"io"
	"testing"

	"github.com/sandialabs/abox/internal/backend/mock"
)

func TestApplyFiltered_InstanceNotFound(t *testing.T) {
	// ApplyFiltered should return an error for a non-existent instance
	be := &mock.Backend{}
	err := ApplyFiltered(io.Discard, "nonexistent-instance-12345", be, false)
	if err == nil {
		t.Error("ApplyFiltered() expected error for non-existent instance, got nil")
	}
}
