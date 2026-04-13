package allowlist

import (
	"fmt"
	"sync"
	"testing"
)

// TestFilter_ConcurrentMixedOperations tests that concurrent Add, Remove,
// Replace, IsAllowed, List, and Count operations don't race or panic.
// Run with: go test -race ./internal/allowlist/
func TestFilter_ConcurrentMixedOperations(t *testing.T) {
	f := NewFilter()

	// Pre-populate with some domains
	for i := range 50 {
		f.Add(fmt.Sprintf("domain%d.com", i))
	}

	var wg sync.WaitGroup

	// Concurrent Adds
	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			f.Add(fmt.Sprintf("new%d.example.com", i))
		}(i)
	}

	// Concurrent Removes
	for i := range 50 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			f.Remove(fmt.Sprintf("domain%d.com", i))
		}(i)
	}

	// Concurrent Replaces
	for range 10 {
		wg.Go(func() {
			f.Replace([]string{"replace1.com", "replace2.com", "replace3.com"})
		})
	}

	// Concurrent IsAllowed checks
	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			f.IsAllowed(fmt.Sprintf("domain%d.com", i))
			f.IsAllowed(fmt.Sprintf("new%d.example.com", i))
			f.IsAllowed("nonexistent.com")
		}(i)
	}

	// Concurrent List + Count
	for range 50 {
		wg.Go(func() {
			_ = f.List()
			_ = f.Count()
		})
	}

	wg.Wait()

	// Sanity: filter should still work after all concurrent operations
	f.Clear()
	f.Add("final.com")
	if !f.IsAllowed("final.com") {
		t.Error("final.com should be allowed after Clear + Add")
	}
	if f.Count() != 1 {
		t.Errorf("Count() = %d, want 1", f.Count())
	}
}
