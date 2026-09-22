//go:build !unix

package sysutil

import (
	"os"
	"testing"
)

// TestFileOwnerFailsClosed verifies that on platforms without POSIX ownership,
// FileOwner reports ok=false and never a fake (0,0,true). Callers use ok=false
// to fail closed on ownership-based security checks, so ok must never be true
// here.
func TestFileOwnerFailsClosed(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "owner")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if _, _, ok := FileOwner(fi); ok {
		t.Fatal("expected ok=false from the non-unix FileOwner stub, got ok=true")
	}
}
