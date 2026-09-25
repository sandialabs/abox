package pull

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/images"
)

// TestVerifyChecksum_EmptyHashFailsClosed verifies that a catalog entry
// with no published checksum is rejected by default.
func TestVerifyChecksum_EmptyHashFailsClosed(t *testing.T) {
	var buf bytes.Buffer
	img := &images.ImageInfo{Name: "mystery", Hash: ""}
	err := verifyChecksum(&buf, img, "deadbeef", false)
	if err == nil {
		t.Fatal("expected a hashless image to fail closed without --allow-unverified")
	}
	if !strings.Contains(err.Error(), "no published checksum") {
		t.Errorf("error = %q, want a no-checksum error", err)
	}
}

// TestVerifyChecksum_EmptyHashAllowedWithFlag verifies the opt-out works.
func TestVerifyChecksum_EmptyHashAllowedWithFlag(t *testing.T) {
	var buf bytes.Buffer
	img := &images.ImageInfo{Name: "mystery", Hash: ""}
	if err := verifyChecksum(&buf, img, "deadbeef", true); err != nil {
		t.Fatalf("--allow-unverified should permit a hashless image, got %v", err)
	}
}

// TestVerifyChecksum_MismatchStillFails is a regression guard for the existing
// mismatch behavior.
func TestVerifyChecksum_MismatchStillFails(t *testing.T) {
	var buf bytes.Buffer
	img := &images.ImageInfo{Name: "ubuntu", Hash: "aaaa", HashAlgo: "sha256"}
	if err := verifyChecksum(&buf, img, "bbbb", true); err == nil {
		t.Fatal("a checksum mismatch must fail even with --allow-unverified")
	}
}

// TestVerifyChecksum_MatchSucceeds confirms a matching hash passes.
func TestVerifyChecksum_MatchSucceeds(t *testing.T) {
	var buf bytes.Buffer
	img := &images.ImageInfo{Name: "ubuntu", Hash: "abc123", HashAlgo: "sha256"}
	if err := verifyChecksum(&buf, img, "abc123", false); err != nil {
		t.Fatalf("matching checksum should verify, got %v", err)
	}
}
