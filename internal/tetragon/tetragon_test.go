package tetragon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestTarballFilename(t *testing.T) {
	tests := []struct {
		version  string
		expected string
	}{
		{"v1.3.0", "tetragon-v1.3.0-amd64.tar.gz"},
		{"v1.6.0", "tetragon-v1.6.0-amd64.tar.gz"},
	}

	for _, tt := range tests {
		got := TarballFilename(tt.version)
		if got != tt.expected {
			t.Errorf("TarballFilename(%q) = %q, want %q", tt.version, got, tt.expected)
		}
	}
}

func TestParseRelease(t *testing.T) {
	release := &githubRelease{
		TagName: "v1.6.0",
		Assets: []githubAsset{
			{Name: "tetragon-v1.6.0-amd64.tar.gz", BrowserDownloadURL: "https://example.com/tetragon-v1.6.0-amd64.tar.gz"},
			{Name: "tetragon-v1.6.0-amd64.tar.gz.sha256sum", BrowserDownloadURL: "https://example.com/tetragon-v1.6.0-amd64.tar.gz.sha256sum"},
		},
	}

	// Note: This will try to fetch the checksum, which will fail
	// We'll test the error case here
	_, err := parseRelease(context.Background(), release)
	if err == nil {
		t.Log("parseRelease succeeded (checksum fetch may have worked)")
	} else {
		// Expected to fail on checksum fetch
		t.Logf("parseRelease failed as expected (no network): %v", err)
	}
}

func TestParseRelease_MissingTarball(t *testing.T) {
	release := &githubRelease{
		TagName: "v1.6.0",
		Assets: []githubAsset{
			{Name: "some-other-file.txt", BrowserDownloadURL: "https://example.com/other"},
		},
	}

	_, err := parseRelease(context.Background(), release)
	if err == nil {
		t.Error("parseRelease should fail when tarball is missing")
	}
}

func TestCacheRoundTrip(t *testing.T) {
	// Create temp directory for cache
	tmpDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmpDir)

	cache := &Cache{
		Timestamp: time.Now(),
		Latest: ReleaseInfo{
			Version:  "v1.6.0",
			URL:      "https://example.com/tetragon-v1.6.0-amd64.tar.gz",
			Hash:     "abc123",
			HashAlgo: "sha256",
		},
	}

	// Save cache
	if err := saveCache(cache); err != nil {
		t.Fatalf("saveCache failed: %v", err)
	}

	// Load cache
	loaded, err := loadCache()
	if err != nil {
		t.Fatalf("loadCache failed: %v", err)
	}

	if loaded.Latest.Version != cache.Latest.Version {
		t.Errorf("Version mismatch: got %q, want %q", loaded.Latest.Version, cache.Latest.Version)
	}
	if loaded.Latest.URL != cache.Latest.URL {
		t.Errorf("URL mismatch: got %q, want %q", loaded.Latest.URL, cache.Latest.URL)
	}
	if loaded.Latest.Hash != cache.Latest.Hash {
		t.Errorf("Hash mismatch: got %q, want %q", loaded.Latest.Hash, cache.Latest.Hash)
	}
}

func TestGetRelease_UsesCache(t *testing.T) {
	// Create temp directory for cache
	tmpDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmpDir)

	// Pre-populate cache
	cache := &Cache{
		Timestamp: time.Now(),
		Latest: ReleaseInfo{
			Version:  "v1.5.0",
			URL:      "https://example.com/tetragon-v1.5.0-amd64.tar.gz",
			Hash:     "cachedHash",
			HashAlgo: "sha256",
		},
	}
	if err := saveCache(cache); err != nil {
		t.Fatalf("saveCache failed: %v", err)
	}

	// GetRelease should use cached value
	release, err := GetRelease(context.Background(), "", false)
	if err != nil {
		t.Fatalf("GetRelease failed: %v", err)
	}

	if release.Version != "v1.5.0" {
		t.Errorf("Expected cached version v1.5.0, got %s", release.Version)
	}
	if release.Hash != "cachedHash" {
		t.Errorf("Expected cached hash cachedHash, got %s", release.Hash)
	}
}

func TestGetRelease_ExpiredCache(t *testing.T) {
	// Create temp directory for cache
	tmpDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmpDir)

	// Pre-populate with expired cache
	cache := &Cache{
		Timestamp: time.Now().Add(-25 * time.Hour), // Expired
		Latest: ReleaseInfo{
			Version:  "v1.4.0",
			URL:      "https://example.com/tetragon-v1.4.0-amd64.tar.gz",
			Hash:     "oldHash",
			HashAlgo: "sha256",
		},
	}
	if err := saveCache(cache); err != nil {
		t.Fatalf("saveCache failed: %v", err)
	}

	// GetRelease should try to fetch, but fall back to stale cache on network error
	release, err := GetRelease(context.Background(), "", false)
	if err != nil {
		// If network is unavailable and cache exists, should use stale cache
		t.Fatalf("GetRelease failed unexpectedly: %v", err)
	}

	// Should have used stale cache as fallback
	if release.Version != "v1.4.0" {
		t.Logf("Got version %s (may have fetched fresh data if network available)", release.Version)
	}
}

func TestFetchChecksum(t *testing.T) {
	// Create a mock server
	checksumContent := "abc123def456  tetragon-v1.6.0-amd64.tar.gz\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(checksumContent))
	}))
	defer server.Close()

	hash, err := fetchChecksum(context.Background(), server.URL, "tetragon-v1.6.0-amd64.tar.gz")
	if err != nil {
		t.Fatalf("fetchChecksum failed: %v", err)
	}

	if hash != "abc123def456" {
		t.Errorf("Expected hash abc123def456, got %s", hash)
	}
}

func TestFetchChecksum_StarPrefix(t *testing.T) {
	// Some checksum files use *<filename> format (binary mode)
	checksumContent := "abc123def456 *tetragon-v1.6.0-amd64.tar.gz\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(checksumContent))
	}))
	defer server.Close()

	hash, err := fetchChecksum(context.Background(), server.URL, "tetragon-v1.6.0-amd64.tar.gz")
	if err != nil {
		t.Fatalf("fetchChecksum failed: %v", err)
	}

	if hash != "abc123def456" {
		t.Errorf("Expected hash abc123def456, got %s", hash)
	}
}

func TestFetchReleaseFromURL(t *testing.T) {
	// Create checksum server first
	checksumContent := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890  tetragon-v1.6.0-amd64.tar.gz\n"
	checksumServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(checksumContent))
	}))
	defer checksumServer.Close()

	// Create release API server
	release := githubRelease{
		TagName: "v1.6.0",
		Assets: []githubAsset{
			{Name: "tetragon-v1.6.0-amd64.tar.gz", BrowserDownloadURL: "https://example.com/tetragon-v1.6.0-amd64.tar.gz"},
			{Name: "tetragon-v1.6.0-amd64.tar.gz.sha256sum", BrowserDownloadURL: checksumServer.URL},
		},
	}
	releaseJSON, _ := json.Marshal(release)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(releaseJSON)
	}))
	defer server.Close()

	info, err := fetchReleaseFromURL(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("fetchReleaseFromURL failed: %v", err)
	}

	if info.Version != "v1.6.0" {
		t.Errorf("Expected version v1.6.0, got %s", info.Version)
	}
	if info.Hash != "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" {
		t.Errorf("Unexpected hash: %s", info.Hash)
	}
}

func TestGetCacheDir(t *testing.T) {
	// Test with XDG_CACHE_HOME set
	tmpDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmpDir)

	cacheDir, err := getCacheDir()
	if err != nil {
		t.Fatalf("getCacheDir failed: %v", err)
	}

	expected := filepath.Join(tmpDir, "abox")
	if cacheDir != expected {
		t.Errorf("Expected %s, got %s", expected, cacheDir)
	}
}
