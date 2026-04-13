// Package tetragon provides dynamic discovery of Tetragon releases from GitHub.
package tetragon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ReleaseInfo contains metadata for a downloadable Tetragon release.
type ReleaseInfo struct {
	Version  string `json:"version"`   // e.g., "v1.6.0"
	URL      string `json:"url"`       // Download URL for amd64 tarball
	Hash     string `json:"hash"`      // SHA256 checksum
	HashAlgo string `json:"hash_algo"` // "sha256"
}

// Cache holds cached release info.
type Cache struct {
	Timestamp time.Time   `json:"timestamp"`
	Latest    ReleaseInfo `json:"latest"`
}

// cacheMaxAge is the maximum age for cached results (24 hours).
const cacheMaxAge = 24 * time.Hour

// githubAPIBase is the base URL for GitHub API.
const githubAPIBase = "https://api.github.com/repos/cilium/tetragon/releases"

// httpClient is a shared HTTP client for fetching releases.
var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}

// getCacheDir returns the cache directory path.
func getCacheDir() (string, error) {
	cacheHome := os.Getenv("XDG_CACHE_HOME")
	if cacheHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get home directory: %w", err)
		}
		cacheHome = filepath.Join(home, ".cache")
	}
	return filepath.Join(cacheHome, "abox"), nil
}

// getCachePath returns the path to the release cache file.
func getCachePath() (string, error) {
	cacheDir, err := getCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cacheDir, "tetragon-release.json"), nil
}

// loadCache loads the cache from disk.
func loadCache() (*Cache, error) {
	cachePath, err := getCachePath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, err
	}

	var cache Cache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, err
	}

	return &cache, nil
}

// saveCache saves the cache to disk.
func saveCache(cache *Cache) error {
	cacheDir, err := getCacheDir()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(cacheDir, 0o755); err != nil { //nolint:gosec // cache dir needs 0o755 for user access
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	cachePath, err := getCachePath()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(cachePath, data, 0o644) //nolint:gosec // cache file, not sensitive
}

// githubRelease represents a GitHub release from the API.
type githubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []githubAsset `json:"assets"`
}

// githubAsset represents an asset in a GitHub release.
type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// GetRelease fetches release info for a specific version or latest.
// If version is empty, fetches the latest release.
// Uses cached results if available and not expired (for latest only).
func GetRelease(ctx context.Context, version string, forceRefresh bool) (*ReleaseInfo, error) {
	// If specific version requested, always fetch (no caching for pinned versions)
	if version != "" {
		return fetchVersion(ctx, version)
	}

	// Try to use cache for latest
	if !forceRefresh {
		cache, err := loadCache()
		if err == nil && time.Since(cache.Timestamp) < cacheMaxAge {
			return &cache.Latest, nil
		}
	}

	// Fetch latest from GitHub
	release, err := fetchLatest(ctx)
	if err != nil {
		// If fetch fails but we have stale cache, use it
		if cache, cacheErr := loadCache(); cacheErr == nil {
			slog.Warn("using cached Tetragon release info", "error", err)
			return &cache.Latest, nil
		}
		return nil, err
	}

	// Cache the result
	cache := &Cache{
		Timestamp: time.Now(),
		Latest:    *release,
	}
	if err := saveCache(cache); err != nil {
		slog.Warn("failed to cache Tetragon release info", "error", err)
	}

	return release, nil
}

// fetchLatest fetches the latest release from GitHub.
func fetchLatest(ctx context.Context) (*ReleaseInfo, error) {
	url := githubAPIBase + "/latest"
	return fetchReleaseFromURL(ctx, url)
}

// fetchVersion fetches a specific version from GitHub.
func fetchVersion(ctx context.Context, version string) (*ReleaseInfo, error) {
	// Ensure version starts with 'v'
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}

	// Validate version format before URL interpolation
	if !regexp.MustCompile(`^v\d+\.\d+\.\d+$`).MatchString(version) {
		return nil, fmt.Errorf("invalid version format %q: must match vX.Y.Z", version)
	}

	url := fmt.Sprintf("%s/tags/%s", githubAPIBase, version)
	return fetchReleaseFromURL(ctx, url)
}

// fetchReleaseFromURL fetches release info from a GitHub API URL.
func fetchReleaseFromURL(ctx context.Context, url string) (*ReleaseInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set User-Agent (required by GitHub API)
	req.Header.Set("User-Agent", "abox")
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New("release not found")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to parse release JSON: %w", err)
	}

	return parseRelease(ctx, &release)
}

// parseRelease extracts ReleaseInfo from a GitHub release.
func parseRelease(ctx context.Context, release *githubRelease) (*ReleaseInfo, error) {
	version := release.TagName

	// Find the amd64 tarball asset
	tarballName := fmt.Sprintf("tetragon-%s-amd64.tar.gz", version)
	checksumName := tarballName + ".sha256sum"

	var tarballURL string
	var checksumURL string

	for _, asset := range release.Assets {
		switch asset.Name {
		case tarballName:
			tarballURL = asset.BrowserDownloadURL
		case checksumName:
			checksumURL = asset.BrowserDownloadURL
		}
	}

	if tarballURL == "" {
		return nil, fmt.Errorf("tarball asset %s not found in release", tarballName)
	}

	// Fetch checksum
	hash := ""
	if checksumURL != "" {
		var err error
		hash, err = fetchChecksum(ctx, checksumURL, tarballName)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch checksum: %w", err)
		}
	}

	return &ReleaseInfo{
		Version:  version,
		URL:      tarballURL,
		Hash:     hash,
		HashAlgo: "sha256",
	}, nil
}

// fetchChecksum fetches and parses a checksum file.
// The file format is: <hash>  <filename> or <hash> *<filename>
func fetchChecksum(ctx context.Context, url, filename string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "abox")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch checksum: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Parse checksum file
	// Format: <hash>  <filename> or <hash> *<filename>
	lines := strings.SplitSeq(string(body), "\n")
	for line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}

		hash := parts[0]
		name := strings.TrimPrefix(parts[1], "*")

		if name == filename {
			return hash, nil
		}
	}

	return "", fmt.Errorf("checksum not found for %s", filename)
}

// TarballFilename returns the filename for the cached Tetragon tarball.
func TarballFilename(version string) string {
	return fmt.Sprintf("tetragon-%s-amd64.tar.gz", version)
}
