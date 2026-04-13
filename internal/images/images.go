// Package images provides dynamic discovery of cloud base images.
package images

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/natsort"
)

// ImageInfo contains metadata for a downloadable base image.
type ImageInfo struct {
	Name        string `json:"name"`        // e.g., "ubuntu-24.04"
	Description string `json:"description"` // e.g., "Ubuntu 24.04 LTS (Noble Numbat)"
	URL         string `json:"url"`         // Download URL
	Hash        string `json:"hash"`        // Expected checksum (hex-encoded)
	HashAlgo    string `json:"hash_algo"`   // "sha256" or "sha512"
	Provider    string `json:"provider"`    // e.g., "ubuntu" or "debian"
}

// Provider defines the interface for cloud image providers.
type Provider interface {
	// Name returns the provider name (e.g., "ubuntu", "debian").
	Name() string
	// FetchAvailable fetches available images from the provider.
	FetchAvailable(ctx context.Context) ([]ImageInfo, error)
}

// Cache holds cached image discovery results.
type Cache struct {
	Timestamp time.Time   `json:"timestamp"`
	Images    []ImageInfo `json:"images"`
}

// cacheMaxAge is the maximum age for cached results.
const cacheMaxAge = 1 * time.Hour

// providers is the list of registered providers.
// Only modified during init(); not safe for concurrent access.
var providers []Provider

// RegisterProvider adds a provider to the list.
// It must only be called from init() functions.
func RegisterProvider(p Provider) {
	providers = append(providers, p)
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

// getCachePath returns the path to the image cache file.
func getCachePath() (string, error) {
	cacheDir, err := getCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cacheDir, "images.json"), nil
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

// FetchAll fetches available images from all providers.
// Uses cached results if available and not expired.
func FetchAll(ctx context.Context, forceRefresh bool) ([]ImageInfo, error) {
	// Try to use cache unless force refresh
	if !forceRefresh {
		cache, err := loadCache()
		if err == nil && time.Since(cache.Timestamp) < cacheMaxAge {
			return cache.Images, nil
		}
	}

	// Fetch from all providers
	var allImages []ImageInfo
	var errors []error

	for _, p := range providers {
		images, err := p.FetchAvailable(ctx)
		if err != nil {
			errors = append(errors, fmt.Errorf("%s: %w", p.Name(), err))
			continue
		}
		allImages = append(allImages, images...)
	}

	// If all providers failed, return error
	if len(allImages) == 0 && len(errors) > 0 {
		return nil, fmt.Errorf("failed to fetch images: %v", errors)
	}

	// Sort images by name with natural ordering (numeric-aware).
	sort.Slice(allImages, func(i, j int) bool {
		return natsort.Less(allImages[i].Name, allImages[j].Name)
	})

	// Cache results
	cache := &Cache{
		Timestamp: time.Now(),
		Images:    allImages,
	}
	if err := saveCache(cache); err != nil {
		// Log warning but don't fail
		logging.Warn("failed to cache image list", "error", err)
	}

	return allImages, nil
}

// FindByName finds an image by name.
func FindByName(ctx context.Context, name string) (*ImageInfo, error) {
	images, err := FetchAll(ctx, false)
	if err != nil {
		return nil, err
	}

	for _, img := range images {
		if img.Name == name {
			return &img, nil
		}
	}

	return nil, fmt.Errorf("image not found: %s", name)
}

// GroupByProvider groups images by their provider.
func GroupByProvider(images []ImageInfo) map[string][]ImageInfo {
	groups := make(map[string][]ImageInfo)
	for _, img := range images {
		groups[img.Provider] = append(groups[img.Provider], img)
	}
	return groups
}

// ProviderOrder returns the canonical display order for providers.
func ProviderOrder() []string {
	return []string{"almalinux", "debian", "ubuntu"}
}

// providerDisplayNames maps provider identifiers to their proper display names.
var providerDisplayNames = map[string]string{
	"almalinux": "AlmaLinux",
	"debian":    "Debian",
	"ubuntu":    "Ubuntu",
}

// ProviderDisplayName returns the display name for a provider.
func ProviderDisplayName(provider string) string {
	if name, ok := providerDisplayNames[provider]; ok {
		return name
	}
	if len(provider) == 0 {
		return provider
	}
	return strings.ToUpper(provider[:1]) + provider[1:]
}

// FormatSize formats a byte count as a human-readable size string.
func FormatSize(bytes int64) string {
	return fmt.Sprintf("%.1f GB", float64(bytes)/(1024*1024*1024))
}

// compareVersionStrings compares two dot-separated version strings numerically.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func compareVersionStrings(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")

	for i := 0; i < len(aParts) || i < len(bParts); i++ {
		var ai, bi int
		if i < len(aParts) {
			ai, _ = strconv.Atoi(aParts[i])
		}
		if i < len(bParts) {
			bi, _ = strconv.Atoi(bParts[i])
		}
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}
	return 0
}

// ParseChecksums parses SHA256SUMS/SHA512SUMS format and returns hash for the given filename.
// Format: <hash>  <filename> or <hash> *<filename>
func ParseChecksums(r io.Reader, filename string) (string, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Split on whitespace - format is "hash  filename" or "hash *filename"
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

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", fmt.Errorf("checksum not found for %s", filename)
}
