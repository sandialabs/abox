package images

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

const ubuntuReleasesJSON = "https://cloud-images.ubuntu.com/releases/streams/v1/com.ubuntu.cloud:released:download.json"

// UbuntuProvider fetches available Ubuntu cloud images.
type UbuntuProvider struct {
	httpClient *http.Client
}

// NewUbuntuProvider creates a new Ubuntu provider.
func NewUbuntuProvider() *UbuntuProvider {
	return &UbuntuProvider{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Name returns the provider name.
func (p *UbuntuProvider) Name() string {
	return providerUbuntu
}

// minUbuntuVersion is the minimum Ubuntu LTS version to offer.
const minUbuntuVersion = "20.04"

type ubuntuCatalog struct {
	Products map[string]ubuntuProduct `json:"products"`
}

type ubuntuProduct struct {
	Arch            string                       `json:"arch"`
	Version         string                       `json:"version"`
	Release         string                       `json:"release"`
	ReleaseCodename string                       `json:"release_codename"`
	ReleaseTitle    string                       `json:"release_title"`
	Supported       bool                         `json:"supported"`
	Versions        map[string]ubuntuVersionInfo `json:"versions"`
}

type ubuntuVersionInfo struct {
	Items map[string]ubuntuItem `json:"items"`
}

type ubuntuItem struct {
	Ftype  string `json:"ftype"`
	SHA256 string `json:"sha256"`
	Path   string `json:"path"`
	Size   int64  `json:"size"`
}

// FetchAvailable fetches available Ubuntu LTS releases.
func (p *UbuntuProvider) FetchAvailable(ctx context.Context) ([]ImageInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ubuntuReleasesJSON, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Ubuntu catalog: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch Ubuntu catalog: HTTP %d", resp.StatusCode)
	}

	var catalog ubuntuCatalog
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("failed to parse Ubuntu catalog: %w", err)
	}

	return parseCatalog(&catalog)
}

// parseCatalog extracts ImageInfo entries from the Ubuntu catalog JSON.
func parseCatalog(catalog *ubuntuCatalog) ([]ImageInfo, error) {
	var images []ImageInfo

	for _, product := range catalog.Products {
		if product.Arch != archAMD64 {
			continue
		}
		if !product.Supported {
			continue
		}
		if !strings.Contains(product.ReleaseTitle, "LTS") {
			continue
		}

		version := extractMajorMinor(product.Version)
		if compareVersionStrings(version, minUbuntuVersion) < 0 {
			continue
		}

		// Find the latest version entry (keys are date strings like "20260225")
		if len(product.Versions) == 0 {
			continue
		}
		versionKeys := make([]string, 0, len(product.Versions))
		for k := range product.Versions {
			versionKeys = append(versionKeys, k)
		}
		sort.Strings(versionKeys)
		latest := product.Versions[versionKeys[len(versionKeys)-1]]

		disk, ok := latest.Items["disk1.img"]
		if !ok {
			continue
		}

		images = append(images, ImageInfo{
			Name:        "ubuntu-" + version,
			Description: fmt.Sprintf("Ubuntu %s LTS (%s)", version, product.ReleaseCodename),
			URL:         "https://cloud-images.ubuntu.com/" + disk.Path,
			Hash:        disk.SHA256,
			HashAlgo:    "sha256",
			Provider:    providerUbuntu,
		})
	}

	if len(images) == 0 {
		return nil, errors.New("no Ubuntu images found")
	}

	// Sort by version for consistent output
	sort.Slice(images, func(i, j int) bool {
		return compareVersionStrings(
			strings.TrimPrefix(images[i].Name, "ubuntu-"),
			strings.TrimPrefix(images[j].Name, "ubuntu-"),
		) < 0
	})

	return images, nil
}

// extractMajorMinor extracts the major.minor version from a full version string.
// e.g., "24.04.3 LTS" -> "24.04"
func extractMajorMinor(version string) string {
	// Remove any suffix like " LTS"
	version = strings.Split(version, " ")[0]

	// Split by dots and take first two parts
	parts := strings.Split(version, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return version
}

func init() {
	RegisterProvider(NewUbuntuProvider())
}
