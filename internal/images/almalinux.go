package images

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/sandialabs/abox/internal/logging"
)

const (
	almalinuxBaseURL = "https://repo.almalinux.org/almalinux"
)

// AlmaLinuxProvider fetches available AlmaLinux cloud images.
type AlmaLinuxProvider struct {
	httpClient *http.Client
}

// NewAlmaLinuxProvider creates a new AlmaLinux provider.
func NewAlmaLinuxProvider() *AlmaLinuxProvider {
	return &AlmaLinuxProvider{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Name returns the provider name.
func (p *AlmaLinuxProvider) Name() string {
	return "almalinux"
}

// almalinuxRelease holds release info for AlmaLinux.
type almalinuxRelease struct {
	version string // e.g., "8", "9"
}

// supportedAlmaLinuxVersions returns the list of supported AlmaLinux versions.
// We check these explicitly since AlmaLinux doesn't have a machine-readable
// release list like Ubuntu's meta-release-lts.
func supportedAlmaLinuxVersions() []almalinuxRelease {
	return []almalinuxRelease{
		{version: "8"},
		{version: "9"},
		{version: "10"},
	}
}

// FetchAvailable fetches available AlmaLinux releases.
func (p *AlmaLinuxProvider) FetchAvailable(ctx context.Context) ([]ImageInfo, error) {
	releases := supportedAlmaLinuxVersions()

	var images []ImageInfo
	for _, rel := range releases {
		img, err := p.fetchImageInfo(ctx, rel)
		if err != nil {
			logging.Warn("skipping AlmaLinux image", "version", rel.version, "error", err)
			continue
		}
		images = append(images, *img)
	}

	if len(images) == 0 {
		return nil, errors.New("no AlmaLinux images found")
	}

	return images, nil
}

// fetchImageInfo fetches the image URL and checksum for a release.
func (p *AlmaLinuxProvider) fetchImageInfo(ctx context.Context, rel almalinuxRelease) (*ImageInfo, error) {
	// AlmaLinux cloud images are at:
	// https://repo.almalinux.org/almalinux/{version}/cloud/x86_64/images/
	// CHECKSUM file contains SHA256 hashes in standard format: <hash>  <filename>
	checksumURL := fmt.Sprintf("%s/%s/cloud/x86_64/images/CHECKSUM", almalinuxBaseURL, rel.version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checksumURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d fetching checksums", resp.StatusCode)
	}

	// Parse CHECKSUM file to find the GenericCloud image
	// Format: <hash>  <filename> (standard format, same as Ubuntu/Debian)
	// We want: AlmaLinux-{version}-GenericCloud-latest.x86_64.qcow2
	imageFilename := fmt.Sprintf("AlmaLinux-%s-GenericCloud-latest.x86_64.qcow2", rel.version)
	hash, err := ParseChecksums(resp.Body, imageFilename)
	if err != nil {
		return nil, err
	}

	imageURL := fmt.Sprintf("%s/%s/cloud/x86_64/images/%s", almalinuxBaseURL, rel.version, imageFilename)

	return &ImageInfo{
		Name:        "almalinux-" + rel.version,
		Description: "AlmaLinux " + rel.version,
		URL:         imageURL,
		Hash:        hash,
		HashAlgo:    "sha256",
		Provider:    "almalinux",
	}, nil
}

func init() {
	RegisterProvider(NewAlmaLinuxProvider())
}
