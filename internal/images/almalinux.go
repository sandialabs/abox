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

// almalinuxUpstreamArch maps a Go-style arch ("amd64"/"arm64") to AlmaLinux's
// upstream naming ("x86_64"/"aarch64"). Returns empty string for unsupported arches.
func almalinuxUpstreamArch(arch string) string {
	switch arch {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return ""
	}
}

// almalinuxImageFilename returns the cloud image filename for a given AlmaLinux
// version and Go-style arch. Returns an error for unsupported arches.
func almalinuxImageFilename(version, arch string) (string, error) {
	upstream := almalinuxUpstreamArch(arch)
	if upstream == "" {
		return "", fmt.Errorf("unsupported arch %q", arch)
	}
	return fmt.Sprintf("AlmaLinux-%s-GenericCloud-latest.%s.qcow2", version, upstream), nil
}

// FetchAvailable fetches available AlmaLinux releases.
func (p *AlmaLinuxProvider) FetchAvailable(ctx context.Context) ([]ImageInfo, error) {
	releases := supportedAlmaLinuxVersions()
	arch := hostArch()

	var images []ImageInfo
	for _, rel := range releases {
		img, err := p.fetchImageInfo(ctx, rel, arch)
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
func (p *AlmaLinuxProvider) fetchImageInfo(ctx context.Context, rel almalinuxRelease, arch string) (*ImageInfo, error) {
	upstream := almalinuxUpstreamArch(arch)
	if upstream == "" {
		return nil, fmt.Errorf("unsupported arch %q", arch)
	}

	// AlmaLinux cloud images are at:
	// https://repo.almalinux.org/almalinux/{version}/cloud/{upstream-arch}/images/
	// CHECKSUM file contains SHA256 hashes in standard format: <hash>  <filename>
	checksumURL := fmt.Sprintf("%s/%s/cloud/%s/images/CHECKSUM", almalinuxBaseURL, rel.version, upstream)
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
	imageFilename, err := almalinuxImageFilename(rel.version, arch)
	if err != nil {
		return nil, err
	}
	hash, err := ParseChecksums(resp.Body, imageFilename)
	if err != nil {
		return nil, err
	}

	imageURL := fmt.Sprintf("%s/%s/cloud/%s/images/%s", almalinuxBaseURL, rel.version, upstream, imageFilename)

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
