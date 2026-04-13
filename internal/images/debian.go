package images

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	debianDistroInfoURL  = "https://debian.pages.debian.net/distro-info-data/debian.csv"
	debianCloudImagesURL = "https://cloud.debian.org/images/cloud"
)

// DebianProvider fetches available Debian cloud images.
type DebianProvider struct {
	httpClient *http.Client
}

// NewDebianProvider creates a new Debian provider.
func NewDebianProvider() *DebianProvider {
	return &DebianProvider{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Name returns the provider name.
func (p *DebianProvider) Name() string {
	return "debian"
}

// debianRelease holds parsed release info from debian.csv.
type debianRelease struct {
	version  string // e.g., "12"
	codename string // e.g., "Bookworm" (display name, capitalized)
	series   string // e.g., "bookworm" (lowercase, used in URLs)
}

// FetchAvailable fetches available Debian releases.
func (p *DebianProvider) FetchAvailable(ctx context.Context) ([]ImageInfo, error) {
	releases, err := p.fetchReleases(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch releases: %w", err)
	}

	var images []ImageInfo
	for _, rel := range releases {
		img, err := p.fetchImageInfo(ctx, rel)
		if err != nil {
			// Skip releases where we can't get checksum
			continue
		}
		images = append(images, *img)
	}

	if len(images) == 0 {
		return nil, errors.New("no Debian images found")
	}

	return images, nil
}

// fetchReleases parses the debian.csv file for supported releases.
func (p *DebianProvider) fetchReleases(ctx context.Context) ([]debianRelease, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, debianDistroInfoURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return p.parseDistroInfo(resp.Body)
}

// debianColumns holds the resolved column indices for the debian CSV.
type debianColumns struct {
	version, codename, series, release, eol int
	eolLTS                                  int
	hasEolLTS                               bool
	maxRequired                             int
}

func parseDebianHeader(header []string) (debianColumns, error) {
	colIndex := make(map[string]int)
	for i, col := range header {
		colIndex[col] = i
	}

	required := []string{"version", "codename", "series", "release", "eol"}
	var cols debianColumns
	for _, name := range required {
		idx, ok := colIndex[name]
		if !ok {
			return cols, fmt.Errorf("%s column not found", name)
		}
		switch name {
		case "version":
			cols.version = idx
		case "codename":
			cols.codename = idx
		case "series":
			cols.series = idx
		case "release":
			cols.release = idx
		case "eol":
			cols.eol = idx
		}
	}
	cols.eolLTS, cols.hasEolLTS = colIndex["eol-lts"]
	cols.maxRequired = max(cols.version, cols.codename, cols.series, cols.release, cols.eol)
	return cols, nil
}

// isReleaseSupported checks if a Debian release is still supported based on EOL dates.
func isReleaseSupported(record []string, cols debianColumns, now time.Time) bool {
	// Check regular EOL
	eolDate := record[cols.eol]
	if eolDate == "" {
		return true // No EOL set means still supported
	}
	if eol, err := time.Parse("2006-01-02", eolDate); err == nil && now.Before(eol) {
		return true
	}

	// Check LTS EOL if available
	if cols.hasEolLTS && len(record) > cols.eolLTS {
		if eolLTSDate := record[cols.eolLTS]; eolLTSDate != "" {
			if eolLTS, err := time.Parse("2006-01-02", eolLTSDate); err == nil && now.Before(eolLTS) {
				return true
			}
		}
	}

	return false
}

// parseDistroInfo parses the debian.csv format.
// CSV columns: version,codename,series,created,release,eol,eol-lts,eol-elts
func (p *DebianProvider) parseDistroInfo(r io.Reader) ([]debianRelease, error) {
	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1 // Allow variable number of fields

	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	cols, err := parseDebianHeader(header)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	var releases []debianRelease

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if len(record) <= cols.maxRequired {
			continue
		}

		// Skip if no release date or release is in the future
		releaseDate := record[cols.release]
		if releaseDate == "" {
			continue
		}
		if release, err := time.Parse("2006-01-02", releaseDate); err == nil && now.Before(release) {
			continue
		}

		if !isReleaseSupported(record, cols, now) {
			continue
		}

		// Skip versions before 13. Old-style versions (1.x, 2.x) don't have
		// cloud images. Debian 11/12 cloud images have broken network
		// initialization under libvirt/QEMU: the guest never sends DHCP
		// traffic, likely due to pre-baked network config in the images
		// conflicting with cloud-init NoCloud network-config. Debian 13+ works.
		version := record[cols.version]
		if !isNumeric(version) || parseVersion(version) < 13 {
			continue
		}

		releases = append(releases, debianRelease{
			version:  version,
			codename: record[cols.codename],
			series:   record[cols.series],
		})
	}

	return releases, nil
}

// isNumeric checks if a string is a numeric version (e.g., "12" not "1.1").
func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

// parseVersion parses a version string to an integer.
func parseVersion(s string) int {
	var v int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			v = v*10 + int(c-'0')
		}
	}
	return v
}

// fetchImageInfo fetches the image URL and checksum for a release.
func (p *DebianProvider) fetchImageInfo(ctx context.Context, rel debianRelease) (*ImageInfo, error) {
	// Fetch SHA512SUMS (use series for URL - it's lowercase)
	checksumURL := fmt.Sprintf("%s/%s/latest/SHA512SUMS", debianCloudImagesURL, rel.series)
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

	// Parse SHA512SUMS to find the generic-amd64 cloud image
	imageFilename := fmt.Sprintf("debian-%s-generic-amd64.qcow2", rel.version)
	hash, err := ParseChecksums(resp.Body, imageFilename)
	if err != nil {
		return nil, err
	}

	imageURL := fmt.Sprintf("%s/%s/latest/%s", debianCloudImagesURL, rel.series, imageFilename)

	return &ImageInfo{
		Name:        "debian-" + rel.version,
		Description: fmt.Sprintf("Debian %s (%s)", rel.version, rel.codename),
		URL:         imageURL,
		Hash:        hash,
		HashAlgo:    "sha512",
		Provider:    "debian",
	}, nil
}

func init() {
	RegisterProvider(NewDebianProvider())
}
