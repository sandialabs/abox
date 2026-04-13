package images

import (
	"strings"
	"testing"
)

func TestUbuntuParseCatalog(t *testing.T) {
	catalog := &ubuntuCatalog{
		Products: map[string]ubuntuProduct{
			"com.ubuntu.cloud:server:24.04:amd64": {
				Arch:            "amd64",
				Version:         "24.04",
				Release:         "noble",
				ReleaseCodename: "Noble Numbat",
				ReleaseTitle:    "24.04 LTS",
				Supported:       true,
				Versions: map[string]ubuntuVersionInfo{
					"20260101": {Items: map[string]ubuntuItem{
						"disk1.img": {SHA256: "oldsha256", Path: "server/releases/noble/release-20260101/ubuntu-24.04-server-cloudimg-amd64.img", Size: 600000000},
					}},
					"20260225": {Items: map[string]ubuntuItem{
						"disk1.img": {SHA256: "newsha256noble", Path: "server/releases/noble/release-20260225/ubuntu-24.04-server-cloudimg-amd64.img", Size: 629048832},
					}},
				},
			},
			"com.ubuntu.cloud:server:22.04:amd64": {
				Arch:            "amd64",
				Version:         "22.04",
				Release:         "jammy",
				ReleaseCodename: "Jammy Jellyfish",
				ReleaseTitle:    "22.04 LTS",
				Supported:       true,
				Versions: map[string]ubuntuVersionInfo{
					"20260301": {Items: map[string]ubuntuItem{
						"disk1.img": {SHA256: "sha256jammy", Path: "server/releases/jammy/release-20260301/ubuntu-22.04-server-cloudimg-amd64.img", Size: 500000000},
					}},
				},
			},
			// Should be excluded: not supported
			"com.ubuntu.cloud:server:18.04:amd64": {
				Arch:            "amd64",
				Version:         "18.04",
				Release:         "bionic",
				ReleaseCodename: "Bionic Beaver",
				ReleaseTitle:    "18.04 LTS",
				Supported:       false,
				Versions: map[string]ubuntuVersionInfo{
					"20260101": {Items: map[string]ubuntuItem{
						"disk1.img": {SHA256: "sha256bionic", Path: "server/releases/bionic/release-20260101/ubuntu-18.04-server-cloudimg-amd64.img"},
					}},
				},
			},
			// Should be excluded: not LTS
			"com.ubuntu.cloud:server:23.10:amd64": {
				Arch:            "amd64",
				Version:         "23.10",
				Release:         "mantic",
				ReleaseCodename: "Mantic Minotaur",
				ReleaseTitle:    "23.10",
				Supported:       true,
				Versions: map[string]ubuntuVersionInfo{
					"20260101": {Items: map[string]ubuntuItem{
						"disk1.img": {SHA256: "sha256mantic", Path: "server/releases/mantic/release-20260101/ubuntu-23.10-server-cloudimg-amd64.img"},
					}},
				},
			},
			// Should be excluded: arm64
			"com.ubuntu.cloud:server:24.04:arm64": {
				Arch:            "arm64",
				Version:         "24.04",
				Release:         "noble",
				ReleaseCodename: "Noble Numbat",
				ReleaseTitle:    "24.04 LTS",
				Supported:       true,
				Versions: map[string]ubuntuVersionInfo{
					"20260225": {Items: map[string]ubuntuItem{
						"disk1.img": {SHA256: "sha256arm", Path: "server/releases/noble/release-20260225/ubuntu-24.04-server-cloudimg-arm64.img"},
					}},
				},
			},
			// Should be excluded: below minUbuntuVersion
			"com.ubuntu.cloud:server:16.04:amd64": {
				Arch:            "amd64",
				Version:         "16.04",
				Release:         "xenial",
				ReleaseCodename: "Xenial Xerus",
				ReleaseTitle:    "16.04 LTS",
				Supported:       true,
				Versions: map[string]ubuntuVersionInfo{
					"20260101": {Items: map[string]ubuntuItem{
						"disk1.img": {SHA256: "sha256xenial", Path: "server/releases/xenial/release-20260101/ubuntu-16.04-server-cloudimg-amd64.img"},
					}},
				},
			},
		},
	}

	images, err := parseCatalog(catalog)
	if err != nil {
		t.Fatalf("parseCatalog failed: %v", err)
	}

	if len(images) != 2 {
		t.Errorf("expected 2 images, got %d", len(images))
		for _, img := range images {
			t.Logf("  %s", img.Name)
		}
	}

	// Results should be sorted by version: 22.04 first, then 24.04
	if len(images) >= 2 {
		if images[0].Name != "ubuntu-22.04" {
			t.Errorf("expected first image 'ubuntu-22.04', got %q", images[0].Name)
		}
		if images[0].Hash != "sha256jammy" {
			t.Errorf("expected hash 'sha256jammy', got %q", images[0].Hash)
		}
		if images[0].Description != "Ubuntu 22.04 LTS (Jammy Jellyfish)" {
			t.Errorf("unexpected description: %q", images[0].Description)
		}

		if images[1].Name != "ubuntu-24.04" {
			t.Errorf("expected second image 'ubuntu-24.04', got %q", images[1].Name)
		}
		// Should pick the latest version (20260225, not 20260101)
		if images[1].Hash != "newsha256noble" {
			t.Errorf("expected hash 'newsha256noble' (latest version), got %q", images[1].Hash)
		}
		if !strings.Contains(images[1].URL, "release-20260225") {
			t.Errorf("expected URL to contain 'release-20260225', got %q", images[1].URL)
		}
	}
}

func TestUbuntuParseCatalogEmpty(t *testing.T) {
	catalog := &ubuntuCatalog{
		Products: map[string]ubuntuProduct{},
	}

	_, err := parseCatalog(catalog)
	if err == nil {
		t.Error("expected error for empty catalog, got nil")
	}
}

func TestParseChecksums(t *testing.T) {
	input := `abc123  other-file.img
def456  noble-server-cloudimg-amd64.img
ghi789 *another-file.img
`

	hash, err := ParseChecksums(strings.NewReader(input), "noble-server-cloudimg-amd64.img")
	if err != nil {
		t.Fatalf("ParseChecksums failed: %v", err)
	}

	if hash != "def456" {
		t.Errorf("expected hash 'def456', got %q", hash)
	}
}

func TestParseChecksumsNotFound(t *testing.T) {
	input := `abc123  other-file.img
`

	_, err := ParseChecksums(strings.NewReader(input), "nonexistent.img")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestParseChecksumsStarPrefix(t *testing.T) {
	input := `abc123 *file-with-star.img
`

	hash, err := ParseChecksums(strings.NewReader(input), "file-with-star.img")
	if err != nil {
		t.Fatalf("ParseChecksums failed: %v", err)
	}

	if hash != "abc123" {
		t.Errorf("expected hash 'abc123', got %q", hash)
	}
}

func TestExtractMajorMinor(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"24.04.3 LTS", "24.04"},
		{"22.04.5 LTS", "22.04"},
		{"20.04", "20.04"},
		{"18.04.6", "18.04"},
		{"24.04", "24.04"},
		{"10", "10"},
	}

	for _, tt := range tests {
		result := extractMajorMinor(tt.input)
		if result != tt.expected {
			t.Errorf("extractMajorMinor(%q) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

func TestDebianParseDistroInfo(t *testing.T) {
	// Simulate CSV with supported releases using future dates to avoid test staleness.
	// Debian 11/12 are skipped (broken cloud images), so only 13+ should appear.
	input := `version,codename,series,created,release,eol,eol-lts,eol-elts
11,Bullseye,bullseye,2019-07-06,2021-08-14,2099-08-14,2099-08-31,2099-06-30
12,Bookworm,bookworm,2021-08-14,2023-06-10,2099-07-11,2099-06-30,2099-06-30
13,Trixie,trixie,2023-06-10,2025-08-09,2099-08-09,2099-06-30,2099-06-30
14,Forky,forky,2025-08-09,2099-08-09,2099-08-09,2099-06-30,2099-06-30
`

	provider := &DebianProvider{}
	releases, err := provider.parseDistroInfo(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseDistroInfo failed: %v", err)
	}

	// Should have 1 release (13 only): 11/12 skipped (< 13), 14 not yet released
	if len(releases) != 1 {
		t.Errorf("expected 1 release, got %d", len(releases))
		for _, r := range releases {
			t.Logf("  %s (%s)", r.version, r.codename)
		}
	}

	// Check Trixie
	if len(releases) > 0 {
		if releases[0].version != "13" {
			t.Errorf("expected version '13', got %q", releases[0].version)
		}
		if releases[0].codename != "Trixie" {
			t.Errorf("expected codename 'Trixie', got %q", releases[0].codename)
		}
		if releases[0].series != "trixie" {
			t.Errorf("expected series 'trixie', got %q", releases[0].series)
		}
	}
}

func TestParseChecksumsSHA512(t *testing.T) {
	// Test with SHA512-length hash (128 hex chars)
	input := `abc123  debian-12-azure-amd64.json
def456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456  debian-12-generic-amd64.qcow2
ghi789  debian-12-ec2-amd64.json
`

	hash, err := ParseChecksums(strings.NewReader(input), "debian-12-generic-amd64.qcow2")
	if err != nil {
		t.Fatalf("ParseChecksums failed: %v", err)
	}

	expected := "def456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456"
	if hash != expected {
		t.Errorf("expected hash %q, got %q", expected, hash)
	}
}

func TestCompareVersionStrings(t *testing.T) {
	tests := []struct {
		a, b     string
		expected int
	}{
		{"8", "9", -1},
		{"9", "10", -1},
		{"10", "8", 1},
		{"10", "10", 0},
		{"20.04", "22.04", -1},
		{"24.04", "22.04", 1},
		{"22.04", "22.04", 0},
		{"11", "11", 0},
	}

	for _, tt := range tests {
		result := compareVersionStrings(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("compareVersionStrings(%q, %q) = %d, expected %d", tt.a, tt.b, result, tt.expected)
		}
	}
}

func TestGroupByProvider(t *testing.T) {
	imgs := []ImageInfo{
		{Name: "ubuntu-24.04", Provider: "ubuntu"},
		{Name: "debian-12", Provider: "debian"},
		{Name: "ubuntu-22.04", Provider: "ubuntu"},
	}

	groups := GroupByProvider(imgs)

	if len(groups["ubuntu"]) != 2 {
		t.Errorf("expected 2 ubuntu images, got %d", len(groups["ubuntu"]))
	}
	if len(groups["debian"]) != 1 {
		t.Errorf("expected 1 debian image, got %d", len(groups["debian"]))
	}
}

func TestProviderDisplayName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"almalinux", "AlmaLinux"},
		{"debian", "Debian"},
		{"ubuntu", "Ubuntu"},
		{"", ""},
		{"a", "A"},
		{"unknown", "Unknown"},
	}

	for _, tt := range tests {
		result := ProviderDisplayName(tt.input)
		if result != tt.expected {
			t.Errorf("ProviderDisplayName(%q) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

func TestFormatSize(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{0, "0.0 GB"},
		{1073741824, "1.0 GB"}, // 1 GB
		{2147483648, "2.0 GB"}, // 2 GB
		{536870912, "0.5 GB"},  // 0.5 GB
		{1610612736, "1.5 GB"}, // 1.5 GB
	}

	for _, tt := range tests {
		result := FormatSize(tt.bytes)
		if result != tt.expected {
			t.Errorf("FormatSize(%d) = %q, expected %q", tt.bytes, result, tt.expected)
		}
	}
}

func TestProviderOrder(t *testing.T) {
	order := ProviderOrder()
	if len(order) < 3 {
		t.Errorf("expected at least 3 providers, got %d", len(order))
	}
	// Verify almalinux, debian and ubuntu are present
	found := make(map[string]bool)
	for _, p := range order {
		found[p] = true
	}
	if !found["almalinux"] {
		t.Error("expected 'almalinux' in provider order")
	}
	if !found["debian"] {
		t.Error("expected 'debian' in provider order")
	}
	if !found["ubuntu"] {
		t.Error("expected 'ubuntu' in provider order")
	}
}
