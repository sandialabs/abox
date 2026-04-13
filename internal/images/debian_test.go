package images

import (
	"strings"
	"testing"
)

// Realistic debian.csv snippet based on actual upstream format.
// Tests the full parseDistroInfo pipeline: header parsing, EOL filtering,
// release date filtering, and version gating (only 13+ returned).
const debianCSV = `version,codename,series,created,release,eol,eol-lts,eol-elts
1.1,Buzz,buzz,1996-06-17,1996-06-17,1997-06-05,,
8,Jessie,jessie,2013-05-04,2015-04-25,2018-06-17,2020-06-30,2025-06-30
10,Buster,buster,2017-06-17,2019-07-06,2022-09-10,2024-06-30,
11,Bullseye,bullseye,2019-07-06,2021-08-14,2024-07-01,2026-06-30,
12,Bookworm,bookworm,2021-08-14,2023-06-10,2028-06-01,,
13,Trixie,trixie,2023-06-10,2025-08-01,,,
14,Forky,forky,2025-06-10,,,,
`

func TestParseDistroInfo_FiltersCorrectly(t *testing.T) {
	p := &DebianProvider{}
	releases, err := p.parseDistroInfo(strings.NewReader(debianCSV))
	if err != nil {
		t.Fatalf("parseDistroInfo() error: %v", err)
	}

	// Build a lookup for easier assertions
	got := make(map[string]debianRelease)
	for _, r := range releases {
		got[r.version] = r
	}

	// Debian 13 (Trixie): released, no EOL set, version >= 13 → included
	if _, ok := got["13"]; !ok {
		t.Error("Debian 13 (Trixie) should be included: released, supported, version >= 13")
	}

	// Debian 12 (Bookworm): released, supported, but version < 13 → excluded
	if _, ok := got["12"]; ok {
		t.Error("Debian 12 (Bookworm) should be excluded: version < 13")
	}

	// Debian 11 (Bullseye): version < 13 → excluded regardless of LTS status
	if _, ok := got["11"]; ok {
		t.Error("Debian 11 (Bullseye) should be excluded: version < 13")
	}

	// Debian 14 (Forky): no release date → excluded (not released yet)
	if _, ok := got["14"]; ok {
		t.Error("Debian 14 (Forky) should be excluded: not yet released")
	}

	// Debian 1.1 (Buzz): non-numeric version → excluded
	if _, ok := got["1.1"]; ok {
		t.Error("Debian 1.1 should be excluded: non-numeric version")
	}

	// Debian 10 (Buster): EOL and LTS both expired → excluded
	if _, ok := got["10"]; ok {
		t.Error("Debian 10 (Buster) should be excluded: fully EOL")
	}

	// Debian 8 (Jessie): ancient, fully EOL → excluded
	if _, ok := got["8"]; ok {
		t.Error("Debian 8 (Jessie) should be excluded: fully EOL")
	}
}

func TestParseDistroInfo_ExtractsFieldsCorrectly(t *testing.T) {
	p := &DebianProvider{}
	releases, err := p.parseDistroInfo(strings.NewReader(debianCSV))
	if err != nil {
		t.Fatalf("parseDistroInfo() error: %v", err)
	}

	// Find Trixie and verify fields are extracted from the right columns
	var trixie *debianRelease
	for i := range releases {
		if releases[i].version == "13" {
			trixie = &releases[i]
			break
		}
	}
	if trixie == nil {
		t.Fatal("Debian 13 not found in results")
	}
	if trixie.codename != "Trixie" {
		t.Errorf("codename = %q, want Trixie", trixie.codename)
	}
	if trixie.series != "trixie" {
		t.Errorf("series = %q, want trixie (used in download URLs)", trixie.series)
	}
}

func TestParseDistroInfo_RejectsGarbledCSV(t *testing.T) {
	p := &DebianProvider{}

	t.Run("missing required column", func(t *testing.T) {
		csv := "version,codename,series,release\n13,Trixie,trixie,2025-08-01\n"
		_, err := p.parseDistroInfo(strings.NewReader(csv))
		if err == nil {
			t.Fatal("should reject CSV missing the 'eol' column")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		_, err := p.parseDistroInfo(strings.NewReader(""))
		if err == nil {
			t.Fatal("should reject empty input")
		}
	})
}

func TestParseDistroInfo_HandlesReorderedColumns(t *testing.T) {
	// Real-world defense: upstream could reorder CSV columns
	csv := `eol,series,codename,release,version
,,trixie,2025-08-01,13
`
	p := &DebianProvider{}
	releases, err := p.parseDistroInfo(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("parseDistroInfo() error: %v", err)
	}
	if len(releases) != 1 || releases[0].version != "13" {
		t.Errorf("should parse correctly regardless of column order, got %v", releases)
	}
}
