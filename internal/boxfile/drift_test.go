package boxfile

import (
	"testing"

	"github.com/sandialabs/abox/internal/config"
)

// matchingInstance returns a config.Instance whose fields agree with the given
// boxfile's effective values, so Drift reports nothing by default.
func matchingInstance(box *Boxfile) *config.Instance {
	return &config.Instance{
		CPUs:   box.CPUs,
		Memory: box.Memory,
		Disk:   box.Disk,
		Base:   box.Base,
		DNS:    config.DNSConfig{Upstream: box.DNS.Upstream},
		HTTP: config.HTTPConfig{
			MITM:           box.GetMITM(),
			MaxConnections: box.GetMaxConnections(),
		},
	}
}

func TestDrift_NoDiffWhenMatching(t *testing.T) {
	box := DefaultBoxfile()
	box.Name = "dev"
	inst := matchingInstance(box)

	if diffs := Drift(box, inst); len(diffs) != 0 {
		t.Errorf("expected no drift, got: %v", diffs)
	}
}

func TestDrift_OmittedBoxfileFieldNotReported(t *testing.T) {
	// A boxfile that omits subnet/disk must not report drift against a populated
	// instance (unset boxfile value = "don't care").
	box := DefaultBoxfile()
	box.Name = "dev"
	box.Subnet = "" // omitted
	box.Disk = ""   // omitted

	inst := matchingInstance(box)
	inst.Subnet = "10.10.5.0/24"
	inst.Disk = "20G"

	for _, d := range Drift(box, inst) {
		if d.Field == "subnet" || d.Field == "disk" {
			t.Errorf("omitted boxfile field %q should not be reported as drift", d.Field)
		}
	}
}

func TestDrift_MaxConnectionsDefaultNoFalsePositive(t *testing.T) {
	// An older instance persisted MaxConnections=0 (meaning "use default"); a
	// boxfile that doesn't set it (also default) must not report drift.
	box := DefaultBoxfile()
	box.Name = "dev"
	inst := matchingInstance(box)
	inst.HTTP.MaxConnections = 0 // legacy "unset" => effective default

	for _, d := range Drift(box, inst) {
		if d.Field == "http.max_connections" {
			t.Errorf("default max_connections should not drift, got %v", d)
		}
	}
}

func TestDrift_ReportsChangedFields(t *testing.T) {
	box := DefaultBoxfile()
	box.Name = "dev"
	box.CPUs = 8
	box.HTTP.AllowPrivateTargets = []string{"10.253.165.0/24"}
	mitmOff := false
	box.HTTP.MITM = &mitmOff

	inst := matchingInstance(box)
	// Instance disagrees on all three.
	inst.CPUs = 2
	inst.HTTP.AllowPrivateTargets = nil
	inst.HTTP.MITM = true

	diffs := Drift(box, inst)
	got := map[string]FieldDiff{}
	for _, d := range diffs {
		got[d.Field] = d
	}

	for _, field := range []string{"cpus", "http.allow_private_targets", "http.mitm"} {
		if _, ok := got[field]; !ok {
			t.Errorf("expected drift for %q, diffs=%v", field, diffs)
		}
	}
	if d := got["cpus"]; d.Declared != "8" || d.Current != "2" {
		t.Errorf("cpus diff wrong: %+v", d)
	}
}
