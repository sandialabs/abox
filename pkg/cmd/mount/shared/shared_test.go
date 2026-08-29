package shared

import (
	"testing"
)

func TestMountRecordRoundTrip(t *testing.T) {
	dir := t.TempDir()

	// Empty when no file exists.
	mounts, err := GetMounts(dir)
	if err != nil {
		t.Fatalf("GetMounts on empty dir: %v", err)
	}
	if len(mounts) != 0 {
		t.Fatalf("expected 0 mounts, got %d", len(mounts))
	}

	// Add two records.
	if err := AddMountRecord(dir, "/mnt/a", "/home/dev"); err != nil {
		t.Fatalf("AddMountRecord: %v", err)
	}
	if err := AddMountRecord(dir, "/mnt/b", "/var/log"); err != nil {
		t.Fatalf("AddMountRecord: %v", err)
	}

	mounts, err = GetMounts(dir)
	if err != nil {
		t.Fatalf("GetMounts: %v", err)
	}
	if len(mounts) != 2 {
		t.Fatalf("expected 2 mounts, got %d", len(mounts))
	}
	if mounts[0].LocalPath != "/mnt/a" || mounts[0].RemotePath != "/home/dev" {
		t.Errorf("unexpected first record: %+v", mounts[0])
	}
	if mounts[0].MountedAt.IsZero() {
		t.Error("expected MountedAt to be set")
	}

	// Remove one record.
	if err := RemoveMountRecord(dir, "/mnt/a"); err != nil {
		t.Fatalf("RemoveMountRecord: %v", err)
	}
	mounts, err = GetMounts(dir)
	if err != nil {
		t.Fatalf("GetMounts: %v", err)
	}
	if len(mounts) != 1 || mounts[0].LocalPath != "/mnt/b" {
		t.Fatalf("expected only /mnt/b to remain, got %+v", mounts)
	}
}
