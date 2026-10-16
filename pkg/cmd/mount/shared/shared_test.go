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

	// Add two records (the second with the sshfs flags set).
	if err := AddMountRecord(dir, MountEntry{LocalPath: "/mnt/a", RemotePath: "/home/dev"}); err != nil {
		t.Fatalf("AddMountRecord: %v", err)
	}
	if err := AddMountRecord(dir, MountEntry{
		LocalPath: "/mnt/b", RemotePath: "/var/log", ReadOnly: true, AllowOther: true,
	}); err != nil {
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
	if mounts[0].ReadOnly || mounts[0].AllowOther {
		t.Errorf("expected default flags to round-trip as false, got %+v", mounts[0])
	}
	if !mounts[1].ReadOnly || !mounts[1].AllowOther {
		t.Errorf("expected ReadOnly/AllowOther to round-trip as true, got %+v", mounts[1])
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
