package shared

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGetForwardsFilePath(t *testing.T) {
	got := GetForwardsFilePath("/some/instance/dir")
	want := "/some/instance/dir/forwards.json"
	if got != want {
		t.Errorf("GetForwardsFilePath() = %q, want %q", got, want)
	}
}

func TestLoadForwards(t *testing.T) {
	t.Run("missing file returns empty list", func(t *testing.T) {
		dir := t.TempDir()
		forwards, err := LoadForwards(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(forwards.Forwards) != 0 {
			t.Errorf("expected empty forwards, got %d", len(forwards.Forwards))
		}
	})

	t.Run("valid file", func(t *testing.T) {
		dir := t.TempDir()
		data := `{"forwards":[{"host_port":8080,"guest_port":80,"pid":1234,"created_at":"2025-01-01T00:00:00Z"}]}`
		if err := os.WriteFile(filepath.Join(dir, "forwards.json"), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}

		forwards, err := LoadForwards(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(forwards.Forwards) != 1 {
			t.Fatalf("expected 1 forward, got %d", len(forwards.Forwards))
		}
		if forwards.Forwards[0].HostPort != 8080 {
			t.Errorf("host_port = %d, want 8080", forwards.Forwards[0].HostPort)
		}
		if forwards.Forwards[0].GuestPort != 80 {
			t.Errorf("guest_port = %d, want 80", forwards.Forwards[0].GuestPort)
		}
		if forwards.Forwards[0].PID != 1234 {
			t.Errorf("pid = %d, want 1234", forwards.Forwards[0].PID)
		}
	})

	t.Run("reverse flag", func(t *testing.T) {
		dir := t.TempDir()
		data := `{"forwards":[{"host_port":8000,"guest_port":8000,"pid":5678,"created_at":"2025-01-01T00:00:00Z","reverse":true}]}`
		if err := os.WriteFile(filepath.Join(dir, "forwards.json"), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}

		forwards, err := LoadForwards(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !forwards.Forwards[0].Reverse {
			t.Error("expected Reverse to be true")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "forwards.json"), []byte("{bad json"), 0o600); err != nil {
			t.Fatal(err)
		}

		_, err := LoadForwards(dir)
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})
}

func TestSaveForwards(t *testing.T) {
	t.Run("creates file with correct permissions", func(t *testing.T) {
		dir := t.TempDir()
		forwards := &ForwardsFile{
			Forwards: []ForwardEntry{
				{HostPort: 8080, GuestPort: 80, PID: 1234, CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
			},
		}

		if err := SaveForwards(dir, forwards); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		path := filepath.Join(dir, "forwards.json")
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("file not created: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("permissions = %o, want 0o600", perm)
		}
	})

	t.Run("round-trips through LoadForwards", func(t *testing.T) {
		dir := t.TempDir()
		ts := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
		original := &ForwardsFile{
			Forwards: []ForwardEntry{
				{HostPort: 8080, GuestPort: 80, PID: 100, CreatedAt: ts},
				{HostPort: 3000, GuestPort: 3000, PID: 200, CreatedAt: ts, Reverse: true},
			},
		}

		if err := SaveForwards(dir, original); err != nil {
			t.Fatalf("save error: %v", err)
		}

		loaded, err := LoadForwards(dir)
		if err != nil {
			t.Fatalf("load error: %v", err)
		}

		if len(loaded.Forwards) != 2 {
			t.Fatalf("expected 2 forwards, got %d", len(loaded.Forwards))
		}
		for i, want := range original.Forwards {
			got := loaded.Forwards[i]
			if got.HostPort != want.HostPort || got.GuestPort != want.GuestPort ||
				got.PID != want.PID || got.Reverse != want.Reverse ||
				!got.CreatedAt.Equal(want.CreatedAt) {
				t.Errorf("forward[%d] = %+v, want %+v", i, got, want)
			}
		}
	})

	t.Run("produces valid JSON", func(t *testing.T) {
		dir := t.TempDir()
		forwards := &ForwardsFile{
			Forwards: []ForwardEntry{
				{HostPort: 9090, GuestPort: 90, PID: 42, CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
			},
		}

		if err := SaveForwards(dir, forwards); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		data, err := os.ReadFile(filepath.Join(dir, "forwards.json"))
		if err != nil {
			t.Fatal(err)
		}

		if !json.Valid(data) {
			t.Errorf("saved file is not valid JSON: %s", data)
		}
	})
}

func TestAddForward(t *testing.T) {
	t.Run("adds to empty file", func(t *testing.T) {
		dir := t.TempDir()
		entry := ForwardEntry{HostPort: 8080, GuestPort: 80, PID: 100, CreatedAt: time.Now()}

		if err := AddForward(dir, entry); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		forwards, err := LoadForwards(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(forwards.Forwards) != 1 {
			t.Fatalf("expected 1 forward, got %d", len(forwards.Forwards))
		}
		if forwards.Forwards[0].HostPort != 8080 {
			t.Errorf("host_port = %d, want 8080", forwards.Forwards[0].HostPort)
		}
	})

	t.Run("appends to existing", func(t *testing.T) {
		dir := t.TempDir()
		first := ForwardEntry{HostPort: 8080, GuestPort: 80, PID: 100, CreatedAt: time.Now()}
		second := ForwardEntry{HostPort: 3000, GuestPort: 3000, PID: 200, CreatedAt: time.Now()}

		if err := AddForward(dir, first); err != nil {
			t.Fatal(err)
		}
		if err := AddForward(dir, second); err != nil {
			t.Fatal(err)
		}

		forwards, err := LoadForwards(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(forwards.Forwards) != 2 {
			t.Fatalf("expected 2 forwards, got %d", len(forwards.Forwards))
		}
		if forwards.Forwards[0].HostPort != 8080 {
			t.Errorf("first forward host_port = %d, want 8080", forwards.Forwards[0].HostPort)
		}
		if forwards.Forwards[1].HostPort != 3000 {
			t.Errorf("second forward host_port = %d, want 3000", forwards.Forwards[1].HostPort)
		}
	})
}

func TestRemoveForward(t *testing.T) {
	setup := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		now := time.Now()
		forwards := &ForwardsFile{
			Forwards: []ForwardEntry{
				{HostPort: 8080, GuestPort: 80, PID: 100, CreatedAt: now},
				{HostPort: 3000, GuestPort: 3000, PID: 200, CreatedAt: now},
				{HostPort: 9090, GuestPort: 90, PID: 300, CreatedAt: now},
			},
		}
		if err := SaveForwards(dir, forwards); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	t.Run("removes middle entry", func(t *testing.T) {
		dir := setup(t)

		if err := RemoveForward(dir, 3000); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		forwards, err := LoadForwards(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(forwards.Forwards) != 2 {
			t.Fatalf("expected 2 forwards, got %d", len(forwards.Forwards))
		}
		for _, f := range forwards.Forwards {
			if f.HostPort == 3000 {
				t.Error("port 3000 should have been removed")
			}
		}
	})

	t.Run("removes first entry", func(t *testing.T) {
		dir := setup(t)

		if err := RemoveForward(dir, 8080); err != nil {
			t.Fatal(err)
		}

		forwards, err := LoadForwards(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(forwards.Forwards) != 2 {
			t.Fatalf("expected 2 forwards, got %d", len(forwards.Forwards))
		}
		if forwards.Forwards[0].HostPort != 3000 {
			t.Errorf("first remaining forward host_port = %d, want 3000", forwards.Forwards[0].HostPort)
		}
	})

	t.Run("removes last entry", func(t *testing.T) {
		dir := setup(t)

		if err := RemoveForward(dir, 9090); err != nil {
			t.Fatal(err)
		}

		forwards, err := LoadForwards(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(forwards.Forwards) != 2 {
			t.Fatalf("expected 2 forwards, got %d", len(forwards.Forwards))
		}
	})

	t.Run("nonexistent port is a no-op", func(t *testing.T) {
		dir := setup(t)

		if err := RemoveForward(dir, 9999); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		forwards, err := LoadForwards(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(forwards.Forwards) != 3 {
			t.Errorf("expected 3 forwards unchanged, got %d", len(forwards.Forwards))
		}
	})

	t.Run("remove all entries leaves empty list", func(t *testing.T) {
		dir := setup(t)

		for _, port := range []int{8080, 3000, 9090} {
			if err := RemoveForward(dir, port); err != nil {
				t.Fatal(err)
			}
		}

		forwards, err := LoadForwards(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(forwards.Forwards) != 0 {
			t.Errorf("expected 0 forwards, got %d", len(forwards.Forwards))
		}
	})
}

func TestFindForwardByHostPort(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	forwards := &ForwardsFile{
		Forwards: []ForwardEntry{
			{HostPort: 8080, GuestPort: 80, PID: 100, CreatedAt: now},
			{HostPort: 3000, GuestPort: 3000, PID: 200, CreatedAt: now, Reverse: true},
		},
	}
	if err := SaveForwards(dir, forwards); err != nil {
		t.Fatal(err)
	}

	t.Run("finds existing forward", func(t *testing.T) {
		entry, err := FindForwardByHostPort(dir, 8080)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if entry == nil {
			t.Fatal("expected entry, got nil")
			return
		}
		if entry.GuestPort != 80 {
			t.Errorf("guest_port = %d, want 80", entry.GuestPort)
		}
		if entry.PID != 100 {
			t.Errorf("pid = %d, want 100", entry.PID)
		}
	})

	t.Run("finds reverse forward", func(t *testing.T) {
		entry, err := FindForwardByHostPort(dir, 3000)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if entry == nil {
			t.Fatal("expected entry, got nil")
			return
		}
		if !entry.Reverse {
			t.Error("expected Reverse to be true")
		}
	})

	t.Run("returns nil for nonexistent port", func(t *testing.T) {
		entry, err := FindForwardByHostPort(dir, 9999)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if entry != nil {
			t.Errorf("expected nil, got %+v", entry)
		}
	})

	t.Run("returns nil for empty file", func(t *testing.T) {
		emptyDir := t.TempDir()
		entry, err := FindForwardByHostPort(emptyDir, 8080)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if entry != nil {
			t.Errorf("expected nil, got %+v", entry)
		}
	})
}

func TestUpdateForwardPID(t *testing.T) {
	setup := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		now := time.Now()
		forwards := &ForwardsFile{
			Forwards: []ForwardEntry{
				{HostPort: 8080, GuestPort: 80, PID: 100, CreatedAt: now},
				{HostPort: 3000, GuestPort: 3000, PID: 200, CreatedAt: now},
			},
		}
		if err := SaveForwards(dir, forwards); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	t.Run("updates PID for existing forward", func(t *testing.T) {
		dir := setup(t)

		if err := UpdateForwardPID(dir, 8080, 999); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		entry, err := FindForwardByHostPort(dir, 8080)
		if err != nil {
			t.Fatal(err)
		}
		if entry.PID != 999 {
			t.Errorf("PID = %d, want 999", entry.PID)
		}
	})

	t.Run("does not modify other entries", func(t *testing.T) {
		dir := setup(t)

		if err := UpdateForwardPID(dir, 8080, 999); err != nil {
			t.Fatal(err)
		}

		other, err := FindForwardByHostPort(dir, 3000)
		if err != nil {
			t.Fatal(err)
		}
		if other.PID != 200 {
			t.Errorf("other entry PID = %d, want 200 (unchanged)", other.PID)
		}
	})

	t.Run("returns error for nonexistent port", func(t *testing.T) {
		dir := setup(t)

		err := UpdateForwardPID(dir, 9999, 500)
		if err == nil {
			t.Fatal("expected error for nonexistent port")
		}
	})

	t.Run("preserves other fields", func(t *testing.T) {
		dir := setup(t)

		before, err := FindForwardByHostPort(dir, 8080)
		if err != nil {
			t.Fatal(err)
		}

		if err := UpdateForwardPID(dir, 8080, 777); err != nil {
			t.Fatal(err)
		}

		after, err := FindForwardByHostPort(dir, 8080)
		if err != nil {
			t.Fatal(err)
		}

		if after.HostPort != before.HostPort {
			t.Errorf("HostPort changed: %d -> %d", before.HostPort, after.HostPort)
		}
		if after.GuestPort != before.GuestPort {
			t.Errorf("GuestPort changed: %d -> %d", before.GuestPort, after.GuestPort)
		}
		if after.Reverse != before.Reverse {
			t.Errorf("Reverse changed: %v -> %v", before.Reverse, after.Reverse)
		}
		if !after.CreatedAt.Equal(before.CreatedAt) {
			t.Errorf("CreatedAt changed: %v -> %v", before.CreatedAt, after.CreatedAt)
		}
		if after.PID != 777 {
			t.Errorf("PID = %d, want 777", after.PID)
		}
	})
}
