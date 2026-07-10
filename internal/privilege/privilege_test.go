package privilege

import (
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
)

func TestInGroup(t *testing.T) {
	// Look up the group name for the process's real GID — this group must
	// always match, even if it only appears as the primary GID and not in
	// the supplementary list.
	primaryGID := os.Getgid()
	primaryGroup, err := user.LookupGroupId(strconv.Itoa(primaryGID))
	if err != nil {
		t.Fatalf("failed to look up primary group for gid %d: %v", primaryGID, err)
	}

	tests := []struct {
		name      string
		groupName string
		want      bool
	}{
		{
			name:      "primary group",
			groupName: primaryGroup.Name,
			want:      true,
		},
		{
			name:      "nonexistent group",
			groupName: "abox-no-such-group-exists-xyz",
			want:      false,
		},
		{
			name:      "root group when not root",
			groupName: "root",
			want:      os.Getgid() == 0 || os.Getegid() == 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InGroup(tt.groupName)
			if got != tt.want {
				t.Errorf("InGroup(%q) = %v, want %v", tt.groupName, got, tt.want)
			}
		})
	}
}

func TestCheckSocketGroupAccess(t *testing.T) {
	t.Run("missing socket returns error", func(t *testing.T) {
		_, err := CheckSocketGroupAccess(filepath.Join(t.TempDir(), "nope.sock"))
		if err == nil {
			t.Fatal("expected error for nonexistent socket")
		}
	})

	t.Run("socket owned by our group is a member", func(t *testing.T) {
		// A socket we create is owned by our gid, so we must be reported a member.
		sockPath := filepath.Join(t.TempDir(), "test.sock")
		l, err := net.Listen("unix", sockPath)
		if err != nil {
			t.Fatalf("failed to create test socket: %v", err)
		}
		defer func() { _ = l.Close() }()

		access, err := CheckSocketGroupAccess(sockPath)
		if err != nil {
			t.Fatalf("CheckSocketGroupAccess returned error: %v", err)
		}
		if access.GID != os.Getgid() {
			t.Errorf("GID = %d, want %d", access.GID, os.Getgid())
		}
		if !access.IsMember {
			t.Errorf("IsMember = false, want true for our own group %q (gid %d)", access.Group, access.GID)
		}
	})
}
