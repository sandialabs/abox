package privilege

import (
	"os"
	"os/user"
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
