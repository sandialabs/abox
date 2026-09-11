//go:build linux

package libvirt

import (
	"context"
	"fmt"
	"slices"
	"testing"
)

func TestSnapshotCreateArgVector(t *testing.T) {
	mock := installMock(t, nil, nil)
	s := &SnapshotManager{}
	if err := s.Create(context.Background(), "dev", "snap1", "my description"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	call := findCall(mock.Calls, "snapshot-create-as")
	if call == nil {
		t.Fatalf("Create did not issue snapshot-create-as; calls=%+v", mock.Calls)
	}
	// Positionals: snapshot-create-as <domain> <name>, then --description <desc>.
	idx := slices.Index(call.Args, "snapshot-create-as")
	rest := call.Args[idx+1:]
	if len(rest) < 2 || rest[0] != "abox-dev" || rest[1] != "snap1" {
		t.Errorf("snapshot-create-as positionals = %v, want [abox-dev snap1 ...]", rest)
	}
	if !slices.Contains(call.Args, "--description") || !slices.Contains(call.Args, "my description") {
		t.Errorf("snapshot-create-as missing description flag: %v", call.Args)
	}
}

func TestSnapshotCreateOmitsEmptyDescription(t *testing.T) {
	mock := installMock(t, nil, nil)
	s := &SnapshotManager{}
	if err := s.Create(context.Background(), "dev", "snap1", ""); err != nil {
		t.Fatalf("Create: %v", err)
	}
	call := findCall(mock.Calls, "snapshot-create-as")
	if call == nil {
		t.Fatalf("no snapshot-create-as call; calls=%+v", mock.Calls)
	}
	if slices.Contains(call.Args, "--description") {
		t.Errorf("empty description should not add --description flag: %v", call.Args)
	}
}

// TestSnapshotNameValidation confirms the primitive-layer snapshot-name guard is
// invoked: a name that could be interpreted as a flag is rejected before virsh.
func TestSnapshotNameValidation(t *testing.T) {
	mock := installMock(t, nil, nil)
	s := &SnapshotManager{}
	bad := "--force"
	if err := s.Create(context.Background(), "dev", bad, ""); err == nil {
		t.Error("Create should reject a flag-like snapshot name")
	}
	if err := s.Revert(context.Background(), "dev", bad); err == nil {
		t.Error("Revert should reject a flag-like snapshot name")
	}
	if err := s.Delete(context.Background(), "dev", bad); err == nil {
		t.Error("Delete should reject a flag-like snapshot name")
	}
	if s.Exists("dev", bad) {
		t.Error("Exists should be false for an invalid snapshot name")
	}
	// None of the rejected calls should have reached virsh.
	if len(mock.Calls) != 0 {
		t.Errorf("invalid snapshot names reached virsh: %+v", mock.Calls)
	}
}

func TestSnapshotRevertAndDeleteArgVectors(t *testing.T) {
	tests := []struct {
		name   string
		call   func(s *SnapshotManager) error
		subcmd string
	}{
		{"revert", func(s *SnapshotManager) error { return s.Revert(context.Background(), "dev", "snap1") }, "snapshot-revert"},
		{"delete", func(s *SnapshotManager) error { return s.Delete(context.Background(), "dev", "snap1") }, "snapshot-delete"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := installMock(t, nil, nil)
			s := &SnapshotManager{}
			if err := tt.call(s); err != nil {
				t.Fatalf("%s: %v", tt.name, err)
			}
			call := findCall(mock.Calls, tt.subcmd)
			if call == nil {
				t.Fatalf("%s did not issue %s; calls=%+v", tt.name, tt.subcmd, mock.Calls)
			}
			idx := slices.Index(call.Args, tt.subcmd)
			if got := call.Args[idx+1:]; !slices.Equal(got, []string{"abox-dev", "snap1"}) {
				t.Errorf("%s positionals = %v, want [abox-dev snap1]", tt.name, got)
			}
		})
	}
}

func TestSnapshotListParsesInfo(t *testing.T) {
	// snapshot-list --name yields names; each name triggers a snapshot-info lookup.
	installMock(t, func(name string, args ...string) (string, error) {
		if slices.Contains(args, "snapshot-list") {
			return "snap1\nsnap2\n", nil
		}
		if slices.Contains(args, "snapshot-info") {
			// Which snapshot is being queried is the last positional.
			which := args[len(args)-1]
			return fmt.Sprintf("Name:           %s\n"+
				"Creation Time:  2026-07-10 12:00:00 +0000\n"+
				"State:          shutoff\n"+
				"Parent:         -\n"+
				"Current:        %s\n",
				which, map[string]string{"snap2": "yes"}[which]), nil
		}
		return "", nil
	}, nil)

	s := &SnapshotManager{}
	infos, err := s.List(context.Background(), "dev")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(infos) != 2 {
		t.Fatalf("List returned %d snapshots, want 2: %+v", len(infos), infos)
	}
	if infos[0].Name != "snap1" || infos[1].Name != "snap2" {
		t.Errorf("List names = %q,%q want snap1,snap2", infos[0].Name, infos[1].Name)
	}
	if infos[0].State != "shutoff" {
		t.Errorf("snap1 State = %q, want shutoff", infos[0].State)
	}
	if infos[0].Current {
		t.Error("snap1 should not be current")
	}
	if !infos[1].Current {
		t.Error("snap2 should be current")
	}
}

func TestSnapshotExistsParsing(t *testing.T) {
	installMock(t, func(name string, args ...string) (string, error) {
		return "snap1\nsnap2\n", nil
	}, nil)
	s := &SnapshotManager{}
	if !s.Exists("dev", "snap2") {
		t.Error("Exists(snap2) should be true")
	}
	if s.Exists("dev", "nope") {
		t.Error("Exists(nope) should be false")
	}
}

func TestSnapshotGetInfoParsing(t *testing.T) {
	installMock(t, func(name string, args ...string) (string, error) {
		return "Name:           snap1\n" +
			"Creation Time:  2026-07-10 09:30:00 +0000\n" +
			"State:          running\n" +
			"Parent:         base\n" +
			"Current:        yes\n", nil
	}, nil)
	s := &SnapshotManager{}
	info, err := s.GetInfo("dev", "snap1")
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if info.Name != "snap1" || info.State != stateRunning || info.Parent != "base" || !info.Current {
		t.Errorf("GetInfo = %+v, unexpected fields", info)
	}
	if info.CreationTime != "2026-07-10 09:30:00 +0000" {
		t.Errorf("CreationTime = %q", info.CreationTime)
	}
}

func TestSnapshotListErrorPropagates(t *testing.T) {
	installMock(t, func(name string, args ...string) (string, error) {
		return "", fmt.Errorf("no such domain")
	}, nil)
	s := &SnapshotManager{}
	if _, err := s.List(context.Background(), "dev"); err == nil {
		t.Error("List should propagate virsh error")
	}
}
