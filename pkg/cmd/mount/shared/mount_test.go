package shared

import (
	"slices"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/config"
)

func TestBuildSSHFSArgs(t *testing.T) {
	paths := &config.Paths{SSHKey: "/key", KnownHosts: "/known_hosts"}

	entry := MountEntry{
		LocalPath:  "/mnt/dev",
		RemotePath: "/home/ubuntu",
		ReadOnly:   true,
		AllowOther: true,
	}
	args := buildSSHFSArgs(paths, "ubuntu", "10.0.0.2", entry)

	var opts []string
	for i := range len(args) - 1 {
		if args[i] == "-o" {
			opts = append(opts, args[i+1])
		}
	}

	// A bare PubkeyAccepted* -o is passed to FUSE by sshfs and rejected.
	for _, o := range opts {
		if strings.HasPrefix(o, "PubkeyAccepted") {
			t.Errorf("sshfs args contain bare %q; must go through ssh_command", o)
		}
	}
	for _, want := range []string{
		"ssh_command=ssh -o PubkeyAcceptedKeyTypes=+ssh-ed25519",
		"IdentityFile=/key",
		"UserKnownHostsFile=/known_hosts",
		"ro",
		"allow_other",
	} {
		if !slices.Contains(opts, want) {
			t.Errorf("sshfs options %v missing %q", opts, want)
		}
	}

	entry.ReadOnly, entry.AllowOther = false, false
	args = buildSSHFSArgs(paths, "ubuntu", "10.0.0.2", entry)
	if slices.Contains(args, "ro") || slices.Contains(args, "allow_other") {
		t.Errorf("unexpected ro/allow_other in %v", args)
	}
}
