package add

import (
	"slices"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/iostreams"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

func TestNewCmdAdd_FlagParsing(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	var gotOpts *Options
	cmd := NewCmdAdd(f, func(o *Options) error {
		gotOpts = o
		return nil
	})
	cmd.SetArgs([]string{"--read-only", "--allow-other", "dev", "/mnt/dev"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotOpts == nil {
		t.Fatal("runF was not called")
	}
	if !gotOpts.ReadOnly {
		t.Error("expected ReadOnly to be true")
	}
	if !gotOpts.AllowOther {
		t.Error("expected AllowOther to be true")
	}
	if gotOpts.Name != "dev" {
		t.Errorf("Name = %q, want %q", gotOpts.Name, "dev")
	}
	if gotOpts.MountPoint != "/mnt/dev" {
		t.Errorf("MountPoint = %q, want %q", gotOpts.MountPoint, "/mnt/dev")
	}
}

func TestNewCmdAdd_RequiresArgs(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	cmd := NewCmdAdd(f, func(o *Options) error {
		t.Fatal("runF should not be called")
		return nil
	})
	cmd.SetArgs([]string{})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when no args provided")
	}
}

func TestBuildSSHFSArgs(t *testing.T) {
	paths := &config.Paths{SSHKey: "/key", KnownHosts: "/known_hosts"}

	args := buildSSHFSArgs(paths, "ubuntu", "10.0.0.2", "/home/ubuntu", "/mnt/dev", true, true)

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

	args = buildSSHFSArgs(paths, "ubuntu", "10.0.0.2", "/home/ubuntu", "/mnt/dev", false, false)
	if slices.Contains(args, "ro") || slices.Contains(args, "allow_other") {
		t.Errorf("unexpected ro/allow_other in %v", args)
	}
}
