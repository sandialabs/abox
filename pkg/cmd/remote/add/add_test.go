package add

import (
	"os/exec"
	"strings"
	"testing"
)

func TestBuildExtURL(t *testing.T) {
	tests := []struct {
		name     string
		instance string
		path     string
		want     string
	}{
		{
			name:     "relative path",
			instance: "dev",
			path:     "projects/my-project",
			want:     "ext::abox ssh dev -- %S 'projects/my-project'",
		},
		{
			name:     "absolute path",
			instance: "dev",
			path:     "/srv/repo",
			want:     "ext::abox ssh dev -- %S '/srv/repo'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildExtURL(tt.instance, tt.path); got != tt.want {
				t.Errorf("buildExtURL(%q, %q) = %q, want %q", tt.instance, tt.path, got, tt.want)
			}
		})
	}
}

func TestEnsureExtAllowed(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	// Fresh repo in a temp dir; t.Chdir restores cwd at test end.
	dir := t.TempDir()
	t.Chdir(dir)
	if out, err := exec.Command("git", "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	// Default repo: ext is disallowed, so the first call sets it.
	changed, err := ensureExtAllowed()
	if err != nil {
		t.Fatalf("ensureExtAllowed: %v", err)
	}
	if !changed {
		t.Error("expected ensureExtAllowed to set config on a fresh repo, got changed=false")
	}

	out, err := exec.Command("git", "config", "--local", "--get", "protocol.ext.allow").Output()
	if err != nil {
		t.Fatalf("reading protocol.ext.allow: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "user" {
		t.Errorf("protocol.ext.allow = %q, want %q", got, "user")
	}

	// Second call is a no-op: already permissive.
	changed, err = ensureExtAllowed()
	if err != nil {
		t.Fatalf("ensureExtAllowed (second call): %v", err)
	}
	if changed {
		t.Error("expected ensureExtAllowed to leave already-permissive config alone, got changed=true")
	}
}

func TestRunValidation(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr string
	}{
		{
			name:    "not remote form",
			target:  "projects/my-project",
			wantErr: "<instance>:<path> format",
		},
		{
			name:    "empty path",
			target:  "dev:",
			wantErr: "no path specified",
		},
		{
			name:    "single quote in path",
			target:  "dev:weird'path",
			wantErr: "must not contain single quotes",
		},
		{
			name:    "nonexistent instance",
			target:  "definitely-not-a-real-instance-xyz:projects/repo",
			wantErr: "does not exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &Options{Target: tt.target}
			err := o.Run()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}
